//! Proof-step tests: `StampLift`, `SpendBind` / `SpendStamp`, the GGM
//! derivation chain, `ArbitraryUnspent` composition, and the `Spendable*`
//! lineage.

#![allow(clippy::panic, reason = "test code")]

extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::array;

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Pcd, Proof};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::{CryptoRng, RngCore};

use super::{PROOF_SYSTEM, delegation, output, pool, spend, spendable, stamp};
use crate::{
    ActionSetPoly, NfSeqPoly, Note, TachygramSetPoly,
    constants::EPOCH_SIZE,
    digest::poseidon,
    entropy::ActionEntropy,
    fixtures::{
        PoolSim, SyncSim, WalletSim, build_anchor_chain_pcd, build_output_plan, build_output_stamp,
        build_unspent_pcd_between_anchors, build_unspent_pcd_between_blocks,
        build_unspent_seed_pcd, random_block, random_block_with, shared_sk, spend_witness,
    },
    note,
    nullifier::{self, Nullifier},
    primitives::{Anchor, BlockHeight, EpochIndex, Tachygram, effect},
    value, witness,
};

fn mine_cm_block(rng: &mut StdRng, pool: &mut PoolSim, cm: note::Commitment) -> BlockHeight {
    pool.mine(random_block_with(rng, &[alloc::vec![cm]], 4));
    pool.height()
}

fn mine_cm_in_epoch_one(
    rng: &mut (impl RngCore + CryptoRng),
    pool: &mut PoolSim,
    cm: note::Commitment,
) -> BlockHeight {
    // Height EPOCH_SIZE is epoch 1's first block, carrying the real B_1 fold.
    while pool.height().0 < EPOCH_SIZE {
        pool.mine(random_block(rng, 1, 3));
    }
    pool.mine(random_block_with(rng, &[alloc::vec![cm]], 4));
    let cm_height = pool.height();
    assert_eq!(cm_height.epoch().0, 1, "cm-block is in epoch 1");
    cm_height
}

fn honest_spend_bind(
    rng: &mut StdRng,
    user: &WalletSim,
    note: &Note,
    spendable: Pcd<spendable::SpendableHeader>,
    spend_epoch: EpochIndex,
) -> Pcd<spend::SpendHeader> {
    let derived = user.derived_range(rng, note, spend_epoch, 2);
    let nf_next = user.nf_at(note, spend_epoch.next());
    let (bind_pcd, ()) = PROOF_SYSTEM
        .fuse(rng, spend::SpendBind, (nf_next,), spendable, derived)
        .expect("SpendBind honest");
    bind_pcd
}

fn honest_spend_stamp(
    rng: &mut StdRng,
    user: &WalletSim,
    note: &Note,
    bind_pcd: Pcd<spend::SpendHeader>,
) -> Pcd<stamp::StampHeader> {
    let (rcv, _theta, alpha) = spend_witness(rng, note);
    let (stamp, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::SpendStamp,
            (*note, rcv, alpha, user.pak),
            bind_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("SpendStamp honest");
    stamp
}

#[test]
fn same_epoch_honest_spend_accepted() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let cm_height = mine_cm_in_epoch_one(rng, &mut pool, note.commitment());
    let epoch = cm_height.epoch();

    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let spend_pcd = honest_spend_bind(rng, &user, &note, spendable, epoch);
    let stamp = honest_spend_stamp(rng, &user, &note, spend_pcd);

    let expected = TachygramSetPoly::from_iter([
        user.nf_at(&note, epoch).into(),
        user.nf_at(&note, epoch.next()).into(),
    ])
    .commit();
    assert_eq!(stamp.data().1, expected, "publishes {{N_E, N_E+1}}");
    PROOF_SYSTEM
        .rerandomize(stamp, rng)
        .expect("rerandomize honest same-epoch spend");
}

#[test]
fn stamp_lift_within_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);

    pool.advance(1, |_| random_block(rng, 1, 4));
    let stamp_anchor = pool.anchor_at(BlockHeight(1));

    let note = user.random_note(200);
    let (stamp, plan) = build_output_stamp(rng, stamp_anchor, note);

    let action_commit = ActionSetPoly::from_iter([plan.digest().expect("valid plan")]).commit();
    let tachygram_commit = TachygramSetPoly::from_iter(stamp.tachygrams).commit();

    pool.advance(EPOCH_SIZE - 2, |_| random_block(rng, 1, 4));
    let new_height = pool.height();

    let stamp_pcd = stamp
        .proof
        .carry((action_commit, tachygram_commit, stamp_anchor));
    let anchor_chain = build_anchor_chain_pcd(rng, &pool, BlockHeight(2)..=new_height);

    let (lifted_pcd, ()) = PROOF_SYSTEM
        .fuse(rng, stamp::StampLift, (), stamp_pcd, anchor_chain)
        .expect("stamp lift");
    PROOF_SYSTEM
        .rerandomize(lifted_pcd, rng)
        .expect("rerandomize lifted stamp");
}

#[test]
fn spendable_init_rejects_tg_absent() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let nf_header = user.derived_range(rng, &note, EpochIndex(0), 1);
    let present_nf = user.nf_at(&note, EpochIndex(0));
    let absent_tg = Tachygram::random(&mut *rng);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            witness::spendable_init(
                (*nf_header.data(), ()),
                Anchor::default(),
                &[absent_tg],
                present_nf,
            ),
            nf_header,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "SpendableInit: commitment not in set");
}

#[test]
fn unspent_seed_rejects_tg_present() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let nf = user.nf_at(&note, EpochIndex(0));

    let start = Anchor::default();

    let err = PROOF_SYSTEM
        .seed(
            rng,
            pool::UnspentSeed,
            witness::unspent_seed(((), ()), start, EpochIndex(0), &[nf.into()], nf),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "UnspentSeed: found nullifier in set");
}

#[test]
fn unspent_fuse_rejects_invalid_compositions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let stamps_left = vec![Tachygram::random(&mut *rng)];
    let stamps_right = vec![Tachygram::random(&mut *rng)];
    let start = Anchor::default();
    let mid = start.next_stamp(
        EpochIndex(0),
        &TachygramSetPoly::from_iter(stamps_left.clone()).commit(),
    );

    // nf mismatch: contiguous states but different nfs.
    {
        let nf_a = Nullifier::from(Fp::random(&mut *rng));
        let nf_b = Nullifier::from(Fp::random(&mut *rng));
        let shard_a = build_unspent_seed_pcd(rng, start, EpochIndex(0), &stamps_left.clone(), nf_a);
        let shard_b = build_unspent_seed_pcd(rng, mid, EpochIndex(0), &stamps_right.clone(), nf_b);
        let w = witness::unspent_fuse((*shard_a.data(), *shard_b.data()), &[], &[]);
        let err = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, w, shard_a, shard_b)
            .err()
            .unwrap();
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "UnspentFuse: halves disagree on the junction nullifier"
        );
    }

    // state discontinuity: same nf, but right's start matches `start`
    // instead of `left.end`.
    {
        let nf = Nullifier::from(Fp::random(&mut *rng));
        let shard_a = build_unspent_seed_pcd(rng, start, EpochIndex(0), &stamps_left, nf);
        let shard_b = build_unspent_seed_pcd(rng, start, EpochIndex(0), &stamps_right, nf);
        let w = witness::unspent_fuse((*shard_a.data(), *shard_b.data()), &[], &[]);
        let err = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, w, shard_a, shard_b)
            .err()
            .unwrap();
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "UnspentFuse: left.anchor_last must equal right.anchor_prev"
        );
    }
}

#[test]
fn anchor_chain_fuse_rejects_invalid_compositions() {
    // anchor break: synthetic right-segment seeded from a bogus start anchor.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let mut pool = PoolSim::genesis(rng);
        pool.advance(2, |_| random_block(rng, 1, 2));

        let left = build_anchor_chain_pcd(rng, &pool, BlockHeight(0)..=BlockHeight(0));

        let bogus_start = Anchor(Fp::random(&mut *rng));
        let stamps = pool.tachygrams_at(BlockHeight(1));
        let (right, ()) = PROOF_SYSTEM
            .seed(
                rng,
                pool::AnchorSeed,
                witness::anchor_seed(((), ()), bogus_start, BlockHeight(1).epoch(), &stamps[0]),
            )
            .expect("AnchorSeed");

        let err = PROOF_SYSTEM
            .fuse(rng, pool::AnchorFuse, (), left, right)
            .err()
            .unwrap();
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(inner.to_string(), "AnchorFuse: segments not adjacent");
    }

    // cross-epoch: left segment ends at epoch_0_final's anchor, right segment
    // over the first block of epoch_1 starts at the boundary anchor.
    // Adjacency fails because the boundary anchor (via Anchor::next_epoch)
    // sits between them, and no AnchorChain step ever emits it.
    {
        let rng = &mut StdRng::seed_from_u64(0);
        let mut pool = PoolSim::genesis(rng);
        pool.advance(EPOCH_SIZE + 1, |_| random_block(rng, 1, 2));

        let left = build_anchor_chain_pcd(rng, &pool, BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1));
        let right = build_anchor_chain_pcd(
            rng,
            &pool,
            BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
        );

        let err = PROOF_SYSTEM
            .fuse(rng, pool::AnchorFuse, (), left, right)
            .err()
            .unwrap();
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(inner.to_string(), "AnchorFuse: segments not adjacent");
    }
}

#[test]
fn empty_blocks_do_not_advance_the_anchor() {
    // A block that publishes no stamp contributes no anchor link, so a run of
    // empty blocks shares the anchor of the last block that did publish one.
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block(rng, 1, 2));
    pool.mine(vec![]);
    pool.mine(vec![]);

    let stamped = BlockHeight(1);
    assert_eq!(pool.anchor_at(BlockHeight(2)), pool.anchor_at(stamped));
    assert_eq!(pool.anchor_at(BlockHeight(3)), pool.anchor_at(stamped));
}

#[test]
fn spendable_stays_current_across_empty_blocks() {
    // A note idling over a stampless span needs no proof work at all: the pool
    // anchor never leaves the spendable's, so there is nothing to lift over.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(100);
    let cm = note.commitment();

    let mut pool = PoolSim::genesis(rng);
    pool.mine(vec![vec![cm.into()]]);
    let cm_height = pool.height();

    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let spendable_anchor = spendable.data().2;

    pool.mine(vec![]);
    pool.mine(vec![]);

    assert_eq!(pool.anchor_at(pool.height()), spendable_anchor);
}

#[test]
fn spend_bind_honest() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let spend_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd, spend_epoch);
    let (_cm, present_nf, _nf_next, _anchor) = *spend_pcd.data();
    assert_eq!(present_nf, user.nf_at(&note, spend_epoch));
}

#[test]
fn spend_stamp_rejects_invalid_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let other = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();

    let phantom = Note {
        value: value::Positive::try_from(999_999u64).expect("test value in range"),
        rcm: note::CommitmentTrapdoor::random(rng),
        ..note
    };
    assert_eq!(Fp::from(note.psi), Fp::from(phantom.psi), "shared psi");
    assert_ne!(note.commitment(), phantom.commitment(), "distinct cm");
    assert_eq!(
        user.nf_at(&note, spend_epoch),
        user.nf_at(&phantom, spend_epoch),
        "shared psi yields shared nullifiers"
    );

    let wrong_value = value::Positive::try_from(999_999u64).expect("test value in range");
    assert_ne!(u64::from(wrong_value), u64::from(note.value));

    // The nullifier pair binds honestly at SpendBind; the note-level checks
    // (value, pak, cm) now live at SpendStamp, which proves the action.
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd, spend_epoch);

    let cases = [
        (
            "value inflation",
            phantom,
            user.pak,
            "SpendStamp: note does not match the spend",
        ),
        (
            "wrong value",
            Note {
                value: wrong_value,
                ..note
            },
            user.pak,
            "SpendStamp: note does not match the spend",
        ),
        (
            "unrelated pak",
            note,
            other.pak,
            "SpendStamp: pak not related to note",
        ),
    ];

    for (label, spend_note, pak, expected) in cases {
        let (rcv, _theta, alpha) = spend_witness(rng, &note);
        let err = PROOF_SYSTEM
            .fuse(
                rng,
                stamp::SpendStamp,
                (spend_note, rcv, alpha, pak),
                bind_pcd.clone(),
                Proof::trivial().carry::<()>(()),
            )
            .err()
            .unwrap();
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(inner.to_string(), expected, "{label}");
    }
}

#[test]
fn spend_bind_rejects_forged_next() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let derived = user.derived_range(rng, &note, spend_epoch, 2);
    let forged_next = Nullifier::from(Fp::random(&mut *rng));

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (forged_next,),
            spendable_pcd,
            derived,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendBind: next nullifier is not the range's end leaf"
    );
}

#[test]
fn spend_bind_rejects_range_from_another_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    // The note's own live pair, but for an epoch the lineage has not reached.
    let ahead = spend_epoch.next();
    let derived = user.derived_range(rng, &note, ahead, 2);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (user.nf_at(&note, ahead.next()),),
            spendable_pcd,
            derived,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendBind: live range does not start at the lineage epoch"
    );
}

#[test]
fn spend_bind_rejects_zero_next_nullifier() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let derived = user.derived_range(rng, &note, spend_epoch, 2);
    let zero_next = Nullifier::from(Fp::ZERO);

    let err = PROOF_SYSTEM
        .fuse(rng, spend::SpendBind, (zero_next,), spendable_pcd, derived)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendBind: next nullifier is not the range's end leaf"
    );
}

/// Zero-value notes are valid, so both stamping steps accept them: an output
/// mints one, and a spend consumes one.
#[test]
fn step_accepts_zero_value_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());

    {
        let zero_note = Note {
            pk: user.pak.derive_payment_key(),
            value: value::Positive::try_from(0u64).expect("zero is in range"),
            psi: nullifier::Trapdoor::random(rng),
            rcm: note::CommitmentTrapdoor::random(rng),
        };
        let out_rcv = value::Trapdoor::random(rng);
        let out_theta = ActionEntropy::random(rng);
        let out_alpha = out_theta.randomizer::<effect::Output>(zero_note.commitment());
        let out_anchor = PoolSim::genesis(rng).anchor();

        let (bind_pcd, ()) = PROOF_SYSTEM
            .seed(rng, output::OutputBind, (zero_note,))
            .expect("bind of a zero-value note");

        PROOF_SYSTEM
            .fuse(
                rng,
                stamp::OutputStamp,
                (out_rcv, out_alpha, zero_note, out_anchor),
                bind_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("output of a zero-value note");
    }

    {
        let mut pool = PoolSim::genesis(rng);
        let note = user.random_note(0);
        pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
        let height = pool.height();
        let spend_epoch = height.epoch();
        let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
        let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd, spend_epoch);

        let (rcv, _theta, alpha) = spend_witness(rng, &note);

        PROOF_SYSTEM
            .fuse(
                rng,
                stamp::SpendStamp,
                (note, rcv, alpha, user.pak),
                bind_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("spend of a zero-value note");
    }
}

#[test]
fn spend_after_lift_publishes_anchor_epoch_nullifiers() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let cm_height = mine_cm_block(rng, &mut pool, note.commitment());
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let start_anchor = spendable.data().2;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1))
        ],
        cm_height,
        start_anchor,
    );
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    let lifted = user.lift(rng, spendable, unspent, &note, EpochIndex(0), EpochIndex(1));

    let spend_pcd = honest_spend_bind(rng, &user, &note, lifted, EpochIndex(1));
    let (_cm, present_nf, _nf_next, _anchor) = *spend_pcd.data();
    assert_eq!(
        present_nf,
        user.nf_at(&note, EpochIndex(1)),
        "publishes the epoch-1 nf"
    );
    assert_ne!(
        present_nf,
        user.nf_at(&note, EpochIndex(0)),
        "nf_0 was consumed by the lift"
    );

    let stamp = honest_spend_stamp(rng, &user, &note, spend_pcd);
    let expected = TachygramSetPoly::from_iter([
        user.nf_at(&note, EpochIndex(1)).into(),
        user.nf_at(&note, EpochIndex(2)).into(),
    ])
    .commit();
    assert_eq!(stamp.data().1, expected);
}

#[test]
fn spend_stamp_assembles_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let spend_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd, spend_epoch);
    let stamp_pcd = honest_spend_stamp(rng, &user, &note, spend_pcd);
    let (_actions, tg_commit, _anchor) = *stamp_pcd.data();
    let expected = TachygramSetPoly::from_iter([
        Tachygram::from(user.nf_at(&note, spend_epoch)),
        Tachygram::from(user.nf_at(&note, spend_epoch.next())),
    ])
    .commit();
    assert_eq!(tg_commit, expected);
}

#[test]
fn notes_with_shared_psi_share_nullifiers() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note_a = user.random_note(500);
    let note_b = Note {
        value: value::Positive::try_from(700u64).expect("test value in range"),
        rcm: note::CommitmentTrapdoor::random(rng),
        ..note_a
    };
    assert_eq!(Fp::from(note_a.psi), Fp::from(note_b.psi), "shared psi");
    assert_ne!(
        note_a.commitment(),
        note_b.commitment(),
        "distinct (rcm, value) yields distinct cm"
    );

    for epoch in 0..4u32 {
        assert_eq!(
            user.nf_at(&note_a, EpochIndex(epoch)),
            user.nf_at(&note_b, EpochIndex(epoch)),
            "shared psi yields shared nullifiers at epoch {epoch}"
        );
    }
}

#[test]
fn sync_sim_builds_unspent_for_wallet_lift_across_epochs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());

    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1))
        ],
        init_height,
        start_anchor,
    );

    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    assert_eq!(sync.consumed(0), 1);

    let lifted = user.lift(rng, spendable, unspent, &note, EpochIndex(0), EpochIndex(1));

    assert_eq!(
        lifted.data().1,
        (EpochIndex(1), user.nf_at(&note, EpochIndex(1))),
        "tip advanced to nf_1"
    );
    assert_eq!(
        lifted.data().2,
        pool.anchor_at(target_height),
        "anchor advanced"
    );
    assert_eq!(lifted.data().0, note.commitment(), "cm threaded unchanged");
}

#[test]
fn unspent_lift_spans_partial_and_whole_epochs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    // cm in a multi-stamp block mid-epoch 0: the spendable anchor sits mid-block,
    // so the lineage's first epoch is partial (the post-cm prefix).
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    assert_eq!(init_height.epoch().0, 0, "cm in epoch 0");
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1)),
            user.nf_at(&note, EpochIndex(2)),
            user.nf_at(&note, EpochIndex(3)),
        ],
        init_height,
        start_anchor,
    );

    // Advance to a mid-epoch-3 block (neither first nor last) so the last epoch is
    // also partial; epochs 1 and 2 are covered whole. The block-granular tree
    // therefore mixes stamp leaves (incl. multi-epoch right at upper
    // merges) with boundary crossing leaves. One interior empty block sits in
    // the walk, contributing no leaf.
    let empty_height = BlockHeight(EPOCH_SIZE + 4);
    let target_height = BlockHeight(3 * EPOCH_SIZE + 7);
    while pool.height() < target_height {
        if pool.height().0 + 1 == empty_height.0 {
            pool.advance(1, |_| Vec::new());
        } else {
            pool.advance(1, |_| random_block(rng, 1, 2));
        }
    }

    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    assert_eq!(
        sync.consumed(0),
        3,
        "three epoch crossings (0 -> 1 -> 2 -> 3)"
    );

    let lifted = user.lift(rng, spendable, unspent, &note, EpochIndex(0), EpochIndex(3));
    assert_eq!(
        lifted.data().1,
        (EpochIndex(3), user.nf_at(&note, EpochIndex(3))),
        "tip advanced to nf_3 across partial first/last and whole interior epochs"
    );
    assert_eq!(
        lifted.data().2,
        pool.anchor_at(target_height),
        "anchor advanced to the mid-epoch-3 target"
    );
    assert_eq!(lifted.data().0, note.commitment(), "cm threaded unchanged");
}

/// Two [`pool::ArbitraryUnspent`] halves meeting at a sub-block, mid-epoch
/// junction. Every anchor involved is off-boundary: the range runs from inside
/// a block of epoch 0, through a junction inside a block of epoch 2, to inside
/// a block of epoch 3 (every `random_block(rng, 1, 2)` block carries two
/// stamps, so its first stamp's anchor is sub-block). The left half carries
/// two crossings (the fuse runs at offset 2), the right half one.
fn multi_epoch_fuse_setup(
    rng: &mut StdRng,
) -> (
    Nullifier,
    Nullifier,
    Nullifier,
    Nullifier,
    Pcd<pool::ArbitraryUnspent>,
    Pcd<pool::ArbitraryUnspent>,
) {
    let mut pool = PoolSim::genesis(rng);
    pool.advance(3 * EPOCH_SIZE + 3, |_| random_block(rng, 1, 2));
    let nf0 = Nullifier::from(Fp::random(&mut *rng));
    let nf1 = Nullifier::from(Fp::random(&mut *rng));
    let nf2 = Nullifier::from(Fp::random(&mut *rng));
    let nf3 = Nullifier::from(Fp::random(&mut *rng));
    let start_height = BlockHeight(2);
    let junction_height = BlockHeight(2 * EPOCH_SIZE + 2);
    let end_height = BlockHeight(3 * EPOCH_SIZE + 2);
    let start = pool.prev_anchor_at(start_height).next_stamp(
        start_height.epoch(),
        &pool.stamp_commits_at(start_height)[0],
    );
    let junction = pool.prev_anchor_at(junction_height).next_stamp(
        junction_height.epoch(),
        &pool.stamp_commits_at(junction_height)[0],
    );
    let end = pool
        .prev_anchor_at(end_height)
        .next_stamp(end_height.epoch(), &pool.stamp_commits_at(end_height)[0]);
    let left = build_unspent_pcd_between_anchors(rng, &pool, &[nf0, nf1, nf2], (start, junction));
    let right = build_unspent_pcd_between_anchors(rng, &pool, &[nf2, nf3], (junction, end));
    assert_eq!(left.data().0, start, "left rooted at the sub-block start");
    assert_eq!(left.data().4, junction, "left ends at the junction");
    assert_eq!(right.data().0, junction, "right rooted at the junction");
    assert_eq!(right.data().4, end, "right ends at the sub-block end");
    (nf0, nf1, nf2, nf3, left, right)
}

#[test]
fn unspent_fuse_composes() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (nf0, nf1, nf2, nf3, left, right) = multi_epoch_fuse_setup(rng);
    let start = left.data().0;
    let end = right.data().4;

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            witness::unspent_fuse((*left.data(), *right.data()), &[nf0, nf1], &[nf2]),
            left,
            right,
        )
        .expect("UnspentFuse mid-epoch with multi-epoch halves");

    let (anchor_prev, (epoch_start, nf_start), elapsed, (epoch_end, nf_end), anchor_last) =
        *fused.data();
    assert_eq!(anchor_prev, start);
    assert_eq!(anchor_last, end);
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([nf0, nf1, nf2]).commit(),
        "left's sentinel cancels at X^2 and right's crossing lands in its slot"
    );
    assert_eq!(nf_start, nf0);
    assert_eq!(nf_end, nf3, "tip advances to the right half's present nf");
    assert_eq!(epoch_start.0, 0);
    assert_eq!(
        epoch_end.0, 3,
        "merged range spans the boundary the right half crossed"
    );
}

#[test]
fn unspent_fuse_rejects_wrong_left_seq() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (nf0, nf1, nf2, _nf3, left, right) = multi_epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            (
                NfSeqPoly::from_iter([nf1, nf0]),
                NfSeqPoly::from_iter([nf0, nf1, nf2]),
                NfSeqPoly::from_iter([nf2]),
            ),
            left,
            right,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentFuse: left polynomial does not match header"
    );
}

#[test]
fn unspent_fuse_rejects_wrong_right_seq() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (nf0, nf1, nf2, nf3, left, right) = multi_epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            (
                NfSeqPoly::from_iter([nf0, nf1]),
                NfSeqPoly::from_iter([nf0, nf1, nf2]),
                NfSeqPoly::from_iter([nf3]),
            ),
            left,
            right,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentFuse: right polynomial does not match header"
    );
}

#[test]
fn unspent_fuse_rejects_wrong_combined() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (nf0, nf1, nf2, _nf3, left, right) = multi_epoch_fuse_setup(rng);
    // Both halves honest; `combined` forged as the right half alone. At offset
    // 0 this forgery satisfies the degenerate identity, so it must fail here.
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            (
                NfSeqPoly::from_iter([nf0, nf1]),
                NfSeqPoly::from_iter([nf2]),
                NfSeqPoly::from_iter([nf2]),
            ),
            left,
            right,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentFuse: combined is not the concatenation of the halves"
    );
}

#[test]
fn unspent_fuse_rejects_epoch_boundary_crossing() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.advance(EPOCH_SIZE + 1, |_| random_block(rng, 1, 2));

    let nf0 = Nullifier::from(Fp::random(&mut *rng));
    let nf1 = Nullifier::from(Fp::random(&mut *rng));
    // Left half spans all of epoch 0; `left.end` is epoch 0's terminal anchor.
    let left = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[nf0],
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let left_end = left.data().4;
    // A forged epoch-1 right half rooted directly at `left.anchor_last` (no
    // `next_epoch` fold). The anchors line up, but the epoch labels reveal a
    // boundary the fuse refuses to cross: a crossing needs its own segment.
    let stamp = [Tachygram::random(&mut *rng)];
    let forged_right = build_unspent_seed_pcd(rng, left_end, EpochIndex(1), &stamp, nf1);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            witness::unspent_fuse((*left.data(), *forged_right.data()), &[], &[]),
            left,
            forged_right,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentFuse: forwards half must sit in left's tip epoch"
    );
}

/// Two [`pool::ArbitraryUnspent`] halves meeting at the epoch 2/3 boundary,
/// together crossing four boundaries. The junction is boundary-pinned by the
/// step's design, but both outer endpoints are off-boundary, sub-block anchors:
/// the left half runs from inside a block of epoch 0 to epoch 2's terminal
/// anchor, the right half from the boundary to inside a block of epoch 4.
fn epoch_fuse_setup(
    rng: &mut StdRng,
) -> (
    [Nullifier; 5],
    Pcd<pool::ArbitraryUnspent>,
    Pcd<pool::ArbitraryUnspent>,
) {
    let mut pool = PoolSim::genesis(rng);
    pool.advance(4 * EPOCH_SIZE + 3, |_| random_block(rng, 1, 2));
    let nf: [Nullifier; 5] = array::from_fn(|_| Nullifier::from(Fp::random(&mut *rng)));
    let start_height = BlockHeight(2);
    let end_height = BlockHeight(4 * EPOCH_SIZE + 2);
    let start = pool.prev_anchor_at(start_height).next_stamp(
        start_height.epoch(),
        &pool.stamp_commits_at(start_height)[0],
    );
    let end = pool
        .prev_anchor_at(end_height)
        .next_stamp(end_height.epoch(), &pool.stamp_commits_at(end_height)[0]);
    let left = build_unspent_pcd_between_anchors(
        rng,
        &pool,
        &nf[..3],
        (start, pool.anchor_at(BlockHeight(3 * EPOCH_SIZE - 1))),
    );
    let right = build_unspent_pcd_between_anchors(
        rng,
        &pool,
        &nf[3..],
        (pool.prev_anchor_at(BlockHeight(3 * EPOCH_SIZE)), end),
    );
    assert_eq!(left.data().0, start, "left rooted at the sub-block start");
    assert_eq!(right.data().4, end, "right ends at the sub-block end");
    (nf, left, right)
}

/// Two halves meeting at a boundary compose through a crossing seed: the seam
/// nullifier the left half was still holding as its tip lands in the merged
/// history, and the merged segment spans both halves' outer endpoints.
#[test]
fn end_epoch_unspent_seed_composes_across_a_boundary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, nf2, nf3, nf4], left, right) = epoch_fuse_setup(rng);
    let start = left.data().0;
    let end = right.data().4;

    // Seed the crossing on left's terminal anchor and fuse it on, so left's
    // tip nullifier stops being in progress and joins the history.
    let (seed, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::EndEpochUnspentSeed,
            witness::end_epoch_unspent_seed(((), ()), left.data().4, EpochIndex(2), nf2, nf3),
        )
        .expect("EndEpochUnspentSeed");
    let (crossed, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            witness::unspent_fuse((*left.data(), *seed.data()), &[nf0, nf1], &[nf2]),
            left,
            seed,
        )
        .expect("UnspentFuse over the crossing");

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            witness::unspent_fuse((*crossed.data(), *right.data()), &[nf0, nf1, nf2], &[nf3]),
            crossed,
            right,
        )
        .expect("UnspentFuse onto the right half");

    let (anchor_prev, (epoch_start, nf_start), elapsed, (epoch_end, nf_end), anchor_last) =
        *fused.data();
    assert_eq!(anchor_prev, start);
    assert_eq!(anchor_last, end);
    assert_eq!(epoch_start.0, 0);
    assert_eq!(nf_start, nf0);
    assert_eq!(epoch_end.0, 4);
    assert_eq!(nf_end, nf4, "tip is the right half's present nf");
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([nf0, nf1, nf2, nf3]).commit(),
        "the crossing seed carries left's tip into the merged history"
    );
}

/// The seed spans exactly one boundary link, recording the epoch it leaves.
#[test]
fn end_epoch_unspent_seed_spans_one_boundary_link() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch_tip = Anchor::from(Fp::random(&mut *rng));
    let nf_prev = Nullifier::from(Fp::random(&mut *rng));
    let nf = Nullifier::from(Fp::random(&mut *rng));

    let (seed, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::EndEpochUnspentSeed,
            witness::end_epoch_unspent_seed(((), ()), epoch_tip, EpochIndex(4), nf_prev, nf),
        )
        .expect("EndEpochUnspentSeed");

    let (anchor_prev, (epoch_start, seed_nf_start), elapsed, (epoch_end, nf_end), anchor_last) =
        *seed.data();
    assert_eq!(anchor_prev, epoch_tip);
    assert_eq!(
        anchor_last,
        epoch_tip.next_epoch(EpochIndex(5)),
        "the segment covers the boundary tick"
    );
    assert_eq!(epoch_start, EpochIndex(4));
    assert_eq!(epoch_end, EpochIndex(5), "one boundary crossed");
    assert_eq!(seed_nf_start, nf_prev);
    assert_eq!(nf_end, nf);
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([nf_prev]).commit(),
        "the crossing records the epoch it leaves"
    );
}

/// A lineage on its epoch's terminal anchor lifts over the crossing seed like
/// any other segment, and the next segment opens on the boundary anchor it
/// lands on.
#[test]
fn spendable_lift_advances_from_an_epoch_tip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(300);
    // A lone cm-stamp, then a silent rest-of-epoch, leaves the spendable's
    // anchor sitting on epoch 0's terminal anchor.
    pool.mine(vec![vec![note.commitment().into()]]);
    let cm_height = pool.height();
    while pool.height().0 + 1 < EPOCH_SIZE {
        pool.advance(1, |_| Vec::new());
    }
    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let epoch0_tip = spendable.data().2;
    assert_eq!(
        epoch0_tip,
        pool.pre_epoch_anchor(EpochIndex(1)),
        "the lineage sits on the epoch tip"
    );

    pool.advance(1, |_| random_block(rng, 1, 2));
    let target_height = pool.height();
    assert_eq!(target_height.epoch(), EpochIndex(1));

    // The crossing is an ordinary segment, so an ordinary lift carries the
    // lineage over it.
    let (crossing, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::EndEpochUnspentSeed,
            witness::end_epoch_unspent_seed(
                ((), ()),
                epoch0_tip,
                EpochIndex(0),
                user.nf_at(&note, EpochIndex(0)),
                user.nf_at(&note, EpochIndex(1)),
            ),
        )
        .expect("EndEpochUnspentSeed");
    let at_boundary = user.lift(
        rng,
        spendable,
        crossing,
        &note,
        EpochIndex(0),
        EpochIndex(1),
    );
    assert_eq!(
        *at_boundary.data(),
        (
            note.commitment(),
            (EpochIndex(1), user.nf_at(&note, EpochIndex(1))),
            epoch0_tip.next_epoch(EpochIndex(1))
        ),
        "the tick advances epoch, nullifier and anchor together"
    );

    // The lineage now rests on epoch 1's boundary anchor.
    let arbitrary = build_unspent_pcd_between_anchors(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(1))],
        (at_boundary.data().2, pool.anchor_at(target_height)),
    );
    let lifted = user.lift(
        rng,
        at_boundary,
        arbitrary,
        &note,
        EpochIndex(1),
        EpochIndex(1),
    );

    assert_eq!(
        lifted.data().1,
        (EpochIndex(1), user.nf_at(&note, EpochIndex(1)))
    );
    assert_eq!(lifted.data().2, pool.anchor_at(target_height));
}

/// A span opening on a boundary anchor covers the crossings after it, not the
/// one that produced it: the lineage already paid for that crossing to arrive.
#[test]
fn unspent_span_starting_on_a_boundary_anchor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(300);
    // A lone cm-stamp, then silence to the end of epoch 0, so the lineage ends
    // up on epoch 0's terminal anchor and crosses to `B_1` by a bare lift.
    pool.mine(vec![vec![note.commitment().into()]]);
    let cm_height = pool.height();
    while pool.height().0 + 1 < EPOCH_SIZE {
        pool.advance(1, |_| Vec::new());
    }
    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let epoch0_tip = spendable.data().2;
    let (crossing, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::EndEpochUnspentSeed,
            witness::end_epoch_unspent_seed(
                ((), ()),
                epoch0_tip,
                EpochIndex(0),
                user.nf_at(&note, EpochIndex(0)),
                user.nf_at(&note, EpochIndex(1)),
            ),
        )
        .expect("EndEpochUnspentSeed");
    let at_boundary = user.lift(
        rng,
        spendable,
        crossing,
        &note,
        EpochIndex(0),
        EpochIndex(1),
    );

    // Epoch 1 publishes nothing, so the span starts on a boundary anchor whose
    // own epoch is silent; epoch 2 resumes.
    while pool.height().0 + 1 < 2 * EPOCH_SIZE {
        pool.advance(1, |_| Vec::new());
    }
    pool.advance(1, |_| random_block(rng, 1, 2));
    let target_height = pool.height();
    assert_eq!(target_height.epoch(), EpochIndex(2));

    let start_anchor = at_boundary.data().2;
    assert_eq!(start_anchor, pool.pre_epoch_anchor(EpochIndex(2)));
    let arbitrary = build_unspent_pcd_between_anchors(
        rng,
        &pool,
        &[
            user.nf_at(&note, EpochIndex(1)),
            user.nf_at(&note, EpochIndex(2)),
        ],
        (start_anchor, pool.anchor_at(target_height)),
    );
    let (_, (epoch_start, _), elapsed, (epoch_end, _), _) = *arbitrary.data();
    assert_eq!(epoch_start, EpochIndex(1));
    assert_eq!(epoch_end, EpochIndex(2));
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([user.nf_at(&note, EpochIndex(1))]).commit(),
        "only the crossing out of the silent epoch, not the one into it"
    );

    let lifted = user.lift(
        rng,
        at_boundary,
        arbitrary,
        &note,
        EpochIndex(1),
        EpochIndex(2),
    );
    assert_eq!(
        lifted.data().1,
        (EpochIndex(2), user.nf_at(&note, EpochIndex(2)))
    );
    assert_eq!(lifted.data().2, pool.anchor_at(target_height));
}

/// A span may end on a boundary anchor: an epoch that has published nothing
/// yet has no post anchor for its blocks to resolve against, so the end
/// resolves to the boundary and the span stops on the crossing.
#[test]
fn unspent_span_ending_on_a_boundary_anchor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(300);
    let cm_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, cm_height);

    // Epoch 0 publishes after the cm; epoch 1 opens with a stampless block, so
    // that block's anchor is `B_1` itself.
    while pool.height().0 + 1 < EPOCH_SIZE {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    pool.advance(1, |_| Vec::new());
    let target_height = pool.height();
    assert_eq!(target_height.epoch(), EpochIndex(1));
    assert_eq!(
        pool.anchor_at(target_height),
        pool.pre_epoch_anchor(EpochIndex(1))
            .next_epoch(EpochIndex(1)),
        "a silent epoch-first block rests on the boundary anchor"
    );

    let arbitrary = build_unspent_pcd_between_anchors(
        rng,
        &pool,
        &[
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1)),
        ],
        (spendable.data().2, pool.anchor_at(target_height)),
    );
    let (_, (epoch_start, _), elapsed, (epoch_end, _), anchor_last) = *arbitrary.data();
    assert_eq!(epoch_start, EpochIndex(0));
    assert_eq!(epoch_end, EpochIndex(1), "the span stops on the crossing");
    assert_eq!(anchor_last, pool.anchor_at(target_height));
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([user.nf_at(&note, EpochIndex(0))]).commit()
    );

    let lifted = user.lift(
        rng,
        spendable,
        arbitrary,
        &note,
        EpochIndex(0),
        EpochIndex(1),
    );
    assert_eq!(
        lifted.data().1,
        (EpochIndex(1), user.nf_at(&note, EpochIndex(1)))
    );
    assert_eq!(lifted.data().2, pool.anchor_at(target_height));
}

/// A stampless epoch is two crossings with nothing between them, so the span
/// still records its nullifier.
#[test]
fn end_epoch_unspent_seed_crosses_a_stampless_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(300);
    let cm_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, cm_height);

    // Epoch 0 keeps publishing after the cm, so the lineage is not on its tip.
    // Epoch 1 then publishes nothing at all; epoch 2 resumes.
    while pool.height().0 + 1 < EPOCH_SIZE {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    while pool.height().0 + 1 < 2 * EPOCH_SIZE {
        pool.advance(1, |_| Vec::new());
    }
    pool.advance(1, |_| random_block(rng, 1, 2));
    let target_height = pool.height();
    assert_eq!(target_height.epoch(), EpochIndex(2));

    let arbitrary = build_unspent_pcd_between_anchors(
        rng,
        &pool,
        &[
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1)),
            user.nf_at(&note, EpochIndex(2)),
        ],
        (spendable.data().2, pool.anchor_at(target_height)),
    );
    let (_, (epoch_start, _), elapsed, (epoch_end, _), _) = *arbitrary.data();
    assert_eq!(epoch_start, EpochIndex(0));
    assert_eq!(epoch_end, EpochIndex(2));
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1)),
        ])
        .commit(),
        "both crossings recorded, including the one over the silent epoch"
    );

    let lifted = user.lift(
        rng,
        spendable,
        arbitrary,
        &note,
        EpochIndex(0),
        EpochIndex(2),
    );
    assert_eq!(
        lifted.data().1,
        (EpochIndex(2), user.nf_at(&note, EpochIndex(2)))
    );
    assert_eq!(lifted.data().2, pool.anchor_at(target_height));
}

#[test]
fn unspent_bind_rejects_tip_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;

    let wrong_tip = Nullifier::from(Fp::random(&mut *rng));
    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1)),
            user.nf_at(&note, EpochIndex(2)),
            wrong_tip
        ],
        init_height,
        start_anchor,
    );
    let target_height = BlockHeight(3 * EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);

    // The witnessed polynomials are the genuine derived values; the unspent
    // header carries the forged tip, so the appended-tip relation rejects the
    // lineage against the derived range.
    let range = user.derived_range(rng, &note, EpochIndex(0), 4);
    let elapsed = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
    ]);
    let nf_seq = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
        user.nf_at(&note, EpochIndex(3)),
    ]);

    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentBind, (elapsed, nf_seq), unspent, range)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: range is not elapsed followed by the tip"
    );
}

/// A three-crossing epoch 0..=3 [`pool::ArbitraryUnspent`] lineage from the
/// block after the note's cm block to a mid-epoch-3 block, for pairing against
/// derived ranges. Its honest witness polynomials are `elapsed = nf[0..3]`
/// and `nf_seq = nf[0..4]`, against `derived_range(.., EpochIndex(0), 4)`.
fn unspent_bind_setup(rng: &mut StdRng) -> (WalletSim, Note, Pcd<pool::ArbitraryUnspent>) {
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let end_height = BlockHeight(3 * EPOCH_SIZE + 2);
    while pool.height() < end_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let unspent = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1)),
            user.nf_at(&note, EpochIndex(2)),
            user.nf_at(&note, EpochIndex(3)),
        ],
        BlockHeight(init_height.0 + 1)..=end_height,
    );
    (user, note, unspent)
}

#[test]
fn unspent_bind_rejects_elapsed_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (user, note, unspent) = unspent_bind_setup(rng);
    let range = user.derived_range(rng, &note, EpochIndex(0), 4);
    // The genuine crossings in swapped order commit differently.
    let bogus_elapsed = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(2)),
    ]);
    let nf_seq = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
        user.nf_at(&note, EpochIndex(3)),
    ]);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentBind,
            (bogus_elapsed, nf_seq),
            unspent,
            range,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: elapsed polynomial does not match header"
    );
}

#[test]
fn unspent_bind_rejects_wrong_start_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (user, note, unspent) = unspent_bind_setup(rng);
    let range = user.derived_range(rng, &note, EpochIndex(1), 4);
    let elapsed = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
    ]);
    let nf_seq = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
        user.nf_at(&note, EpochIndex(3)),
        user.nf_at(&note, EpochIndex(4)),
    ]);

    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentBind, (elapsed, nf_seq), unspent, range)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: derived range does not start at the unspent's start epoch"
    );
}

#[test]
fn unspent_bind_rejects_wrong_span() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (user, note, unspent) = unspent_bind_setup(rng);
    // A three-crossing lineage demands a range of exactly its crossings plus
    // the tip (four epochs); a five-epoch range overshoots.
    let range = user.derived_range(rng, &note, EpochIndex(0), 5);
    let elapsed = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
    ]);
    let nf_seq = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
        user.nf_at(&note, EpochIndex(3)),
        user.nf_at(&note, EpochIndex(4)),
    ]);

    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentBind, (elapsed, nf_seq), unspent, range)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: derived range does not span the crossings plus the tip"
    );
}

#[test]
fn unspent_bind_rejects_wrong_range_poly() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (user, note, unspent) = unspent_bind_setup(rng);
    let range = user.derived_range(rng, &note, EpochIndex(0), 4);
    let elapsed = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
    ]);
    // The genuine range in swapped order commits differently.
    let bogus_nf_seq = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(2)),
        user.nf_at(&note, EpochIndex(3)),
    ]);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentBind,
            (elapsed, bogus_nf_seq),
            unspent,
            range,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: range polynomial does not match header"
    );
}

#[test]
fn unspent_bind_rejects_start_nf_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (user, note, unspent) = unspent_bind_setup(rng);
    // A range header whose `nf_start` disagrees with its own committed
    // sequence: the derivation steps never produce this, so it is carried
    // directly.
    let range = user.derived_range(rng, &note, EpochIndex(0), 4);
    let (nf_cm, (epoch_start, _nf_start), seq_commit, (epoch_end, nf_end)) = *range.data();
    let bogus = Nullifier::from(Fp::random(&mut *rng));
    let forged_range = Proof::trivial().carry::<delegation::NullifierHeader>((
        nf_cm,
        (epoch_start, bogus),
        seq_commit,
        (epoch_end, nf_end),
    ));
    let elapsed = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
    ]);
    let nf_seq = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
        user.nf_at(&note, EpochIndex(3)),
    ]);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentBind,
            (elapsed, nf_seq),
            unspent,
            forged_range,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: start nullifier does not match the derived range"
    );
}

#[test]
fn unspent_bind_rejects_end_nf_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (user, note, unspent) = unspent_bind_setup(rng);
    // The mirror forgery: `nf_end` disagrees with the committed sequence.
    let range = user.derived_range(rng, &note, EpochIndex(0), 4);
    let (nf_cm, (epoch_start, nf_start), seq_commit, (epoch_end, _nf_end)) = *range.data();
    let bogus = Nullifier::from(Fp::random(&mut *rng));
    let forged_range = Proof::trivial().carry::<delegation::NullifierHeader>((
        nf_cm,
        (epoch_start, nf_start),
        seq_commit,
        (epoch_end, bogus),
    ));
    let elapsed = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
    ]);
    let nf_seq = NfSeqPoly::from_iter([
        user.nf_at(&note, EpochIndex(0)),
        user.nf_at(&note, EpochIndex(1)),
        user.nf_at(&note, EpochIndex(2)),
        user.nf_at(&note, EpochIndex(3)),
    ]);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentBind,
            (elapsed, nf_seq),
            unspent,
            forged_range,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: end nullifier does not match the derived range"
    );
}

#[test]
fn spendable_lift_rejects_wrong_cm() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let phantom = Note {
        value: value::Positive::try_from(700u64).expect("test value in range"),
        rcm: note::CommitmentTrapdoor::random(rng),
        ..note
    };
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1))
        ],
        init_height,
        start_anchor,
    );
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let arbitrary = sync.build_next_unspent(rng, 0, &pool, target_height);
    let unspent = user.unspent_bind(rng, arbitrary, &phantom, EpochIndex(0), EpochIndex(1));

    let err = PROOF_SYSTEM
        .fuse(rng, spendable::SpendableLift, (), spendable, unspent)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendableLift: unspent cm does not match spendable"
    );
}

#[test]
fn crossing_bind_rejects_bad_range() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let other = user.random_note(700);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());

    let cases = [
        // The range must derive from the lineage's own note. The bind reaches
        // its polynomial check before its nullifier checks, so a foreign
        // range's sequence is what first disagrees; the `cm` identity itself
        // is `SpendableLift`'s to enforce.
        (
            &other,
            EpochIndex(0),
            2,
            "UnspentBind: range polynomial does not match header",
        ),
        // The range must open on the epoch the lineage is presently in.
        (
            &note,
            EpochIndex(1),
            2,
            "UnspentBind: derived range does not start at the unspent's start epoch",
        ),
        // The range spans exactly the two epochs the crossing moves between.
        (
            &note,
            EpochIndex(0),
            3,
            "UnspentBind: derived range does not span the crossings plus the tip",
        ),
    ];

    for (range_note, epoch_start, len, expected) in cases {
        let spendable = user.spendable_init(rng, &note, &pool, init_height);
        let (_, (epoch, present_nf), anchor) = *spendable.data();
        let (crossing, ()) = PROOF_SYSTEM
            .seed(
                rng,
                pool::EndEpochUnspentSeed,
                witness::end_epoch_unspent_seed(
                    ((), ()),
                    anchor,
                    epoch,
                    present_nf,
                    user.nf_at(&note, epoch.next()),
                ),
            )
            .expect("EndEpochUnspentSeed");
        let range = user.derived_range(rng, range_note, epoch_start, len);
        let elapsed = [present_nf];
        let err = PROOF_SYSTEM
            .fuse(
                rng,
                pool::UnspentBind,
                witness::unspent_bind((*crossing.data(), *range.data()), &elapsed),
                crossing,
                range,
            )
            .err()
            .unwrap_or_else(|| panic!("UnspentBind accepted {expected}"));
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness for {expected}, got {err:?}");
        };
        assert_eq!(inner.to_string(), expected);
    }
}

#[test]
fn spendable_lift_rejects_non_adjacent_unspent() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let arbitrary = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(0))],
        init_height..=init_height,
    );
    let unspent = user.unspent_bind(rng, arbitrary, &note, EpochIndex(0), EpochIndex(0));

    let err = PROOF_SYSTEM
        .fuse(rng, spendable::SpendableLift, (), spendable, unspent)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendableLift: unspent not adjacent to spendable"
    );
}

#[test]
fn nullifier_fuse_rejects_non_contiguous() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let range_a = user.derived_range(rng, &note, EpochIndex(0), 1);
    let range_b = user.derived_range(rng, &note, EpochIndex(2), 1);
    let witness = witness::nullifier_fuse(
        (*range_a.data(), *range_b.data()),
        &[user.nf_at(&note, EpochIndex(0))],
        user.nf_at(&note, EpochIndex(2)),
    );

    let err = PROOF_SYSTEM
        .fuse(rng, delegation::NullifierFuse, witness, range_a, range_b)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "NullifierFuse: ranges not contiguous");
}

#[test]
fn nullifier_fuse_rejects_wrong_cm() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note_a = user.random_note(500);
    let note_b = user.random_note(500);

    let range_a = user.derived_range(rng, &note_a, EpochIndex(0), 1);
    let range_b = user.derived_range(rng, &note_b, EpochIndex(1), 1);
    let witness = witness::nullifier_fuse(
        (*range_a.data(), *range_b.data()),
        &[user.nf_at(&note_a, EpochIndex(0))],
        user.nf_at(&note_b, EpochIndex(1)),
    );

    let err = PROOF_SYSTEM
        .fuse(rng, delegation::NullifierFuse, witness, range_a, range_b)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "NullifierFuse: note commitments differ");
}

/// The pad the step publishes is `pad_tachygram` over the note's own fields.
fn expected_pad(note: &Note) -> Tachygram {
    Tachygram::from(poseidon::pad_tachygram(
        Fp::from(note.rcm),
        Fp::from(note.pk),
        u64::from(note.value),
        Fp::from(note.psi),
    ))
}

/// `OutputBind` emits the note's commitment and pad, both derived natively.
#[test]
fn output_bind_publishes_the_note_pair() {
    let rng = &mut StdRng::seed_from_u64(0);
    let note = WalletSim::new(shared_sk()).random_note(200);

    let (pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note,))
        .expect("OutputBind honest");

    assert_eq!(
        *pcd.data(),
        (Tachygram::from(note.commitment()), expected_pad(&note))
    );
}

/// Domain separation is what the pad buys: the same note fields hashed under
/// two domains must not coincide.
#[test]
fn pad_differs_from_commitment() {
    let note = WalletSim::new(shared_sk()).random_note(200);

    assert_ne!(Tachygram::from(note.commitment()), expected_pad(&note));
}

/// `OutputStamp` binds its note to the pair `OutputBind` settled.
#[test]
fn output_stamp_rejects_note_not_matching_the_bind() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let bound_note = user.random_note(200);
    let other_note = user.random_note(300);

    let (bind_pcd, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (bound_note,))
        .expect("OutputBind honest");

    let (rcv, alpha, _plan) = build_output_plan(rng, other_note);
    let anchor = PoolSim::genesis(rng).anchor();

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::OutputStamp,
            (rcv, alpha, other_note, anchor),
            bind_pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "OutputStamp: note does not match the bound output"
    );
}
