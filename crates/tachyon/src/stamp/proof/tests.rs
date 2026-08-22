//! Proof-step tests: `StampLift`, `SpendBind` / `SpendStamp`, the flat
//! nullifier-derivation chain, `ArbitraryUnspent` composition, and the
//! `Spendable*` lineage.

#![allow(
    clippy::panic,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "test code"
)]

extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::{array, iter};

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
    nullifier::{self, NF_DERIVATION_WIDTH, Nullifier},
    primitives::{
        Anchor, BlockHeight, EpochGroup, EpochIndex, NfMarginPoly, NfTailPoly, Tachygram, effect,
    },
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
    let derived = user.derivation_pcd(rng, *note, spend_epoch, EpochIndex(spend_epoch.0 + 2));
    let witness = witness::spend_bind(
        (*spendable.data(), *derived.data()),
        &user.covering_window(note, &derived),
    );
    let (bind_pcd, ()) = PROOF_SYSTEM
        .fuse(rng, spend::SpendBind, witness, spendable, derived)
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
    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable, epoch);
    let stamp = honest_spend_stamp(rng, &user, &note, bind_pcd);

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

    let nf_header = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(1));
    let absent_tg = Tachygram::random(&mut *rng);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            witness::spendable_init(
                (*nf_header.data(), ()),
                Anchor::default(),
                &[absent_tg],
                EpochIndex(0),
                &user.covering_window(&note, &nf_header),
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
    let mk = user.pak.nk.derive_note_private(note.psi);
    let nf = mk.derive_nullifier(EpochIndex(0));

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
        let w = witness::unspent_fuse((*shard_a.data(), *shard_b.data()), &[nf_a], &[nf_b]);
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
        let w = witness::unspent_fuse((*shard_a.data(), *shard_b.data()), &[nf], &[nf]);
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

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd, spend_epoch);
    let (_cm, present_nf, nf_next, _anchor) = *bind_pcd.data();
    assert_eq!(present_nf, user.nf_at(&note, spend_epoch));
    assert_eq!(nf_next, user.nf_at(&note, spend_epoch.next()));
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

    let bind_pcd = honest_spend_bind(rng, &user, &note, lifted, EpochIndex(1));
    let (_cm, present_nf, _nf_next, _anchor) = *bind_pcd.data();
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

    let stamp = honest_spend_stamp(rng, &user, &note, bind_pcd);
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

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd, spend_epoch);
    let stamp_pcd = honest_spend_stamp(rng, &user, &note, bind_pcd);
    let (_actions, tg_commit, _anchor) = *stamp_pcd.data();
    let expected = TachygramSetPoly::from_iter([
        Tachygram::from(user.nf_at(&note, spend_epoch)),
        Tachygram::from(user.nf_at(&note, spend_epoch.next())),
    ])
    .commit();
    assert_eq!(tg_commit, expected);
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
            witness::unspent_fuse((*left.data(), *right.data()), &[nf0, nf1, nf2], &[nf2, nf3]),
            left,
            right,
        )
        .expect("UnspentFuse mid-epoch with multi-epoch halves");

    let (anchor_prev, (epoch_start, nf_start), elapsed, (epoch_last, nf_last), anchor_last) =
        *fused.data();
    assert_eq!(anchor_prev, start);
    assert_eq!(anchor_last, end);
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([nf0, nf1, nf2, nf3]).commit(),
        "the junction member appears once in the combined sequence"
    );
    assert_eq!(nf_start, nf0);
    assert_eq!(nf_last, nf3, "tip advances to the right half's present nf");
    assert_eq!(epoch_start.0, 0);
    assert_eq!(
        epoch_last.0, 3,
        "merged range spans the boundary the right half crossed"
    );
}

#[test]
fn unspent_fuse_rejects_wrong_left_seq() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (nf0, nf1, nf2, nf3, left, right) = multi_epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            (
                NfSeqPoly::from_iter([nf1, nf0, nf2]),
                NfSeqPoly::from_iter([nf0, nf1, nf2, nf3]),
                NfSeqPoly::from_iter([nf2, nf3]),
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
                NfSeqPoly::from_iter([nf0, nf1, nf2]),
                NfSeqPoly::from_iter([nf0, nf1, nf2, nf3]),
                NfSeqPoly::from_iter([nf3, nf2]),
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
    let (nf0, nf1, nf2, nf3, left, right) = multi_epoch_fuse_setup(rng);
    // Both halves honest; `combined` forged as the right half alone. The
    // right half carries two members, so the dedup identity is
    // non-degenerate and the forgery must fail here.
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            (
                NfSeqPoly::from_iter([nf0, nf1, nf2]),
                NfSeqPoly::from_iter([nf2, nf3]),
                NfSeqPoly::from_iter([nf2, nf3]),
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

/// A same-epoch fuse with a one-member right half adds stamps, not members:
/// the dedup identity degenerates to `combined = left`, and that combined
/// sequence is the honest one. Contrast
/// [`unspent_fuse_rejects_wrong_combined`], where a multi-member right half
/// makes the same shape a forgery.
#[test]
fn unspent_fuse_accepts_left_as_combined_for_one_member_right() {
    let rng = &mut StdRng::seed_from_u64(0);
    let stamps_left = vec![Tachygram::random(&mut *rng)];
    let stamps_right = vec![Tachygram::random(&mut *rng)];
    let start = Anchor::default();
    let mid = start.next_stamp(
        EpochIndex(0),
        &TachygramSetPoly::from_iter(stamps_left.clone()).commit(),
    );
    let nf = Nullifier::from(Fp::random(&mut *rng));
    let left = build_unspent_seed_pcd(rng, start, EpochIndex(0), &stamps_left, nf);
    let right = build_unspent_seed_pcd(rng, mid, EpochIndex(0), &stamps_right, nf);

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            witness::unspent_fuse((*left.data(), *right.data()), &[nf], &[nf]),
            left,
            right,
        )
        .expect("one-member halves fuse");
    assert_eq!(
        fused.data().2,
        NfSeqPoly::from_iter([nf]).commit(),
        "combined equals the left sequence"
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
            witness::unspent_fuse((*left.data(), *forged_right.data()), &[nf0], &[nf1]),
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
            witness::unspent_fuse((*left.data(), *seed.data()), &[nf0, nf1, nf2], &[nf2, nf3]),
            left,
            seed,
        )
        .expect("UnspentFuse over the crossing");

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            witness::unspent_fuse(
                (*crossed.data(), *right.data()),
                &[nf0, nf1, nf2, nf3],
                &[nf3, nf4],
            ),
            crossed,
            right,
        )
        .expect("UnspentFuse onto the right half");

    let (anchor_prev, (epoch_start, nf_start), elapsed, (epoch_last, nf_last), anchor_last) =
        *fused.data();
    assert_eq!(anchor_prev, start);
    assert_eq!(anchor_last, end);
    assert_eq!(epoch_start.0, 0);
    assert_eq!(nf_start, nf0);
    assert_eq!(epoch_last.0, 4);
    assert_eq!(nf_last, nf4, "tip is the right half's present nf");
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([nf0, nf1, nf2, nf3, nf4]).commit(),
        "the crossing seed shares a member with each half it joins"
    );
}

/// A zero head would make the two-member encoding commit exactly as a
/// one-member sequence does, so the crossing could present itself as a point
/// segment. The rank pin is the guard against it.
#[test]
fn end_epoch_unspent_seed_rejects_a_zero_member() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let nf = Nullifier::from(Fp::random(&mut *rng));
    let zero = Nullifier::from(Fp::ZERO);

    for (nf_prev, incoming, expected) in [
        (zero, nf, "EndEpochUnspentSeed: outgoing nullifier is zero"),
        (nf, zero, "EndEpochUnspentSeed: incoming nullifier is zero"),
    ] {
        let err = PROOF_SYSTEM
            .seed(
                rng,
                pool::EndEpochUnspentSeed,
                witness::end_epoch_unspent_seed(((), ()), anchor, EpochIndex(4), nf_prev, incoming),
            )
            .err()
            .unwrap_or_else(|| panic!("EndEpochUnspentSeed accepted {expected}"));
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness for {expected}, got {err:?}");
        };
        assert_eq!(inner.to_string(), expected);
    }
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

    let (anchor_prev, (epoch_start, seed_nf_start), elapsed, (epoch_last, nf_last), anchor_last) =
        *seed.data();
    assert_eq!(anchor_prev, epoch_tip);
    assert_eq!(
        anchor_last,
        epoch_tip.next_epoch(EpochIndex(5)),
        "the segment covers the boundary tick"
    );
    assert_eq!(epoch_start, EpochIndex(4));
    assert_eq!(epoch_last, EpochIndex(5), "one boundary crossed");
    assert_eq!(seed_nf_start, nf_prev);
    assert_eq!(nf_last, nf);
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([nf_prev, nf]).commit(),
        "the crossing records the epoch it leaves and the one it enters"
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
    let (_, (epoch_start, _), elapsed, (epoch_last, _), _) = *arbitrary.data();
    assert_eq!(epoch_start, EpochIndex(1));
    assert_eq!(epoch_last, EpochIndex(2));
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([
            user.nf_at(&note, EpochIndex(1)),
            user.nf_at(&note, EpochIndex(2)),
        ])
        .commit(),
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
    let (_, (epoch_start, _), elapsed, (epoch_last, _), anchor_last) = *arbitrary.data();
    assert_eq!(epoch_start, EpochIndex(0));
    assert_eq!(epoch_last, EpochIndex(1), "the span stops on the crossing");
    assert_eq!(anchor_last, pool.anchor_at(target_height));
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1)),
        ])
        .commit()
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
    let (_, (epoch_start, _), elapsed, (epoch_last, _), _) = *arbitrary.data();
    assert_eq!(epoch_start, EpochIndex(0));
    assert_eq!(epoch_last, EpochIndex(2));
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1)),
            user.nf_at(&note, EpochIndex(2)),
        ])
        .commit(),
        "every covered epoch's member recorded, including the silent epoch's"
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
        alloc::vec![user.nf_at(&note, EpochIndex(0)), wrong_tip],
        init_height,
        start_anchor,
    );
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);

    // The witnessed sequence matches the header, with the forged tip as its
    // final member, so the poly bind passes; the covering read then compares
    // it against the genuine sequence and rejects the tip's coefficient.
    let (_, _, _, (unspent_last, _), _) = *unspent.data();
    let range = user.derivation_pcd(rng, note, EpochIndex(0), unspent_last.next());
    let witness = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &[user.nf_at(&note, EpochIndex(0)), wrong_tip],
    );

    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentBind, witness, unspent, range)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: sequence does not match the derivation"
    );
}

#[test]
fn unspent_bind_rejects_elapsed_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let unspent = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(0))],
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    let range = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(1));
    let (_honest_elapsed_seq, nf_seq, older, tail) = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &[user.nf_at(&note, EpochIndex(0))],
    );
    let bogus_elapsed = NfSeqPoly::from_iter([Nullifier::from(Fp::random(&mut *rng))]);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentBind,
            (bogus_elapsed, nf_seq, older, tail),
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
fn unspent_bind_rejects_uncovered_start() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let unspent = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(0))],
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    // A derivation whose coverage begins after the unspent's start epoch (a
    // later window) cannot cover it.
    // The builder would segment out of range, so the witness is assembled
    // by hand: the genuine covering sequence, empty margins.
    let range = user.derivation_pcd(rng, note, EpochIndex(64), EpochIndex(65));
    let window = user.covering_window(&note, &range);
    let witness = (
        iter::once(user.nf_at(&note, EpochIndex(0))).collect(),
        window.iter().copied().collect::<NfSeqPoly>(),
        NfMarginPoly::new(&[]),
        NfTailPoly::new(&[]),
    );

    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentBind, witness, unspent, range)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: derivation does not cover the unspent start"
    );
}

/// The covering read needs the tip as well as the crossings, so a derivation
/// stopping at the unspent's own end epoch does not cover it.
#[test]
fn unspent_bind_rejects_uncovered_end() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    // A crossing out of the window's last epoch: its tip sits at the first
    // epoch the derivation does not reach.
    let last = EpochIndex(NF_DERIVATION_WIDTH as u32 - 1);
    let anchor = Anchor::from(Fp::random(&mut *rng));
    let (unspent, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::EndEpochUnspentSeed,
            witness::end_epoch_unspent_seed(
                ((), ()),
                anchor,
                last,
                user.nf_at(&note, last),
                user.nf_at(&note, last.next()),
            ),
        )
        .expect("EndEpochUnspentSeed");

    let range = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(1));
    let window = user.covering_window(&note, &range);
    // The builder would segment out of range, so the witness is assembled
    // by hand: the genuine elapsed and covering sequence, empty margins.
    let witness = (
        [user.nf_at(&note, last), user.nf_at(&note, last.next())]
            .into_iter()
            .collect::<NfSeqPoly>(),
        window.iter().copied().collect::<NfSeqPoly>(),
        NfMarginPoly::new(&[]),
        NfTailPoly::new(&[]),
    );

    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentBind, witness, unspent, range)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentBind: derivation does not cover the unspent end"
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

/// Expect `PROOF_SYSTEM.fuse` to fail with the given `InvalidWitness` text.
fn expect_invalid<H: ragu::Header, S>(
    rng: &mut StdRng,
    step: S,
    witness: S::Witness<'_>,
    left: Pcd<S::Left>,
    right: Pcd<S::Right>,
    message: &str,
) where
    S: ragu::Step<Output = H>,
{
    let err = PROOF_SYSTEM
        .fuse(rng, step, witness, left, right)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), message);
}

/// An honest master seed for a note.
fn honest_master(
    rng: &mut StdRng,
    user: &WalletSim,
    note: Note,
) -> Pcd<delegation::NfMasterHeader> {
    let (master, ()) = PROOF_SYSTEM
        .seed(
            rng,
            delegation::NfMasterSeed,
            witness::nf_master_seed(((), ()), note, user.pak),
        )
        .expect("NfMasterSeed");
    master
}

/// A note paired with an unrelated proof authorizing key fails the
/// payment-key pin before any master derivation.
#[test]
fn master_seed_rejects_unrelated_pak() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let stranger = WalletSim::random(rng);
    let note = user.random_note(500);

    expect_invalid(
        rng,
        delegation::NfMasterSeed,
        (note, stranger.pak),
        Proof::trivial().carry::<()>(()),
        Proof::trivial().carry::<()>(()),
        "NfMasterSeed: pak not related to note",
    );
}

/// A sequence built from a different note's nullifiers fails the accumulation
/// opening: `mk` is threaded off the seed header, so the step derives the
/// real note's nullifiers no matter what polynomial is offered.
#[test]
fn nf_derive_rejects_a_foreign_sequence() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note_a = user.random_note(500);
    let note_b = user.random_note(700);

    let master_a = honest_master(rng, &user, note_a);
    let (cm_a, _) = *master_a.data();
    let (group, foreign_seq) = witness::nf_derive(((cm_a, user.mk(&note_b)), ()), EpochGroup(4));
    expect_invalid(
        rng,
        delegation::NfDerive,
        (group, foreign_seq),
        master_a,
        Proof::trivial().carry::<()>(()),
        "NfDerive: sequence does not match the derived window",
    );
}

/// A direct [`delegation::NfDerive`] leaf over one whole window.
fn leaf_window(
    rng: &mut StdRng,
    user: &WalletSim,
    note: Note,
    group: EpochGroup,
) -> Pcd<delegation::NullifierDerivation> {
    let master = honest_master(rng, user, note);
    let (leaf, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NfDerive,
            witness::nf_derive((*master.data(), ()), group),
            master,
            Proof::trivial().carry::<()>(()),
        )
        .expect("NfDerive");
    leaf
}

/// The window's members, oldest first.
fn window_members(user: &WalletSim, note: &Note, group: EpochGroup) -> Vec<Nullifier> {
    (group.start_epoch().0..(group.start_epoch().0 + NF_DERIVATION_WIDTH as u32))
        .map(|epoch| user.nf_at(note, EpochIndex(epoch)))
        .collect()
}

/// A leaf exports its whole window, labelled with the window's bounds and its
/// genuine boundary members, and every window of the same note carries the
/// same `cm`.
#[test]
fn derivation_exports_the_whole_window() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let group = EpochGroup(3);
    let range = leaf_window(rng, &user, note, group);
    let (cm, (start, nf_start), commit, (range_end, nf_end)) = *range.data();

    assert_eq!(start, group.start_epoch(), "starts at the group's base");
    assert_eq!(
        range_end,
        EpochIndex(group.start_epoch().0 + NF_DERIVATION_WIDTH as u32),
        "spans the whole window"
    );
    let members = window_members(&user, &note, group);
    assert_eq!(
        nf_start,
        *members.first().expect("window is nonempty"),
        "genuine start member"
    );
    assert_eq!(
        nf_end,
        *members.last().expect("window is nonempty"),
        "genuine end member"
    );
    let seq = members.iter().copied().collect::<NfSeqPoly>();
    assert_eq!(commit, seq.commit(), "header commits the window sequence");

    let far = leaf_window(rng, &user, note, EpochGroup(25_000));
    assert_eq!(cm, far.data().0, "same note cm");
}

/// The fixture's covering derivation spans whole windows around the request
/// and commits the covering sequence.
#[test]
fn derivation_covers_with_whole_windows() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    // Spans two windows: the fixture fuses whole-window leaves internally.
    let start = EpochIndex(NF_DERIVATION_WIDTH as u32 - 2);
    let end = EpochIndex(NF_DERIVATION_WIDTH as u32 + 2);
    let range = user.derivation_pcd(rng, note, start, end);
    let (cm, (cover_start, nf_start), commit, (cover_end, nf_end)) = *range.data();

    assert_eq!(Tachygram::from(cm), note.commitment().into());
    assert!(
        cover_start.0 <= start.0 && end.0 <= cover_end.0,
        "covers the requested range"
    );
    assert_eq!(
        (cover_end.0 - cover_start.0) % NF_DERIVATION_WIDTH as u32,
        0,
        "whole windows"
    );
    assert_eq!(nf_start, user.nf_at(&note, cover_start));
    assert_eq!(nf_end, user.nf_at(&note, EpochIndex(cover_end.0 - 1)));
    let seq = (cover_start.0..cover_end.0)
        .map(|epoch| user.nf_at(&note, EpochIndex(epoch)))
        .collect::<NfSeqPoly>();
    assert_eq!(commit, seq.commit(), "merged commit is the concat sequence");
}

#[test]
fn nullifier_fuse_rejects_non_contiguous() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    // Windows separated by a gap: group 0 covers `[0, 16)`, group 8 starts at
    // 32, so the halves are not adjacent.
    let (left_group, right_group) = (EpochGroup(0), EpochGroup(8));
    let range_a = leaf_window(rng, &user, note, left_group);
    let range_b = leaf_window(rng, &user, note, right_group);
    let witness = witness::nullifier_fuse(
        (*range_a.data(), *range_b.data()),
        &window_members(&user, &note, left_group),
        &window_members(&user, &note, right_group),
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
    let note_b = user.random_note(700);

    let (left_group, right_group) = (EpochGroup(0), EpochGroup(4));
    let range_a = leaf_window(rng, &user, note_a, left_group);
    let range_b = leaf_window(rng, &user, note_b, right_group);
    let witness = witness::nullifier_fuse(
        (*range_a.data(), *range_b.data()),
        &window_members(&user, &note_a, left_group),
        &window_members(&user, &note_b, right_group),
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

/// An honest spendable and covering derivation for `SpendBind` witness
/// substitution tests, at the cm-block's epoch.
fn spend_bind_parts(
    rng: &mut StdRng,
    user: &WalletSim,
    note: &Note,
) -> (
    Pcd<spendable::SpendableHeader>,
    Pcd<delegation::NullifierDerivation>,
    EpochIndex,
) {
    let mut pool = PoolSim::genesis(rng);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let epoch = init_height.epoch();
    let spendable = user.spendable_init(rng, note, &pool, init_height);
    let derived = user.derivation_pcd(rng, *note, epoch, EpochIndex(epoch.0 + 2));
    (spendable, derived, epoch)
}

/// A forged next nullifier fails the covering read.
#[test]
fn spend_bind_rejects_forged_next() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let (spendable, derived, _epoch) = spend_bind_parts(rng, &user, &note);
    let (nf_seq, older, tail, _nf_next) = witness::spend_bind(
        (*spendable.data(), *derived.data()),
        &user.covering_window(&note, &derived),
    );
    let forged = Nullifier::from(Fp::random(&mut *rng));
    expect_invalid(
        rng,
        spend::SpendBind,
        (nf_seq, older, tail, forged),
        spendable,
        derived,
        "SpendBind: nullifier pair does not match the derivation",
    );
}

/// A range that does not cover the lineage epoch is rejected, however
/// internally consistent it is.
#[test]
fn spend_bind_rejects_uncovering_range() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let (spendable, _derived, epoch) = spend_bind_parts(rng, &user, &note);
    let ahead = EpochIndex(epoch.0 + NF_DERIVATION_WIDTH as u32);
    let derived_ahead = user.derivation_pcd(rng, note, ahead, EpochIndex(ahead.0 + 2));
    // The builder would segment out of range, so the witness is assembled
    // by hand: the genuine covering sequence, empty margins.
    let window = user.covering_window(&note, &derived_ahead);
    let witness = (
        window.iter().copied().collect::<NfSeqPoly>(),
        NfMarginPoly::new(&[]),
        NfTailPoly::new(&[]),
        user.nf_at(&note, epoch.next()),
    );
    expect_invalid(
        rng,
        spend::SpendBind,
        witness,
        spendable,
        derived_ahead,
        "SpendBind: derivation does not cover the lineage epoch",
    );
}

/// A different note's range does not match the lineage's `cm`.
#[test]
fn spend_bind_rejects_a_foreign_range() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let other = user.random_note(700);

    let (spendable, _derived, epoch) = spend_bind_parts(rng, &user, &note);
    let foreign = user.derivation_pcd(rng, other, epoch, EpochIndex(epoch.0 + 2));
    let witness = witness::spend_bind(
        (*spendable.data(), *foreign.data()),
        &user.covering_window(&other, &foreign),
    );
    expect_invalid(
        rng,
        spend::SpendBind,
        witness,
        spendable,
        foreign,
        "SpendBind: derived range does not match note",
    );
}

/// A sequence built from a different note does not match the derivation
/// header's commitment.
#[test]
fn spend_bind_rejects_a_foreign_sequence() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let other = user.random_note(700);

    let (spendable, derived, _epoch) = spend_bind_parts(rng, &user, &note);
    let witness = witness::spend_bind(
        (*spendable.data(), *derived.data()),
        &user.covering_window(&other, &derived),
    );
    expect_invalid(
        rng,
        spend::SpendBind,
        witness,
        spendable,
        derived,
        "SpendBind: covering sequence does not match header",
    );
}

/// A forged present nullifier fails the covering read at
/// `SpendableInit`.
#[test]
fn spendable_init_rejects_a_forged_nullifier() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let nf_header = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(1));
    let dummy_tg = Tachygram::random(&mut *rng);
    let (_, _, _, _, nf_seq, older, tail) = witness::spendable_init(
        (*nf_header.data(), ()),
        Anchor::default(),
        &[dummy_tg],
        EpochIndex(0),
        &user.covering_window(&note, &nf_header),
    );
    let forged = Nullifier::from(Fp::random(&mut *rng));
    expect_invalid(
        rng,
        spendable::SpendableInit,
        (
            Anchor::default(),
            TachygramSetPoly::from_iter([dummy_tg]),
            EpochIndex(0),
            forged,
            nf_seq,
            older,
            tail,
        ),
        nf_header,
        Proof::trivial().carry::<()>(()),
        "SpendableInit: nullifier does not match the derivation",
    );
}

/// A range that does not cover the creation epoch is rejected at
/// `SpendableInit`.
#[test]
fn spendable_init_rejects_an_uncovering_range() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let nf_header = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(1));
    let past = EpochIndex(NF_DERIVATION_WIDTH as u32);
    let dummy_tg = Tachygram::random(&mut *rng);
    // The builder would segment out of range, so the witness is assembled
    // by hand: the genuine covering sequence, the whole window as the tail.
    let window = user.covering_window(&note, &nf_header);
    let witness = (
        Anchor::default(),
        TachygramSetPoly::from_iter([dummy_tg]),
        past,
        user.nf_at(&note, past),
        window.iter().copied().collect::<NfSeqPoly>(),
        NfMarginPoly::new(&[]),
        NfTailPoly::new(&window),
    );
    expect_invalid(
        rng,
        spendable::SpendableInit,
        witness,
        nf_header,
        Proof::trivial().carry::<()>(()),
        "SpendableInit: derivation does not cover the creation epoch",
    );
}

/// A covering sequence built from a different note does not match the
/// derivation header's commitment at `UnspentBind`.
#[test]
fn unspent_bind_rejects_a_foreign_sequence() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let other = user.random_note(700);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let unspent = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(0))],
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    let range = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(1));
    let witness = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&other, &range),
        &[user.nf_at(&note, EpochIndex(0))],
    );
    expect_invalid(
        rng,
        pool::UnspentBind,
        witness,
        unspent,
        range,
        "UnspentBind: covering sequence does not match header",
    );
}

/// A span exceeding one window chunks through sequential bind+lift rounds,
/// each bound against its own single window based at its chunk's start.
#[test]
fn multi_chunk_lift_uses_per_chunk_windows() {
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
            user.nf_at(&note, EpochIndex(1)),
            user.nf_at(&note, EpochIndex(2)),
        ],
        init_height,
        start_anchor,
    );

    // First chunk: epochs 0 to 1, bound against the window based at epoch 0.
    let target_one = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_one {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent_one = sync.build_next_unspent(rng, 0, &pool, target_one);
    let lifted_one = user.lift(
        rng,
        spendable,
        unspent_one,
        &note,
        EpochIndex(0),
        EpochIndex(1),
    );
    assert_eq!(
        lifted_one.data().1,
        (EpochIndex(1), user.nf_at(&note, EpochIndex(1)))
    );

    // Second chunk: epochs 1 to 2, bound against a fresh window based at
    // epoch 1 (the chunk boundary needs no alignment between windows).
    let target_two = BlockHeight(2 * EPOCH_SIZE);
    while pool.height() < target_two {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent_two = sync.build_next_unspent(rng, 0, &pool, target_two);
    let lifted_two = user.lift(
        rng,
        lifted_one,
        unspent_two,
        &note,
        EpochIndex(1),
        EpochIndex(2),
    );

    assert_eq!(
        lifted_two.data().1,
        (EpochIndex(2), user.nf_at(&note, EpochIndex(2))),
        "tip advanced across two chunks"
    );
    assert_eq!(
        lifted_two.data().2,
        pool.anchor_at(target_two),
        "anchor advanced across two chunks"
    );
    assert_eq!(lifted_two.data().0, note.commitment(), "cm threaded");
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

/// Adjacent ranges fuse into one: the merged sequence is the bare Horner
/// concatenation, with the endpoints threaded from the halves.
#[test]
fn nullifier_fuse_composes() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let left = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(16));
    let right = user.derivation_pcd(rng, note, EpochIndex(16), EpochIndex(32));
    let left_nfs: Vec<Nullifier> = (0..16)
        .map(|epoch| user.nf_at(&note, EpochIndex(epoch)))
        .collect();
    let right_nfs: Vec<Nullifier> = (16..32)
        .map(|epoch| user.nf_at(&note, EpochIndex(epoch)))
        .collect();
    let fuse_witness =
        witness::nullifier_fuse((*left.data(), *right.data()), &left_nfs, &right_nfs);
    let (merged, ()) = PROOF_SYSTEM
        .fuse(rng, delegation::NullifierFuse, fuse_witness, left, right)
        .expect("NullifierFuse");

    let (cm, (start, nf_start), commit, (end, nf_last)) = *merged.data();
    assert_eq!(cm, note.commitment());
    assert_eq!((start, end), (EpochIndex(0), EpochIndex(32)));
    assert_eq!(nf_start, user.nf_at(&note, EpochIndex(0)));
    assert_eq!(nf_last, user.nf_at(&note, EpochIndex(31)));
    let expected: NfSeqPoly = (0..32)
        .map(|epoch| user.nf_at(&note, EpochIndex(epoch)))
        .collect();
    assert_eq!(
        commit,
        expected.commit(),
        "merged commits the concatenation"
    );
}

/// A merged polynomial that is not the concatenation fails the shifted
/// combination.
#[test]
fn nullifier_fuse_rejects_a_wrong_merged() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let left = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(16));
    let right = user.derivation_pcd(rng, note, EpochIndex(16), EpochIndex(32));
    let left_nfs: Vec<Nullifier> = (0..16)
        .map(|epoch| user.nf_at(&note, EpochIndex(epoch)))
        .collect();
    let right_nfs: Vec<Nullifier> = (16..32)
        .map(|epoch| user.nf_at(&note, EpochIndex(epoch)))
        .collect();
    let (left_seq, _merged, right_seq) =
        witness::nullifier_fuse((*left.data(), *right.data()), &left_nfs, &right_nfs);
    let wrong: NfSeqPoly = iter::repeat_with(|| Nullifier::from(Fp::random(&mut *rng)))
        .take(32)
        .collect();
    expect_invalid(
        rng,
        delegation::NullifierFuse,
        (left_seq, wrong, right_seq),
        left,
        right,
        "NullifierFuse: merged is not the concat of the halves",
    );
}

/// A forged next-epoch nullifier cannot be compensated by choosing the
/// margins: both bands are disjoint from the read's, so no margin content
/// moves the read's coefficients.
///
/// The derivation starts below the pair's epoch so that *both* margins carry
/// members. `spend_bind_parts` mints at genesis, which leaves the older margin
/// empty and reduces this to `spend_bind_rejects_forged_next` with a garbled
/// tail.
#[test]
fn spend_bind_rejects_a_forged_next_over_garbage_margins() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);

    // Mint into a later epoch, so the window can start below the pair.
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let note = user.random_note(500);
    let stranger = user.random_note(900);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let epoch = init_height.epoch();
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let derived = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(epoch.0 + 2));

    let (nf_seq, _older, _tail, _nf_next) = witness::spend_bind(
        (*spendable.data(), *derived.data()),
        &user.covering_window(&note, &derived),
    );

    // Garbage margins: another note's members in place of this note's.
    let (_, (deriv_start, _), _, (deriv_end, _)) = *derived.data();
    let stranger_mk = user.mk(&stranger);
    let older_members: Vec<Nullifier> = (deriv_start.0..epoch.0)
        .map(|epoch_idx| stranger_mk.derive_nullifier(EpochIndex(epoch_idx)))
        .collect();
    let tail_members: Vec<Nullifier> = (epoch.0 + 2..deriv_end.0)
        .map(|epoch_idx| stranger_mk.derive_nullifier(EpochIndex(epoch_idx)))
        .collect();
    assert!(!older_members.is_empty(), "older margin must carry members");
    assert!(!tail_members.is_empty(), "newer margin must carry members");
    let older = NfMarginPoly::new(&older_members);
    let tail = NfTailPoly::new(&tail_members);

    let forged = Nullifier::from(Fp::random(&mut *rng));
    expect_invalid(
        rng,
        spend::SpendBind,
        (nf_seq, older, tail, forged),
        spendable,
        derived,
        "SpendBind: nullifier pair does not match the derivation",
    );
}

/// A segment beginning past the spendable's position does not lift it: its
/// first member is not the lineage nullifier.
#[test]
fn spendable_lift_rejects_a_wrong_start() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, init_height);

    // A segment covering only epoch 1, one epoch past the spendable.
    while pool.height().0 < EPOCH_SIZE {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let epoch1_height = pool.height();
    let arbitrary = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(1))],
        epoch1_height..=epoch1_height,
    );
    let unspent = user.unspent_bind(rng, arbitrary, &note, EpochIndex(1), EpochIndex(1));

    expect_invalid(
        rng,
        spendable::SpendableLift,
        (),
        spendable,
        unspent,
        "SpendableLift: segment does not start at the lineage nullifier",
    );
}

/// The per-stamp walk from an epoch's terminal anchor opens *on* that anchor:
/// the boundary is a segment of its own, so the walk seeds the crossing and
/// the span starts in the outgoing epoch rather than past it. A spendable
/// resting on the terminal anchor is therefore adjacent to what it lifts over.
#[test]
fn unspent_walk_from_an_epoch_tip_opens_on_the_tip() {
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

    let arbitrary = build_unspent_pcd_between_anchors(
        rng,
        &pool,
        &[
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1)),
        ],
        (epoch0_tip, pool.anchor_at(target_height)),
    );
    let unspent = user.unspent_bind(rng, arbitrary, &note, EpochIndex(0), EpochIndex(1));

    assert_eq!(
        unspent.data().1,
        epoch0_tip,
        "the segment opens on the spendable's own anchor, not past it"
    );
    assert_eq!(
        unspent.data().2,
        (EpochIndex(0), user.nf_at(&note, EpochIndex(0))),
        "the span begins in the epoch being left"
    );
    assert_eq!(
        unspent.data().3,
        (EpochIndex(1), user.nf_at(&note, EpochIndex(1)))
    );
    assert_eq!(unspent.data().4, pool.anchor_at(target_height));
}

/// The terminal-anchor composition end to end: a note whose cm-stamp closes
/// its epoch lifts over a crossing seed, then binds and spends in the next
/// epoch.
#[test]
fn crossing_seed_carries_a_terminal_anchor_to_a_spend() {
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

    // The tick's bookkeeping: epoch and nullifier advance by one, and the
    // anchor folds the domain-separated boundary in the crossing segment.
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
    let lifted = user.lift(
        rng,
        spendable,
        crossing,
        &note,
        EpochIndex(0),
        EpochIndex(1),
    );
    assert_eq!(
        *lifted.data(),
        (
            note.commitment(),
            (EpochIndex(1), user.nf_at(&note, EpochIndex(1))),
            epoch0_tip.next_epoch(EpochIndex(1)),
        ),
        "the lift crosses to the boundary anchor"
    );

    // Walk through epoch 1 from the boundary anchor the lift landed on.
    pool.advance(1, |_| random_block(rng, 1, 2));
    let end_height = pool.height();
    assert_eq!(end_height.epoch(), EpochIndex(1));
    let arbitrary = build_unspent_pcd_between_anchors(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(1))],
        (lifted.data().2, pool.anchor_at(end_height)),
    );
    let walked = user.lift(rng, lifted, arbitrary, &note, EpochIndex(1), EpochIndex(1));
    let bind_pcd = honest_spend_bind(rng, &user, &note, walked, EpochIndex(1));
    let stamp = honest_spend_stamp(rng, &user, &note, bind_pcd);

    let expected = TachygramSetPoly::from_iter([
        user.nf_at(&note, EpochIndex(1)).into(),
        user.nf_at(&note, EpochIndex(2)).into(),
    ])
    .commit();
    assert_eq!(stamp.data().1, expected, "publishes {{N_1, N_2}}");
}

/// A `tail` carrying weight in its forced-zero band (below the cap shift)
/// breaks the lifted identity: the margin cannot smuggle content anywhere
/// but its own band.
#[test]
fn unspent_bind_rejects_a_tail_below_its_band() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let unspent = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(0))],
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    let range = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(1));
    let (elapsed_seq, nf_seq, older, _tail) = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &[user.nf_at(&note, EpochIndex(0))],
    );
    // The honest tail plus a stray coefficient in the forced-zero band.
    let cap = 1usize << ragu::Polynomial::R;
    let mut coeffs = alloc::vec![Fp::ZERO; cap];
    coeffs[0] = Fp::ONE;
    coeffs[7] = Fp::random(&mut *rng);
    let below_band = NfTailPoly::from(ragu::Polynomial::from_coeffs(coeffs));
    expect_invalid(
        rng,
        pool::UnspentBind,
        (elapsed_seq, nf_seq, older, below_band),
        unspent,
        range,
        "UnspentBind: sequence does not match the derivation",
    );
}

/// An `older` margin whose sentinel slot is not exactly 1 breaks the
/// identity: the slot is forced, not conventional.
#[test]
fn unspent_bind_rejects_a_forged_sentinel() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let unspent = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(0))],
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    let range = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(1));
    let (elapsed_seq, nf_seq, _older, tail) = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &[user.nf_at(&note, EpochIndex(0))],
    );
    // The read's older margin is empty here, so the honest witness is the
    // constant 1; a doubled sentinel breaks the compensated identity.
    let forged_sentinel =
        NfMarginPoly::from(ragu::Polynomial::from_coeffs(alloc::vec![Fp::from(2u64)]));
    expect_invalid(
        rng,
        pool::UnspentBind,
        (elapsed_seq, nf_seq, forged_sentinel, tail),
        unspent,
        range,
        "UnspentBind: sequence does not match the derivation",
    );
}

/// A sentinel-less empty margin is the zero polynomial, which commits to the
/// identity point; witnessing rejects it. This is the path that makes the
/// sentinel necessary.
#[test]
fn sentinel_less_empty_margin_cannot_be_witnessed() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let unspent = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(0))],
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    let range = user.derivation_pcd(rng, note, EpochIndex(0), EpochIndex(1));
    let (elapsed_seq, nf_seq, _older, tail) = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.covering_window(&note, &range),
        &[user.nf_at(&note, EpochIndex(0))],
    );
    let zero_margin = NfMarginPoly::from(ragu::Polynomial::from_coeffs(alloc::vec![Fp::ZERO]));
    let result = PROOF_SYSTEM.fuse(
        rng,
        pool::UnspentBind,
        (elapsed_seq, nf_seq, zero_margin, tail),
        unspent,
        range,
    );
    assert!(
        result.is_err(),
        "an identity-commitment margin must not witness"
    );
}

/// A span exceeding one window binds once, against a fused chain of cached
/// whole windows; no bind-per-window rounds and no partial leaves.
#[test]
fn multi_window_span_binds_once() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;

    // Publish one block per epoch (each epoch's first block) through epoch
    // NF_DERIVATION_WIDTH, so the lineage spans one epoch more than a single
    // window covers and the span's end anchor is a stamped block's.
    let last_epoch = NF_DERIVATION_WIDTH as u32;
    let target_height = BlockHeight(last_epoch * EPOCH_SIZE);
    while pool.height() < target_height {
        let publish = pool.height().0 % EPOCH_SIZE == EPOCH_SIZE - 1;
        if publish {
            pool.advance(1, |_| random_block(rng, 1, 2));
        } else {
            pool.advance(1, |_| Vec::new());
        }
    }

    let nfs: Vec<Nullifier> = (0..=last_epoch)
        .map(|epoch| user.nf_at(&note, EpochIndex(epoch)))
        .collect();
    let arbitrary = build_unspent_pcd_between_anchors(
        rng,
        &pool,
        &nfs,
        (start_anchor, pool.anchor_at(target_height)),
    );
    let unspent = user.unspent_bind(rng, arbitrary, &note, EpochIndex(0), EpochIndex(last_epoch));

    assert_eq!(
        unspent.data().3,
        (
            EpochIndex(last_epoch),
            user.nf_at(&note, EpochIndex(last_epoch))
        ),
        "one bind carries the whole multi-window span"
    );
}

/// One covering derivation serves init, epoch bookkeeping, and spend: the
/// fixture's memoized covering window is the same PCD at every consumer, and
/// the whole spend flow closes against it.
#[test]
fn one_window_serves_init_bind_and_spend() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let epoch = init_height.epoch();

    let window = user.derivation_pcd(rng, note, epoch, EpochIndex(epoch.0 + 2));
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let again = user.derivation_pcd(rng, note, epoch, epoch.next());
    assert_eq!(
        again.data(),
        window.data(),
        "the memoized covering window is one PCD for every request inside it"
    );

    let bind_pcd = honest_spend_bind(rng, &user, &note, spendable, epoch);
    assert_eq!(bind_pcd.data().1, user.nf_at(&note, epoch));
    assert_eq!(bind_pcd.data().2, user.nf_at(&note, epoch.next()));
}
