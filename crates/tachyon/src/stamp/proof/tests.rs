//! Proof-step tests: `StampLift`, `SpendBind` / `SpendStamp`, the flat
//! nullifier-derivation chain, `Unspent` composition, and the `Spendable*`
//! lineage.

#![allow(
    clippy::panic,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "test code"
)]

extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::array;

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Pcd, Proof};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::{CryptoRng, RngCore};

use super::{PROOF_SYSTEM, delegation, pool, spend, spendable, stamp};
use crate::{
    ActionSetPoly, NfSeqPoly, Note, TachygramSetPoly,
    constants::{EPOCH_MAX, EPOCH_SIZE, NF_DERIVATION_WIDTH},
    entropy::ActionEntropy,
    fixtures::{
        PoolSim, SyncSim, WalletSim, build_anchor_chain_pcd, build_output_stamp,
        build_unspent_pcd_between_anchors, build_unspent_pcd_between_blocks,
        build_unspent_seed_pcd, random_block, random_block_with, shared_sk, spend_witness,
        spendable_init_inputs,
    },
    note,
    nullifier::{
        self, NfTraceGrid, Nullifier,
        derivation::{NF_COSET_SHIFT, NF_EPOCH_STEP},
    },
    primitives::{Anchor, BlockHeight, EpochIndex, Tachygram, effect},
    value, witness,
};

fn tg<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Tachygram {
    Tachygram::from(Fp::random(rng))
}

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
    let derived = user.derivation_pcd(rng, *note, spend_epoch);
    let witness = witness::spend_bind(
        (*spendable.data(), *derived.data()),
        spend_epoch,
        &user.mk(note),
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
fn same_epoch_wrong_index_rejected_against_honest_chain() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let cm_height = mine_cm_in_epoch_one(rng, &mut pool, note.commitment());
    let wrong = EpochIndex(cm_height.epoch().0 + 2);

    let (pre_epoch_anchor, pre_cm_anchor, creation_set, chain) =
        spendable_init_inputs(rng, &pool, note.commitment(), cm_height);
    let nf_wrong = user.derivation_pcd(rng, note, wrong);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            witness::spendable_init(
                (*chain.data(), *nf_wrong.data()),
                pre_epoch_anchor,
                pre_cm_anchor,
                &creation_set,
                wrong,
                &user.mk(&note),
            ),
            chain,
            nf_wrong,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendableInit: chain not rooted at epoch boundary"
    );
}

#[test]
fn spendable_init_accepts_forged_chain() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let cm = note.commitment();
    let cm_height = mine_cm_in_epoch_one(rng, &mut pool, cm);
    let wrong = EpochIndex(cm_height.epoch().0 + 2);

    // Forge a boundary at the wrong epoch: `pre_epoch_anchor = x` (arbitrary), a
    // chain seeded at `forged_start = x.next_epoch(wrong)` absorbing the real
    // cm-stamp, and `pre_cm_anchor = forged_start` so `chain_end ==
    // pre_cm_anchor.next_stamp(cm_commit)`. All SpendableInit checks then pass.
    let stamps = pool.tachygrams_at(cm_height);
    let cm_idx = stamps
        .iter()
        .position(|tgs| tgs.contains(&cm.into()))
        .expect("cm present in cm-block");
    let x = Anchor::from(Fp::random(&mut *rng));
    let forged_start = x.next_epoch(wrong);
    let cm_set = TachygramSetPoly::from_iter(stamps[cm_idx].clone());
    let cm_commit = cm_set.commit();
    let (forged_chain, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::AnchorSeed,
            witness::anchor_seed(((), ()), forged_start, &stamps[cm_idx]),
        )
        .expect("AnchorSeed");

    let nf_wrong = user.derivation_pcd(rng, note, wrong);
    let (forged_spendable, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            witness::spendable_init(
                (*forged_chain.data(), *nf_wrong.data()),
                x,
                forged_start,
                &stamps[cm_idx],
                wrong,
                &user.mk(&note),
            ),
            forged_chain,
            nf_wrong,
        )
        .expect("SpendableInit accepts the forged wrong-index chain");

    // The circuit accepted, but the produced anchor is off the published sequence,
    // so consensus anchor membership is what rejects the eventual spend.
    let forged_anchor = forged_spendable.data().2;
    assert_eq!(forged_anchor, forged_start.next_stamp(&cm_commit));
    let forged_off_sequence =
        (0..=cm_height.0).all(|height| pool.anchor_at(BlockHeight(height)) != forged_anchor);
    assert!(
        forged_off_sequence,
        "forged wrong-index anchor must be absent from the published sequence"
    );
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

    pool.advance(usize::try_from(EPOCH_SIZE - 2).expect("fits"), |_| {
        random_block(rng, 1, 4)
    });
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

    let nf_header = user.derivation_pcd(rng, note, EpochIndex(0));
    let absent_tg = tg(rng);
    // cm-inclusion is checked before the chain rooting, so a dummy boundary
    // chain suffices here.
    let dummy_tg = tg(rng);
    let (dummy_chain, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::AnchorSeed,
            witness::anchor_seed(((), ()), Anchor::default(), &[dummy_tg]),
        )
        .expect("AnchorSeed");

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            witness::spendable_init(
                (*dummy_chain.data(), *nf_header.data()),
                Anchor::default(),
                Anchor::default(),
                &[absent_tg],
                EpochIndex(0),
                &user.mk(&note),
            ),
            dummy_chain,
            nf_header,
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
    let stamps_left = vec![tg(rng)];
    let stamps_right = vec![tg(rng)];
    let start = Anchor::default();
    let mid = start.next_stamp(&TachygramSetPoly::from_iter(stamps_left.clone()).commit());

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
                witness::anchor_seed(((), ()), bogus_start, &stamps[0]),
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
        pool.advance(usize::try_from(EPOCH_SIZE + 1).expect("fits"), |_| {
            random_block(rng, 1, 2)
        });

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
fn empty_block_anchor_unique_per_height() {
    // Two consecutive empty blocks publish distinct anchors.
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.mine(vec![]);
    pool.mine(vec![]);

    let h1 = BlockHeight(1);
    let h2 = BlockHeight(2);
    assert_ne!(pool.anchor_at(h1), pool.anchor_at(h2));
    // h2's anchor is h1's anchor advanced via next_empty.
    assert_eq!(pool.anchor_at(h2), pool.anchor_at(h1).next_empty());
}

#[test]
fn empty_block_unspent_lifts_spendable() {
    // Build a spendable, then lift it across an empty block via an
    // Unspent built solely from EmptyBlockUnspentSeed.
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(100);
    let cm = note.commitment();

    let mut pool = PoolSim::genesis(rng);
    pool.mine(vec![vec![cm.into()]]);
    let cm_height = pool.height();
    let epoch = cm_height.epoch();

    // Bootstrap spendable at the cm-block's published anchor.
    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let spendable_anchor_before = spendable.data().2;

    // Mine one empty block.
    pool.mine(vec![]);
    let empty_height = pool.height();

    // Build an Unspent over the empty block via EmptyBlockUnspentSeed,
    // then lift the spendable.
    let nf = spendable.data().1;
    let unspent = build_unspent_pcd_between_blocks(rng, &pool, &[nf], empty_height..=empty_height);
    let lifted = user.lift(rng, spendable, unspent, &note, epoch, epoch);

    assert_eq!(lifted.data().2, spendable_anchor_before.next_empty());
    assert_eq!(lifted.data().2, pool.anchor_at(empty_height));
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

#[test]
fn step_rejects_zero_value_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());

    let zero_note = Note {
        pk: user.pak.derive_payment_key(),
        value: value::Positive::new_unchecked(0),
        psi: nullifier::Trapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    };

    {
        let out_rcv = value::Trapdoor::random(rng);
        let out_theta = ActionEntropy::random(rng);
        let out_alpha = out_theta.randomizer::<effect::Output>(zero_note.commitment());
        let out_anchor = PoolSim::genesis(rng).anchor();
        let err = PROOF_SYSTEM
            .seed(
                rng,
                stamp::OutputStamp,
                (out_rcv, out_alpha, zero_note, out_anchor),
            )
            .err()
            .unwrap();
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(inner.to_string(), "OutputStamp: zero-value note");
    }

    {
        let mut pool = PoolSim::genesis(rng);
        let note = user.random_note(500);
        pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
        let height = pool.height();
        let spend_epoch = height.epoch();
        let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
        let bind_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd, spend_epoch);

        let (rcv, _theta, alpha) = spend_witness(rng, &note);

        let err = PROOF_SYSTEM
            .fuse(
                rng,
                stamp::SpendStamp,
                (
                    Note {
                        value: value::Positive::new_unchecked(0),
                        ..note
                    },
                    rcv,
                    alpha,
                    user.pak,
                ),
                bind_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .err()
            .unwrap();
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(inner.to_string(), "SpendStamp: zero-value note");
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
        user.nf_at(&note, EpochIndex(1)),
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
    // therefore mixes mid-epoch `UnspentFuse` (incl. multi-epoch right at upper
    // merges) with boundary `UnspentEpochFuse`. One interior empty block seeds
    // `EmptyBlockUnspentSeed` into the same walk.
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
        user.nf_at(&note, EpochIndex(3)),
        "tip advanced to nf_3 across partial first/last and whole interior epochs"
    );
    assert_eq!(
        lifted.data().2,
        pool.anchor_at(target_height),
        "anchor advanced to the mid-epoch-3 target"
    );
    assert_eq!(lifted.data().0, note.commitment(), "cm threaded unchanged");
}

/// Two [`pool::Unspent`] halves meeting at a sub-block, mid-epoch junction.
/// Every anchor involved is off-boundary: the range runs from inside a block
/// of epoch 0, through a junction inside a block of epoch 2, to inside a
/// block of epoch 3 (every `random_block(rng, 1, 2)` block carries two
/// stamps, so its first stamp's anchor is sub-block). The left half carries
/// two crossings (the fuse runs at offset 2), the right half one.
fn multi_epoch_fuse_setup(
    rng: &mut StdRng,
) -> (
    Nullifier,
    Nullifier,
    Nullifier,
    Nullifier,
    Pcd<pool::Unspent>,
    Pcd<pool::Unspent>,
) {
    let mut pool = PoolSim::genesis(rng);
    pool.advance(usize::try_from(3 * EPOCH_SIZE + 3).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });
    let nf0 = Nullifier::from(Fp::random(&mut *rng));
    let nf1 = Nullifier::from(Fp::random(&mut *rng));
    let nf2 = Nullifier::from(Fp::random(&mut *rng));
    let nf3 = Nullifier::from(Fp::random(&mut *rng));
    let start_height = BlockHeight(2);
    let junction_height = BlockHeight(2 * EPOCH_SIZE + 2);
    let end_height = BlockHeight(3 * EPOCH_SIZE + 2);
    let start = pool
        .prev_anchor_at(start_height)
        .next_stamp(&pool.stamp_commits_at(start_height)[0]);
    let junction = pool
        .prev_anchor_at(junction_height)
        .next_stamp(&pool.stamp_commits_at(junction_height)[0]);
    let end = pool
        .prev_anchor_at(end_height)
        .next_stamp(&pool.stamp_commits_at(end_height)[0]);
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
    pool.advance(usize::try_from(EPOCH_SIZE + 1).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });

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
    // boundary the fuse refuses to cross: that is `UnspentEpochFuse`'s job.
    let stamp = [tg(rng)];
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

/// Two [`pool::Unspent`] halves meeting at the epoch 2/3 boundary, together
/// crossing four boundaries. The junction is boundary-pinned by the step's
/// design, but both outer endpoints are off-boundary, sub-block anchors: the
/// left half runs from inside a block of epoch 0 to epoch 2's terminal
/// anchor, the right half from the boundary to inside a block of epoch 4.
fn epoch_fuse_setup(rng: &mut StdRng) -> ([Nullifier; 5], Pcd<pool::Unspent>, Pcd<pool::Unspent>) {
    let mut pool = PoolSim::genesis(rng);
    pool.advance(usize::try_from(4 * EPOCH_SIZE + 3).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });
    let nf: [Nullifier; 5] = array::from_fn(|_| Nullifier::from(Fp::random(&mut *rng)));
    let start_height = BlockHeight(2);
    let end_height = BlockHeight(4 * EPOCH_SIZE + 2);
    let start = pool
        .prev_anchor_at(start_height)
        .next_stamp(&pool.stamp_commits_at(start_height)[0]);
    let end = pool
        .prev_anchor_at(end_height)
        .next_stamp(&pool.stamp_commits_at(end_height)[0]);
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

#[test]
fn unspent_epoch_fuse_composes() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, nf2, nf3, nf4], left, right) = epoch_fuse_setup(rng);
    let start = left.data().0;
    let end = right.data().4;

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            witness::unspent_epoch_fuse((*left.data(), *right.data()), &[nf0, nf1], &[nf3]),
            left,
            right,
        )
        .expect("UnspentEpochFuse boundary splice");

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
        "the boundary fold splices left's tip between the halves' histories"
    );
}

#[test]
fn unspent_epoch_fuse_rejects_wrong_left_seq() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, nf2, nf3, _nf4], left, right) = epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (
                NfSeqPoly::from_iter([nf1, nf0]),
                NfSeqPoly::from_iter([nf0, nf1, nf2, nf3]),
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
        "UnspentEpochFuse: left polynomial does not match header"
    );
}

#[test]
fn unspent_epoch_fuse_rejects_wrong_right_seq() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, nf2, nf3, nf4], left, right) = epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (
                NfSeqPoly::from_iter([nf0, nf1]),
                NfSeqPoly::from_iter([nf0, nf1, nf2, nf3]),
                NfSeqPoly::from_iter([nf4]),
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
        "UnspentEpochFuse: right polynomial does not match header"
    );
}

#[test]
fn unspent_epoch_fuse_rejects_wrong_combined() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, _nf2, nf3, _nf4], left, right) = epoch_fuse_setup(rng);
    // Both halves honest; `combined` forged as the right half alone, dropping
    // the left history and the boundary fold.
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (
                NfSeqPoly::from_iter([nf0, nf1]),
                NfSeqPoly::from_iter([nf3]),
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
        "UnspentEpochFuse: combined is not the splice of the halves"
    );
}

#[test]
fn unspent_epoch_fuse_rejects_wrong_boundary_anchor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let ([nf0, nf1, _nf2, nf3, _nf4], left, _right) = epoch_fuse_setup(rng);
    let left_end = left.data().4;
    // A forged epoch-3 right half rooted directly at `left.anchor_last`: the
    // epoch labels are adjacent, but the root skips the `next_epoch` fold the
    // boundary demands.
    let stamp = [tg(rng)];
    let forged_right = build_unspent_seed_pcd(rng, left_end, EpochIndex(3), &stamp, nf3);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            witness::unspent_epoch_fuse((*left.data(), *forged_right.data()), &[nf0, nf1], &[]),
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
        "UnspentEpochFuse: boundary anchor does not match right.anchor_prev"
    );
}

#[test]
fn unspent_epoch_fuse_rejects_epoch_skip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.advance(usize::try_from(2 * EPOCH_SIZE).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });
    let nf_e0 = Nullifier::from(Fp::random(&mut *rng));
    let nf_e2 = Nullifier::from(Fp::random(&mut *rng));
    let left = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[nf_e0],
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let right = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[nf_e2],
        BlockHeight(2 * EPOCH_SIZE)..=BlockHeight(2 * EPOCH_SIZE),
    );
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            witness::unspent_epoch_fuse((*left.data(), *right.data()), &[], &[]),
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
        "UnspentEpochFuse: right epoch must be one past left's tip"
    );
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

    // The witnessed sequences are the genuine derived values; the unspent
    // header carries the forged tip, so the discharge's tip monomial
    // mismatches the telescoped nullifier at that offset.
    let range = user.derivation_pcd(rng, note, EpochIndex(0));
    let witness = witness::unspent_bind(
        (*unspent.data(), *range.data()),
        &user.mk(&note),
        &[user.nf_at(&note, EpochIndex(0))],
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
        "UnspentBind: sub-sequence does not match the derivation"
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
    let range = user.derivation_pcd(rng, note, EpochIndex(0));
    let (_honest_elapsed_seq, nf_spectrum, accumulator) =
        witness::unspent_bind((*unspent.data(), *range.data()), &user.mk(&note), &[]);
    let bogus_elapsed = NfSeqPoly::from_iter([Nullifier::from(Fp::random(&mut *rng))]);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentBind,
            (bogus_elapsed, nf_spectrum, accumulator),
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
    // later window) cannot cover it: the coverage offset underflows.
    let range = user.derivation_pcd(rng, note, EpochIndex(64));
    let witness = witness::unspent_bind((*unspent.data(), *range.data()), &user.mk(&note), &[]);

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
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    let verified = user.unspent_bind(rng, unspent, &phantom, EpochIndex(0), EpochIndex(1));

    let err = PROOF_SYSTEM
        .fuse(rng, spendable::SpendableLift, (), spendable, verified)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendableLift: verified unspent cm does not match spendable"
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
    let unspent = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(0))],
        init_height..=init_height,
    );
    let verified = user.unspent_bind(rng, unspent, &note, EpochIndex(0), EpochIndex(0));

    let err = PROOF_SYSTEM
        .fuse(rng, spendable::SpendableLift, (), spendable, verified)
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

/// An honest [`Sbox`](delegation::Sbox) cert for one window.
fn honest_sbox(
    rng: &mut StdRng,
    user: &WalletSim,
    note: &Note,
    base: EpochIndex,
) -> Pcd<delegation::Sbox> {
    let (sbox, ()) = PROOF_SYSTEM
        .seed(
            rng,
            delegation::SboxStep,
            witness::sbox_boundary(((), ()), &user.mk(note), base),
        )
        .expect("SboxStep");
    sbox
}

#[test]
fn sbox_boundary_rejects_wrong_base() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    // An honest base-100 trace certified as base 200: the boundary term pins
    // the first column to base 200's input window, which the trace does not
    // carry.
    let (trace, square, quartic, quotient, mk, _base) =
        witness::sbox_boundary(((), ()), &user.mk(&note), EpochIndex(100));
    expect_invalid(
        rng,
        delegation::SboxStep,
        (trace, square, quartic, quotient, mk, EpochIndex(200)),
        Proof::trivial().carry::<()>(()),
        Proof::trivial().carry::<()>(()),
        "Sbox: sbox/boundary identity fails at challenge",
    );
}

#[test]
fn sbox_boundary_rejects_base_out_of_range() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let (trace, square, quartic, quotient, mk, _base) =
        witness::sbox_boundary(((), ()), &user.mk(&note), EpochIndex(0));
    expect_invalid(
        rng,
        delegation::SboxStep,
        (trace, square, quartic, quotient, mk, EpochIndex(EPOCH_MAX)),
        Proof::trivial().carry::<()>(()),
        Proof::trivial().carry::<()>(()),
        "Sbox: base exceeds epoch space",
    );
}

/// A foreign window's trace (self-consistent for its own base) does not match
/// the cert's trace commitment, so the stitch rejects it.
#[test]
fn wrap_rejects_foreign_trace() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let mk = user.mk(&note);

    let sbox = honest_sbox(rng, &user, &note, EpochIndex(0));
    let (_trace, quartic, wrap, quotient, note_w, pak) =
        witness::recurrence((*sbox.data(), ()), note, user.pak);
    let foreign_trace = NfTraceGrid::derive(&mk, EpochIndex(10)).spectrum();
    expect_invalid(
        rng,
        delegation::WrapStep,
        (foreign_trace, quartic, wrap, quotient, note_w, pak),
        sbox,
        Proof::trivial().carry::<()>(()),
        "Wrap: trace does not match the cert",
    );
}

/// A cert whose free-witness `mk` belongs to a different note fails the
/// master pin: the derived `mk` disagrees with the cert's round key. This is
/// the guard against a crafted trace certified under a lying key.
#[test]
fn wrap_rejects_foreign_note_master() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note_a = user.random_note(500);
    let note_b = user.random_note(700);

    let sbox_a = honest_sbox(rng, &user, &note_a, EpochIndex(0));
    let witness = witness::recurrence((*sbox_a.data(), ()), note_b, user.pak);
    expect_invalid(
        rng,
        delegation::WrapStep,
        witness,
        sbox_a,
        Proof::trivial().carry::<()>(()),
        "Wrap: round key does not match the note",
    );
}

/// A note paired with an unrelated proof authorizing key fails the
/// payment-key pin before any master derivation.
#[test]
fn wrap_rejects_unrelated_pak() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let stranger = WalletSim::random(rng);
    let note = user.random_note(500);

    let sbox = honest_sbox(rng, &user, &note, EpochIndex(0));
    let witness = witness::recurrence((*sbox.data(), ()), note, stranger.pak);
    expect_invalid(
        rng,
        delegation::WrapStep,
        witness,
        sbox,
        Proof::trivial().carry::<()>(()),
        "Wrap: pak not related to note",
    );
}

/// Two independent, non-adjacent windows derive directly from the note's
/// master key, with no shared intermediate state between them (unlike a tree,
/// where sibling windows would share a common node path).
#[test]
fn independent_windows_derive_directly() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let near = user.derivation_pcd(rng, note, EpochIndex(0));
    let far = user.derivation_pcd(rng, note, EpochIndex(100_000));

    assert_eq!(near.data().1, EpochIndex(0));
    assert_eq!(far.data().1, EpochIndex(100_000));
    assert_eq!(near.data().0, far.data().0, "same note cm");
}

/// A derivation's window need not land on any global alignment grid: it
/// starts exactly at the request.
#[test]
fn derivation_windows_are_not_grid_aligned() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let range = user.derivation_pcd(rng, note, EpochIndex(10));
    assert_eq!(
        range.data().1,
        EpochIndex(10),
        "starts exactly at the request, not rounded to a grid"
    );
}

/// The published `nf_commit` is the whitened trace's commitment, and the
/// whitened trace reads back every covered nullifier at its nullifier point.
#[test]
fn derivation_publishes_the_whitened_trace() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let mk = user.mk(&note);

    let pcd = user.derivation_pcd(rng, note, EpochIndex(10));
    let spectrum = NfTraceGrid::derive(&mk, EpochIndex(10))
        .spectrum()
        .whiten(mk.1);
    assert_eq!(
        pcd.data().3,
        spectrum.commit(),
        "header commits the whitened trace"
    );

    let mut point = *NF_COSET_SHIFT;
    for offset in 0..NF_DERIVATION_WIDTH {
        assert_eq!(
            spectrum.as_ref().eval(point),
            Fp::from(user.nf_at(&note, EpochIndex(10 + offset))),
            "whitened trace reads back the covered nullifier"
        );
        point *= *NF_EPOCH_STEP;
    }
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
    let derived = user.derivation_pcd(rng, *note, epoch);
    (spendable, derived, epoch)
}

/// A nullifier point off the last-column coset fails the coset pin, whatever
/// value the spectrum takes there.
#[test]
fn spend_bind_rejects_off_coset_point() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let (spendable, derived, epoch) = spend_bind_parts(rng, &user, &note);
    let (nf_spectrum, _nf_point) =
        witness::spend_bind((*spendable.data(), *derived.data()), epoch, &user.mk(&note));
    let off_coset = Fp::random(&mut *rng);
    expect_invalid(
        rng,
        spend::SpendBind,
        (nf_spectrum, off_coset),
        spendable,
        derived,
        "SpendBind: nullifier point is not on the last column",
    );
}

/// The window's last epoch has no in-window successor: the wrap back to the
/// window's first is rejected.
#[test]
fn spend_bind_rejects_window_tail() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);

    let (spendable, derived, epoch) = spend_bind_parts(rng, &user, &note);
    let (nf_spectrum, _nf_point) =
        witness::spend_bind((*spendable.data(), *derived.data()), epoch, &user.mk(&note));
    let tail_point =
        *NF_COSET_SHIFT * NF_EPOCH_STEP.pow_vartime([u64::from(NF_DERIVATION_WIDTH - 1)]);
    expect_invalid(
        rng,
        spend::SpendBind,
        (nf_spectrum, tail_point),
        spendable,
        derived,
        "SpendBind: next epoch is past the derivation",
    );
}

/// A different window's whitened trace (same note) does not match the
/// derivation header's commitment.
#[test]
fn spend_bind_rejects_foreign_spectrum() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let mk = user.mk(&note);

    let (spendable, derived, epoch) = spend_bind_parts(rng, &user, &note);
    let (_nf_spectrum, nf_point) =
        witness::spend_bind((*spendable.data(), *derived.data()), epoch, &mk);
    let foreign = NfTraceGrid::derive(&mk, EpochIndex(epoch.0 + NF_DERIVATION_WIDTH))
        .spectrum()
        .whiten(mk.1);
    expect_invalid(
        rng,
        spend::SpendBind,
        (foreign, nf_point),
        spendable,
        derived,
        "SpendBind: whitened trace does not match header",
    );
}

/// A different window's whitened trace does not match the derivation header's
/// commitment at `SpendableInit`.
#[test]
fn spendable_init_rejects_foreign_spectrum() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let mk = user.mk(&note);

    let nf_header = user.derivation_pcd(rng, note, EpochIndex(0));
    // The spectrum bind is checked first, so a dummy boundary chain suffices.
    let dummy_tg = tg(rng);
    let (dummy_chain, ()) = PROOF_SYSTEM
        .seed(
            rng,
            pool::AnchorSeed,
            witness::anchor_seed(((), ()), Anchor::default(), &[dummy_tg]),
        )
        .expect("AnchorSeed");
    let foreign = NfTraceGrid::derive(&mk, EpochIndex(NF_DERIVATION_WIDTH))
        .spectrum()
        .whiten(mk.1);
    expect_invalid(
        rng,
        spendable::SpendableInit,
        (
            (Anchor::default(), Anchor::default()),
            TachygramSetPoly::from_iter([dummy_tg]),
            EpochIndex(0),
            foreign,
        ),
        dummy_chain,
        nf_header,
        "SpendableInit: whitened trace does not match header",
    );
}

/// A different window's whitened trace does not match the derivation header's
/// commitment at `UnspentBind`.
#[test]
fn unspent_bind_rejects_foreign_spectrum() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(500);
    let mk = user.mk(&note);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let unspent = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[user.nf_at(&note, EpochIndex(0))],
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    let range = user.derivation_pcd(rng, note, EpochIndex(0));
    let (elapsed_seq, _nf_spectrum, accumulator) =
        witness::unspent_bind((*unspent.data(), *range.data()), &mk, &[]);
    let foreign = NfTraceGrid::derive(&mk, EpochIndex(NF_DERIVATION_WIDTH))
        .spectrum()
        .whiten(mk.1);
    expect_invalid(
        rng,
        pool::UnspentBind,
        (elapsed_seq, foreign, accumulator),
        unspent,
        range,
        "UnspentBind: whitened trace does not match header",
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
    assert_eq!(lifted_one.data().1, user.nf_at(&note, EpochIndex(1)));

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
        user.nf_at(&note, EpochIndex(2)),
        "tip advanced across two chunks"
    );
    assert_eq!(
        lifted_two.data().2,
        pool.anchor_at(target_two),
        "anchor advanced across two chunks"
    );
    assert_eq!(lifted_two.data().0, note.commitment(), "cm threaded");
}
