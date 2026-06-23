//! Proof-step tests: `StampLift`, `SpendBind` / `SpendStamp`, the GGM
//! derivation chain, `Unspent` composition, and the `Spendable*` lineage.

#![allow(clippy::panic, reason = "test code")]

extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Pcd, Proof};
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::{CryptoRng, RngCore};

use super::{PROOF_SYSTEM, delegation, pool, spend, spendable, stamp};
use crate::{
    ActionSetPoly, Note, TachygramSetPoly,
    constants::EPOCH_SIZE,
    entropy::ActionEntropy,
    fixtures::{
        PoolSim, SyncSim, WalletSim, build_anchor_chain_pcd, build_output_stamp, build_unspent_pcd,
        build_unspent_seed_pcd, random_block, random_block_with, spend_witness,
        spendable_init_inputs,
    },
    note::{self, Nullifier},
    primitives::{Anchor, BlockHeight, EpochIndex, NfSeqCommit, NfSeqPoly, Tachygram, effect},
    value,
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
) -> Pcd<spend::SpendHeader> {
    let (rcv, _theta, alpha) = spend_witness(rng, note);
    let (spend_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            (
                (note.pk, note.value, note.rcm, note.psi),
                rcv,
                alpha,
                user.pak,
            ),
            spendable,
            Proof::trivial().carry::<()>(()),
        )
        .expect("SpendBind honest");
    spend_pcd
}

fn honest_spend_stamp(
    rng: &mut StdRng,
    user: &WalletSim,
    note: &Note,
    spend_pcd: Pcd<spend::SpendHeader>,
    spend_epoch: EpochIndex,
) -> Pcd<stamp::StampHeader> {
    let derived = user.derived_range(rng, note, spend_epoch, 2);
    let nf_next = user.nf_at(note, spend_epoch.next());
    let (stamp, ()) = PROOF_SYSTEM
        .fuse(rng, stamp::SpendStamp, (nf_next,), spend_pcd, derived)
        .expect("SpendStamp honest");
    stamp
}

#[test]
fn same_epoch_honest_spend_accepted() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let cm_height = mine_cm_in_epoch_one(rng, &mut pool, note.commitment());
    let epoch = cm_height.epoch();

    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let spend_pcd = honest_spend_bind(rng, &user, &note, spendable);
    let stamp = honest_spend_stamp(rng, &user, &note, spend_pcd, epoch);

    let expected = TachygramSetPoly::from(
        [
            user.nf_at(&note, epoch).into(),
            user.nf_at(&note, epoch.next()).into(),
        ]
        .as_slice(),
    )
    .commit();
    assert_eq!(stamp.data().1, expected, "publishes {{N_E, N_E+1}}");
    PROOF_SYSTEM
        .rerandomize(stamp, rng)
        .expect("rerandomize honest same-epoch spend");
}

#[test]
fn same_epoch_wrong_index_rejected_against_honest_chain() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let cm_height = mine_cm_in_epoch_one(rng, &mut pool, note.commitment());
    let wrong = EpochIndex(cm_height.epoch().0 + 2);

    let (pre_epoch_anchor, pre_cm_anchor, creation_set, chain) =
        spendable_init_inputs(rng, &pool, note.commitment(), cm_height);
    let present_nf = user.nf_at(&note, wrong);
    let nf_wrong = user.derived_range(rng, &note, wrong, 1);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            (pre_epoch_anchor, pre_cm_anchor, creation_set, present_nf),
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
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
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
    let cm_set = TachygramSetPoly::from(stamps[cm_idx].as_slice());
    let cm_commit = cm_set.commit();
    let (forged_chain, ()) = PROOF_SYSTEM
        .seed(rng, pool::AnchorSeed, (forged_start, cm_commit))
        .expect("AnchorSeed");

    let present_nf = user.nf_at(&note, wrong);
    let nf_wrong = user.derived_range(rng, &note, wrong, 1);
    let (forged_spendable, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            (x, forged_start, cm_set, present_nf),
            forged_chain,
            nf_wrong,
        )
        .expect("SpendableInit accepts the forged wrong-index chain");

    // The circuit accepted, but the produced anchor is off the published sequence,
    // so consensus anchor membership is what rejects the eventual spend.
    let forged_anchor = forged_spendable.data().1;
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
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(1, |_| random_block(rng, 1, 4));
    let stamp_anchor = pool.anchor_at(BlockHeight(1));

    let note = user.random_note(rng, 200);
    let (stamp, plan) = build_output_stamp(rng, stamp_anchor, note);

    let action_commit =
        ActionSetPoly::from([plan.digest().expect("valid plan")].as_slice()).commit();
    let tachygram_commit = TachygramSetPoly::from(stamp.tachygrams.as_slice()).commit();

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
    let user = WalletSim::random(rng);
    let note = user.random_note(rng, 500);

    let nf_header = user.derived_range(rng, &note, EpochIndex(0), 1);
    let present_nf = user.nf_at(&note, EpochIndex(0));
    let absent_set = TachygramSetPoly::from([tg(rng)].as_slice());
    // cm-inclusion is checked first, so a dummy boundary chain suffices here.
    let dummy_commit = TachygramSetPoly::from([tg(rng)].as_slice()).commit();
    let (dummy_chain, ()) = PROOF_SYSTEM
        .seed(rng, pool::AnchorSeed, (Anchor::default(), dummy_commit))
        .expect("AnchorSeed");

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            (Anchor::default(), Anchor::default(), absent_set, present_nf),
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
    let user = WalletSim::random(rng);
    let note = user.random_note(rng, 500);
    let nf = note.nullifier(&user.pak.nk, EpochIndex(0));

    let containing_set = TachygramSetPoly::from([nf.into()].as_slice());
    let start = Anchor::default();

    let err = PROOF_SYSTEM
        .seed(
            rng,
            pool::UnspentSeed,
            (start, EpochIndex(0), containing_set, nf),
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
    let mid = start.next_stamp(&TachygramSetPoly::from(stamps_left.as_slice()).commit());

    // nf mismatch: contiguous states but different nfs.
    {
        let nf_a = Nullifier::from(Fp::random(&mut *rng));
        let nf_b = Nullifier::from(Fp::random(&mut *rng));
        let shard_a = build_unspent_seed_pcd(rng, start, EpochIndex(0), &stamps_left, nf_a);
        let shard_b = build_unspent_seed_pcd(rng, mid, EpochIndex(0), &stamps_right, nf_b);
        let err = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, (), shard_a, shard_b)
            .err()
            .unwrap();
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "UnspentFuse: left and right must share the same nf"
        );
    }

    // state discontinuity: same nf, but right's start matches `start`
    // instead of `left.end`.
    {
        let nf = Nullifier::from(Fp::random(&mut *rng));
        let shard_a = build_unspent_seed_pcd(rng, start, EpochIndex(0), &stamps_left, nf);
        let shard_b = build_unspent_seed_pcd(rng, start, EpochIndex(0), &stamps_right, nf);
        let err = PROOF_SYSTEM
            .fuse(rng, pool::UnspentFuse, (), shard_a, shard_b)
            .err()
            .unwrap();
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "UnspentFuse: left.end must equal right.start"
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
        let commit = pool.stamp_commits_at(BlockHeight(1))[0];
        let (right, ()) = PROOF_SYSTEM
            .seed(rng, pool::AnchorSeed, (bogus_start, commit))
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
    let user = WalletSim::random(rng);
    let note = user.random_note(rng, 100);
    let cm = note.commitment();

    let mut pool = PoolSim::genesis(rng);
    pool.mine(vec![vec![cm.into()]]);
    let cm_height = pool.height();
    let epoch = cm_height.epoch();

    // Bootstrap spendable at the cm-block's published anchor.
    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let spendable_anchor_before = spendable.data().1;

    // Mine one empty block.
    pool.mine(vec![]);
    let empty_height = pool.height();

    // Build an Unspent over the empty block via EmptyBlockUnspentSeed,
    // then lift the spendable.
    let nf = spendable.data().0;
    let unspent = build_unspent_pcd(rng, &pool, nf, empty_height..=empty_height);
    let lifted = user.lift(rng, spendable, unspent, &note, epoch, epoch);

    assert_eq!(lifted.data().1, spendable_anchor_before.next_empty());
    assert_eq!(lifted.data().1, pool.anchor_at(empty_height));
}

#[test]
fn spend_bind_honest() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let spend_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let (_cv, _rk, present_nf, _anchor, _cm) = *spend_pcd.data();
    assert_eq!(present_nf, user.nf_at(&note, spend_epoch));
}

#[test]
fn spend_bind_rejects_invalid_inputs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let other = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();

    let phantom = Note {
        value: note::Value::try_from(999_999u64).expect("test value in range"),
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

    let wrong_value = note::Value::try_from(999_999u64).expect("test value in range");
    assert_ne!(u64::from(wrong_value), u64::from(note.value));

    let cases = [
        (
            "value inflation",
            (phantom.pk, phantom.value, phantom.rcm, phantom.psi),
            user.pak,
            "SpendBind: note does not match the spendable lineage",
        ),
        (
            "wrong value",
            (note.pk, wrong_value, note.rcm, note.psi),
            user.pak,
            "SpendBind: note does not match the spendable lineage",
        ),
        (
            "unrelated pak",
            (note.pk, note.value, note.rcm, note.psi),
            other.pak,
            "SpendBind: pak not related to note",
        ),
    ];

    for (label, preimage, pak, expected) in cases {
        let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);
        let (rcv, _theta, alpha) = spend_witness(rng, &note);
        let err = PROOF_SYSTEM
            .fuse(
                rng,
                spend::SpendBind,
                (preimage, rcv, alpha, pak),
                spendable_pcd,
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
fn spend_stamp_rejects_forged_next() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let spend_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let derived = user.derived_range(rng, &note, spend_epoch, 2);
    let forged_next = Nullifier::from(Fp::random(&mut *rng));

    let err = PROOF_SYSTEM
        .fuse(rng, stamp::SpendStamp, (forged_next,), spend_pcd, derived)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendStamp: published scalars are not the derived leaf pair"
    );
}

#[test]
fn spend_stamp_rejects_zero_next_nullifier() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let spend_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let derived = user.derived_range(rng, &note, spend_epoch, 2);
    let zero_next = Nullifier::from(Fp::ZERO);

    let err = PROOF_SYSTEM
        .fuse(rng, stamp::SpendStamp, (zero_next,), spend_pcd, derived)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendStamp: published scalars are not the derived leaf pair"
    );
}

#[test]
fn spend_stamp_rejects_identity_cv() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let real_spend = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let (_real_cv, real_rk, present_nf, anchor, cm) = *real_spend.data();
    let identity_cv = value::Commitment::balance(0);
    let forged_spend = real_spend.proof().clone().carry::<spend::SpendHeader>((
        identity_cv,
        real_rk,
        present_nf,
        anchor,
        cm,
    ));

    let derived = user.derived_range(rng, &note, spend_epoch, 2);
    let nf_next = user.nf_at(&note, spend_epoch.next());
    let err = PROOF_SYSTEM
        .fuse(rng, stamp::SpendStamp, (nf_next,), forged_spend, derived)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendStamp: action digest construction failed"
    );
}

#[test]
fn step_rejects_zero_value_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);

    let zero_note = Note {
        pk: user.pak.derive_payment_key(),
        value: note::Value::ZERO,
        psi: note::NullifierTrapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    };

    {
        let out_rcv = value::CommitmentTrapdoor::random(rng);
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
        let note = user.random_note(rng, 500);
        pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
        let height = pool.height();
        let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

        let (rcv, _theta, alpha) = spend_witness(rng, &note);

        let err = PROOF_SYSTEM
            .fuse(
                rng,
                spend::SpendBind,
                (
                    (note.pk, note::Value::ZERO, note.rcm, note.psi),
                    rcv,
                    alpha,
                    user.pak,
                ),
                spendable_pcd,
                Proof::trivial().carry::<()>(()),
            )
            .err()
            .unwrap();
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(inner.to_string(), "SpendBind: zero-value note");
    }
}

#[test]
fn spend_after_lift_publishes_anchor_epoch_nullifiers() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let cm_height = mine_cm_block(rng, &mut pool, note.commitment());
    let cm_idx = pool
        .tachygrams_at(cm_height)
        .iter()
        .position(|tgs| tgs.contains(&note.commitment().into()))
        .expect("cm in block");
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let start_anchor = spendable.data().1;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1))
        ],
        cm_height,
        cm_idx,
        start_anchor,
    );
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    let lifted = user.lift(rng, spendable, unspent, &note, EpochIndex(0), EpochIndex(1));

    let spend_pcd = honest_spend_bind(rng, &user, &note, lifted);
    let (_cv, _rk, present_nf, _anchor, _cm) = *spend_pcd.data();
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

    let stamp = honest_spend_stamp(rng, &user, &note, spend_pcd, EpochIndex(1));
    let expected = TachygramSetPoly::from(
        [
            user.nf_at(&note, EpochIndex(1)).into(),
            user.nf_at(&note, EpochIndex(2)).into(),
        ]
        .as_slice(),
    )
    .commit();
    assert_eq!(stamp.data().1, expected);
}

#[test]
fn spend_stamp_assembles_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let spend_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let stamp_pcd = honest_spend_stamp(rng, &user, &note, spend_pcd, spend_epoch);
    let (_actions, tg_commit, _anchor) = *stamp_pcd.data();
    let expected = TachygramSetPoly::from(
        [
            Tachygram::from(user.nf_at(&note, spend_epoch)),
            Tachygram::from(user.nf_at(&note, spend_epoch.next())),
        ]
        .as_slice(),
    )
    .commit();
    assert_eq!(tg_commit, expected);
}

#[test]
fn notes_with_shared_psi_share_nullifiers() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let note_a = user.random_note(rng, 500);
    let note_b = Note {
        value: note::Value::try_from(700u64).expect("test value in range"),
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
fn unspent_epoch_fuse_concatenates_polynomials() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.advance(usize::try_from(EPOCH_SIZE + 1).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });

    let nf_e0 = Nullifier::from(Fp::random(&mut *rng));
    let nf_e1 = Nullifier::from(Fp::random(&mut *rng));
    let left = build_unspent_pcd(
        rng,
        &pool,
        nf_e0,
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let right = build_unspent_pcd(
        rng,
        &pool,
        nf_e1,
        BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
    );

    let left_poly = NfSeqPoly::from(Vec::<Nullifier>::new().as_slice());
    let right_poly = NfSeqPoly::from(Vec::<Nullifier>::new().as_slice());
    let combined = NfSeqPoly::from([nf_e0].as_slice());
    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (left_poly, right_poly, combined),
            left,
            right,
        )
        .expect("UnspentEpochFuse");

    let ((elapsed, present_epoch), _prev, _end, present_nf, start_epoch) = *fused.data();
    assert_eq!(elapsed, NfSeqCommit::from([nf_e0].as_slice()));
    assert_eq!(present_epoch.0 - start_epoch.0, 1, "one crossing");
    assert_eq!(present_nf, nf_e1, "new tip is the right half's present nf");
}

#[test]
fn sync_sim_builds_unspent_for_wallet_lift_across_epochs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let cm_idx = pool
        .tachygrams_at(init_height)
        .iter()
        .position(|tgs| tgs.contains(&note.commitment().into()))
        .expect("cm in block");

    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().1;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1))
        ],
        init_height,
        cm_idx,
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
        lifted.data().0,
        user.nf_at(&note, EpochIndex(1)),
        "tip advanced to nf_1"
    );
    assert_eq!(
        lifted.data().1,
        pool.anchor_at(target_height),
        "anchor advanced"
    );
    assert_eq!(lifted.data().2, note.commitment(), "cm threaded unchanged");
}

#[test]
fn sync_unspent_spans_two_crossings() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let cm_idx = pool
        .tachygrams_at(init_height)
        .iter()
        .position(|tgs| tgs.contains(&note.commitment().into()))
        .expect("cm in block");
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().1;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1)),
            user.nf_at(&note, EpochIndex(2))
        ],
        init_height,
        cm_idx,
        start_anchor,
    );

    let target_height = BlockHeight(2 * EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    assert_eq!(sync.consumed(0), 2, "two epoch crossings");

    let lifted = user.lift(rng, spendable, unspent, &note, EpochIndex(0), EpochIndex(2));
    assert_eq!(lifted.data().0, user.nf_at(&note, EpochIndex(2)));
    assert_eq!(lifted.data().1, pool.anchor_at(target_height));
}

#[test]
fn unspent_fuse_rejects_nonzero_forward_half() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.advance(usize::try_from(EPOCH_SIZE + 1).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });

    let nf0 = Nullifier::from(Fp::random(&mut *rng));
    let nf1 = Nullifier::from(Fp::random(&mut *rng));
    let m_left = build_unspent_pcd(
        rng,
        &pool,
        nf0,
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let m_right = build_unspent_pcd(
        rng,
        &pool,
        nf1,
        BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
    );
    let empty = NfSeqPoly::from(Vec::<Nullifier>::new().as_slice());
    let (multi, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (empty.clone(), empty, NfSeqPoly::from([nf0].as_slice())),
            m_left,
            m_right,
        )
        .expect("multi-epoch segment");

    let left = build_unspent_pcd(rng, &pool, nf0, BlockHeight(0)..=BlockHeight(0));
    let err = PROOF_SYSTEM
        .fuse(rng, pool::UnspentFuse, (), left, multi)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "UnspentFuse: forwards half must stay within one epoch"
    );
}

fn epoch_fuse_setup(
    rng: &mut StdRng,
) -> (
    PoolSim,
    Nullifier,
    Nullifier,
    Pcd<pool::Unspent>,
    Pcd<pool::Unspent>,
) {
    let mut pool = PoolSim::genesis(rng);
    pool.advance(usize::try_from(EPOCH_SIZE + 1).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });
    let nf_e0 = Nullifier::from(Fp::random(&mut *rng));
    let nf_e1 = Nullifier::from(Fp::random(&mut *rng));
    let left = build_unspent_pcd(
        rng,
        &pool,
        nf_e0,
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let right = build_unspent_pcd(
        rng,
        &pool,
        nf_e1,
        BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
    );
    (pool, nf_e0, nf_e1, left, right)
}

#[test]
fn unspent_epoch_fuse_rejects_wrong_left_poly() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_pool, nf_e0, nf_e1, left, right) = epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (
                NfSeqPoly::from([nf_e1].as_slice()),
                NfSeqPoly::from(Vec::<Nullifier>::new().as_slice()),
                NfSeqPoly::from([nf_e0].as_slice()),
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
fn unspent_epoch_fuse_rejects_wrong_combined() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_pool, _nf_e0, nf_e1, left, right) = epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (
                NfSeqPoly::from(Vec::<Nullifier>::new().as_slice()),
                NfSeqPoly::from(Vec::<Nullifier>::new().as_slice()),
                NfSeqPoly::from([nf_e1].as_slice()),
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
fn unspent_epoch_fuse_rejects_epoch_skip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.advance(usize::try_from(2 * EPOCH_SIZE).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });
    let nf_e0 = Nullifier::from(Fp::random(&mut *rng));
    let nf_e2 = Nullifier::from(Fp::random(&mut *rng));
    let left = build_unspent_pcd(
        rng,
        &pool,
        nf_e0,
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let right = build_unspent_pcd(
        rng,
        &pool,
        nf_e2,
        BlockHeight(2 * EPOCH_SIZE)..=BlockHeight(2 * EPOCH_SIZE),
    );
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (
                NfSeqPoly::from(Vec::<Nullifier>::new().as_slice()),
                NfSeqPoly::from(Vec::<Nullifier>::new().as_slice()),
                NfSeqPoly::from([nf_e0].as_slice()),
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
        "UnspentEpochFuse: right epoch must be one past left's tip"
    );
}

#[test]
fn verify_unspent_rejects_tip_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let cm_idx = pool
        .tachygrams_at(init_height)
        .iter()
        .position(|tgs| tgs.contains(&note.commitment().into()))
        .expect("cm in block");
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().1;

    let wrong_tip = Nullifier::from(Fp::random(&mut *rng));
    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![user.nf_at(&note, EpochIndex(0)), wrong_tip],
        init_height,
        cm_idx,
        start_anchor,
    );
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);

    let range = user.derived_range(rng, &note, EpochIndex(0), 2);
    let elapsed = NfSeqPoly::from([user.nf_at(&note, EpochIndex(0))].as_slice());
    let tip = NfSeqPoly::from([user.nf_at(&note, EpochIndex(1))].as_slice());
    let range_poly = NfSeqPoly::from(
        [
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1)),
        ]
        .as_slice(),
    );

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::VerifyUnspent,
            (elapsed, tip, range_poly),
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
        "VerifyUnspent: tip polynomial does not match present nullifier"
    );
}

#[test]
fn verify_unspent_rejects_elapsed_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let unspent = build_unspent_pcd(
        rng,
        &pool,
        user.nf_at(&note, EpochIndex(0)),
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    let range = user.derived_range(rng, &note, EpochIndex(0), 1);
    let bogus_elapsed = NfSeqPoly::from([Nullifier::from(Fp::random(&mut *rng))].as_slice());
    let tip = NfSeqPoly::from([user.nf_at(&note, EpochIndex(0))].as_slice());
    let range_poly = NfSeqPoly::from([user.nf_at(&note, EpochIndex(0))].as_slice());

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::VerifyUnspent,
            (bogus_elapsed, tip, range_poly),
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
        "VerifyUnspent: elapsed polynomial does not match header"
    );
}

#[test]
fn verify_unspent_rejects_wrong_start_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let unspent = build_unspent_pcd(
        rng,
        &pool,
        user.nf_at(&note, EpochIndex(0)),
        BlockHeight(init_height.0 + 1)..=BlockHeight(init_height.0 + 1),
    );
    let range = user.derived_range(rng, &note, EpochIndex(1), 1);
    let elapsed = NfSeqPoly::from(Vec::<Nullifier>::new().as_slice());
    let tip = NfSeqPoly::from([user.nf_at(&note, EpochIndex(1))].as_slice());
    let range_poly = NfSeqPoly::from([user.nf_at(&note, EpochIndex(1))].as_slice());

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::VerifyUnspent,
            (elapsed, tip, range_poly),
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
        "VerifyUnspent: derived range does not start at the elapsed epoch"
    );
}

#[test]
fn spendable_lift_rejects_wrong_cm() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let phantom = Note {
        value: note::Value::try_from(700u64).expect("test value in range"),
        rcm: note::CommitmentTrapdoor::random(rng),
        ..note
    };
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let cm_idx = pool
        .tachygrams_at(init_height)
        .iter()
        .position(|tgs| tgs.contains(&note.commitment().into()))
        .expect("cm in block");
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().1;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(1))
        ],
        init_height,
        cm_idx,
        start_anchor,
    );
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    let verified = user.verify_unspent(rng, unspent, &phantom, EpochIndex(0), EpochIndex(1));

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
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    pool.advance(1, |_| random_block(rng, 1, 2));

    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let unspent = build_unspent_pcd(
        rng,
        &pool,
        user.nf_at(&note, EpochIndex(0)),
        init_height..=init_height,
    );
    let verified = user.verify_unspent(rng, unspent, &note, EpochIndex(0), EpochIndex(0));

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

#[test]
fn nullifier_fuse_rejects_non_contiguous() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let note = user.random_note(rng, 500);

    let range_a = user.derived_range(rng, &note, EpochIndex(0), 1);
    let range_b = user.derived_range(rng, &note, EpochIndex(2), 1);
    let left_poly = NfSeqPoly::from([user.nf_at(&note, EpochIndex(0))].as_slice());
    let right_poly = NfSeqPoly::from([user.nf_at(&note, EpochIndex(2))].as_slice());
    let merged = NfSeqPoly::from(
        [
            user.nf_at(&note, EpochIndex(0)),
            user.nf_at(&note, EpochIndex(2)),
        ]
        .as_slice(),
    );

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NullifierFuse,
            (left_poly, right_poly, merged),
            range_a,
            range_b,
        )
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
    let user = WalletSim::random(rng);
    let note_a = user.random_note(rng, 500);
    let note_b = user.random_note(rng, 500);

    let range_a = user.derived_range(rng, &note_a, EpochIndex(0), 1);
    let range_b = user.derived_range(rng, &note_b, EpochIndex(1), 1);
    let left_poly = NfSeqPoly::from([user.nf_at(&note_a, EpochIndex(0))].as_slice());
    let right_poly = NfSeqPoly::from([user.nf_at(&note_b, EpochIndex(1))].as_slice());
    let merged = NfSeqPoly::from(
        [
            user.nf_at(&note_a, EpochIndex(0)),
            user.nf_at(&note_b, EpochIndex(1)),
        ]
        .as_slice(),
    );

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NullifierFuse,
            (left_poly, right_poly, merged),
            range_a,
            range_b,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "NullifierFuse: note commitments differ");
}
