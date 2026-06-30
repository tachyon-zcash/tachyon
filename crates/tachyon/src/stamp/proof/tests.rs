//! Proof-step tests: `StampLift`, `SpendBind` / `SpendStamp`, the MiMC
//! derivation chain, `Unspent` composition, and the `Spendable*` lineage.

#![allow(clippy::panic, clippy::as_conversions, reason = "test code")]

extern crate alloc;

use alloc::{string::ToString as _, vec};

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
        PoolSim, SyncSim, WalletSim, build_anchor_chain_pcd, build_output_stamp,
        build_unspent_pcd_between_blocks, build_unspent_seed_pcd, random_block, random_block_with,
        spend_witness, spendable_init_inputs,
    },
    keys::{ExpandedKey, NoteMasterKey},
    note::{self, Nullifier},
    primitives::{Anchor, BlockHeight, EpochIndex, EpochOffset, NfSeqPoly, Tachygram, effect},
    value, witness,
};

fn tg<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Tachygram {
    Tachygram::from(Fp::random(rng))
}

#[test]
fn nullifier_derivation_certifies_a_note() {
    // Proving the step end-to-end asserts the certify relations hold: the
    // committed-offset recurrence (periodic offset == C + closed-form selectors)
    // and the ROWS=1 boundary, per poly. The header must then reflect the keyset
    // and creation epoch.
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let note = wallet.random_note(rng, 400);
    let creation_epoch = EpochIndex(7);

    let cm_expected = note.commitment();
    let mk = wallet.master_key(&note);
    let keyset = mk.derive_expanded();
    let salts = mk.query_salts();
    let (ratios_expected, shift_expected) = mk.query_weights();
    let polys_expected = keyset.derivation_polys(&salts);

    let pcd = wallet.derivation_pcd(rng, note, creation_epoch);
    let (commits, _digest, cm, e0, shift, ratios) = *pcd.data();

    assert_eq!(cm, cm_expected, "header carries the note commitment");
    assert_eq!(e0, creation_epoch, "header carries the creation epoch");
    assert_eq!(
        shift.0, shift_expected.0,
        "header forwards the mk-derived shift c"
    );
    assert_eq!(
        ratios.0, ratios_expected.0,
        "header forwards the mk-derived ratios"
    );

    for (commit, poly) in commits.iter().zip(&polys_expected) {
        assert_eq!(
            commit.0,
            poly.0.commit(),
            "header commits the genuine derivation polynomials"
        );
    }
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
    creation_epoch: EpochIndex,
) -> Pcd<stamp::StampHeader> {
    // SpendStamp reads the spend offset `d = present_epoch - E_0` from the
    // SpendHeader (derived at SpendBind); here we only supply the derivation
    // (keyed by the note's creation epoch E_0, the same PCD the spendable
    // lineage used) and its polynomials.
    let (derivation, polys, _keyset) = user.derivation(rng, note, creation_epoch);
    let (stamp, ()) = PROOF_SYSTEM
        .fuse(rng, stamp::SpendStamp, (polys,), spend_pcd, derivation)
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

    let expected = TachygramSetPoly::from_iter([
        user.query_nf(&note, EpochOffset(0)).into(),
        user.query_nf(&note, EpochOffset(1)).into(),
    ])
    .commit();
    assert_eq!(stamp.data().1, expected, "publishes {{nf_0, nf_1}}");
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
    // The derivation pins E_0 = `wrong`, but the chain is rooted at the real
    // creation-epoch boundary, so the E_0 binding rejects it.
    let (derivation, polys, _keyset) = user.derivation(rng, &note, wrong);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            (pre_epoch_anchor, pre_cm_anchor, creation_set, polys),
            chain,
            derivation,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendableInit: chain not rooted at the creation-epoch boundary"
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
    let cm_set = stamps[cm_idx].iter().copied().collect::<TachygramSetPoly>();
    let cm_commit = cm_set.commit();
    let (forged_chain, ()) = PROOF_SYSTEM
        .seed(rng, pool::AnchorSeed, (forged_start, cm_commit))
        .expect("AnchorSeed");

    let (derivation, polys, _keyset) = user.derivation(rng, &note, wrong);
    let (forged_spendable, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            (x, forged_start, cm_set, polys),
            forged_chain,
            derivation,
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
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(1, |_| random_block(rng, 1, 4));
    let stamp_anchor = pool.anchor_at(BlockHeight(1));

    let note = user.random_note(rng, 200);
    let (stamp, plan) = build_output_stamp(rng, stamp_anchor, note);

    let action_commit = ActionSetPoly::from_iter([plan.digest().expect("valid plan")]).commit();
    let tachygram_commit = stamp
        .tachygrams
        .iter()
        .copied()
        .collect::<TachygramSetPoly>()
        .commit();

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

    let (derivation, polys, _keyset) = user.derivation(rng, &note, EpochIndex(0));
    let absent_set = TachygramSetPoly::from_iter([tg(rng)]);
    // cm-inclusion is checked first, so a dummy boundary chain suffices here.
    let dummy_commit = TachygramSetPoly::from_iter([tg(rng)]).commit();
    let (dummy_chain, ()) = PROOF_SYSTEM
        .seed(rng, pool::AnchorSeed, (Anchor::default(), dummy_commit))
        .expect("AnchorSeed");

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SpendableInit,
            (Anchor::default(), Anchor::default(), absent_set, polys),
            dummy_chain,
            derivation,
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
    let nf = user.query_nf(&note, EpochOffset(0));
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
    let mid = start.next_stamp(
        &stamps_left
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit(),
    );

    // nf mismatch: contiguous states but different nfs.
    {
        let nf_a = Nullifier::from(Fp::random(&mut *rng));
        let nf_b = Nullifier::from(Fp::random(&mut *rng));
        let shard_a = build_unspent_seed_pcd(rng, start, EpochIndex(0), &stamps_left, nf_a);
        let shard_b = build_unspent_seed_pcd(rng, mid, EpochIndex(0), &stamps_right, nf_b);
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
    let spendable_anchor_before = spendable.data().2;

    // Mine one empty block.
    pool.mine(vec![]);
    let empty_height = pool.height();

    // Build an Unspent over the empty block via EmptyBlockUnspentSeed,
    // then lift the spendable.
    let nf = spendable.data().1.1;
    let unspent = build_unspent_pcd_between_blocks(rng, &pool, &[nf], empty_height..=empty_height);
    let lifted = user.lift(rng, spendable, unspent, &note, epoch, epoch);

    assert_eq!(lifted.data().2, spendable_anchor_before.next_empty());
    assert_eq!(lifted.data().2, pool.anchor_at(empty_height));
}

#[test]
fn spend_bind_honest() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let spend_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    let (_cm, (_cv, _rk), present_nf, _anchor, _offset) = *spend_pcd.data();
    assert_eq!(present_nf, user.query_nf(&note, EpochOffset(0)));
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

    let phantom = Note {
        value: note::Value::try_from(999_999u64).expect("test value in range"),
        rcm: note::CommitmentTrapdoor::random(rng),
        ..note
    };
    assert_eq!(Fp::from(note.psi), Fp::from(phantom.psi), "shared psi");
    assert_ne!(note.commitment(), phantom.commitment(), "distinct cm");
    assert_eq!(
        user.query_nf(&note, EpochOffset(0)),
        user.query_nf(&phantom, EpochOffset(0)),
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
fn spend_stamp_rejects_wrong_offset() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let spend_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    // The offset is threaded on the SpendHeader (derived at SpendBind, offset 0
    // here). Forge a header advertising a different offset while present_nf
    // stays the creation-epoch nullifier; SpendStamp queries the derivation at
    // the forged offset, gets a different nf, and the continuity check against
    // present_nf rejects it.
    let (cm, (cv, rk), present_nf, anchor, _offset) = *spend_pcd.data();
    let forged = spend_pcd.proof().clone().carry::<spend::SpendHeader>((
        cm,
        (cv, rk),
        present_nf,
        anchor,
        EpochOffset(1),
    ));
    let (derivation, polys, _keyset) = user.derivation(rng, &note, spend_epoch);
    let err = PROOF_SYSTEM
        .fuse(rng, stamp::SpendStamp, (polys,), forged, derivation)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendStamp: query does not match the lineage nullifier"
    );
}

#[test]
fn spend_stamp_rejects_foreign_derivation() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 4));
    let height = pool.height();
    let spend_epoch = height.epoch();
    let spendable_pcd = user.fresh_spend(rng, &pool, height, &note);

    let spend_pcd = honest_spend_bind(rng, &user, &note, spendable_pcd);
    // A derivation certifying a *different* note does not match this spend's cm.
    let other = user.random_note(rng, 500);
    let (derivation, polys, _keyset) = user.derivation(rng, &other, spend_epoch);
    let err = PROOF_SYSTEM
        .fuse(rng, stamp::SpendStamp, (polys,), spend_pcd, derivation)
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendStamp: derivation does not certify the note"
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
    let (cm, (_real_cv, real_rk), present_nf, anchor, offset) = *real_spend.data();
    let identity_cv = value::Commitment::balance(0);
    let forged_spend = real_spend.proof().clone().carry::<spend::SpendHeader>((
        cm,
        (identity_cv, real_rk),
        present_nf,
        anchor,
        offset,
    ));

    let (derivation, polys, _keyset) = user.derivation(rng, &note, spend_epoch);
    let err = PROOF_SYSTEM
        .fuse(rng, stamp::SpendStamp, (polys,), forged_spend, derivation)
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
            user.query_nf(&note, EpochOffset(0)),
            user.query_nf(&note, EpochOffset(1))
        ],
        cm_height,
        start_anchor,
    );
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    let lifted = user.lift(rng, spendable, unspent, &note, EpochIndex(0), EpochIndex(1));

    let spend_pcd = honest_spend_bind(rng, &user, &note, lifted);
    let (_cm, (_cv, _rk), present_nf, _anchor, _offset) = *spend_pcd.data();
    assert_eq!(
        present_nf,
        user.query_nf(&note, EpochOffset(1)),
        "publishes the epoch-1 nf"
    );
    assert_ne!(
        present_nf,
        user.query_nf(&note, EpochOffset(0)),
        "nf_0 was consumed by the lift"
    );

    // E_0 = 0 (cm minted in epoch 0); the spend at epoch 1 is offset d = 1.
    let stamp = honest_spend_stamp(rng, &user, &note, spend_pcd, EpochIndex(0));
    let expected = TachygramSetPoly::from_iter([
        user.query_nf(&note, EpochOffset(1)).into(),
        user.query_nf(&note, EpochOffset(2)).into(),
    ])
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
    let expected = TachygramSetPoly::from_iter([
        Tachygram::from(user.query_nf(&note, EpochOffset(0))),
        Tachygram::from(user.query_nf(&note, EpochOffset(1))),
    ])
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

    for offset in 0..4u32 {
        assert_eq!(
            user.query_nf(&note_a, EpochOffset(offset)),
            user.query_nf(&note_b, EpochOffset(offset)),
            "shared psi yields shared nullifiers at offset {offset}"
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
    let left = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[nf_e0],
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let right = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[nf_e1],
        BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
    );

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            witness::unspent_epoch_fuse((*left.data(), *right.data()), &[], &[]),
            left,
            right,
        )
        .expect("UnspentEpochFuse");

    let (_anchor_prev, (epoch_start, _nf_start), elapsed, (epoch_end, nf_end), _anchor_last) =
        *fused.data();
    assert_eq!(elapsed, NfSeqPoly::from_iter([nf_e0]).commit());
    assert_eq!(epoch_end.0 - epoch_start.0, 1, "one crossing");
    assert_eq!(nf_end, nf_e1, "new tip is the right half's tip nf");
}

#[test]
fn sync_sim_builds_unspent_for_wallet_lift_across_epochs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());

    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.query_nf(&note, EpochOffset(0)),
            user.query_nf(&note, EpochOffset(1))
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
        lifted.data().1.1,
        user.query_nf(&note, EpochOffset(1)),
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
fn sync_unspent_spans_two_crossings() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.query_nf(&note, EpochOffset(0)),
            user.query_nf(&note, EpochOffset(1)),
            user.query_nf(&note, EpochOffset(2))
        ],
        init_height,
        start_anchor,
    );

    let target_height = BlockHeight(2 * EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    assert_eq!(sync.consumed(0), 2, "two epoch crossings");

    let lifted = user.lift(rng, spendable, unspent, &note, EpochIndex(0), EpochIndex(2));
    assert_eq!(lifted.data().1.1, user.query_nf(&note, EpochOffset(2)));
    assert_eq!(lifted.data().2, pool.anchor_at(target_height));
    assert_eq!(
        lifted.data().1.0,
        EpochIndex(2),
        "present_epoch advances to the unspent tip epoch"
    );
}

#[test]
fn unspent_fuse_composes_multi_epoch_right() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis(rng);
    pool.advance(usize::try_from(EPOCH_SIZE + 1).expect("fits"), |_| {
        random_block(rng, 1, 2)
    });

    let nf0 = Nullifier::from(Fp::random(&mut *rng));
    let nf1 = Nullifier::from(Fp::random(&mut *rng));
    // Left: epoch 0's first block only (single-epoch). Right: the rest of epoch 0
    // plus epoch 1's first block — multi-epoch, sharing the mid-epoch junction.
    let left =
        build_unspent_pcd_between_blocks(rng, &pool, &[nf0], BlockHeight(0)..=BlockHeight(0));
    let right = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[nf0, nf1],
        BlockHeight(1)..=BlockHeight(EPOCH_SIZE),
    );

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            witness::unspent_fuse((*left.data(), *right.data()), &[], &[nf0]),
            left,
            right,
        )
        .expect("UnspentFuse mid-epoch with multi-epoch right");

    let (_anchor_prev, (epoch_start, nf_start), elapsed, (epoch_end, nf_end), _anchor_last) =
        *fused.data();
    assert_eq!(
        elapsed,
        NfSeqPoly::from_iter([nf0]).commit(),
        "junction epoch recorded once, not duplicated"
    );
    assert_eq!(nf_start, nf0);
    assert_eq!(nf_end, nf1, "tip advances to the right half's present nf");
    assert_eq!(epoch_start.0, 0);
    assert_eq!(
        epoch_end.0, 1,
        "merged range spans the boundary the right crossed"
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
    // Left spans all of epoch 0; `left.anchor_last` is epoch 0's terminal anchor.
    let left = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[nf0],
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let left_end = left.data().4;
    // A forged epoch-1 right rooted directly at `left.anchor_last` (no
    // `next_epoch` fold): anchors line up, but the epoch labels reveal a boundary
    // this fuse refuses to cross (that is `UnspentEpochFuse`'s job).
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
    let left = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[nf_e0],
        BlockHeight(0)..=BlockHeight(EPOCH_SIZE - 1),
    );
    let right = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[nf_e1],
        BlockHeight(EPOCH_SIZE)..=BlockHeight(EPOCH_SIZE),
    );
    (pool, nf_e0, nf_e1, left, right)
}

#[test]
fn unspent_epoch_fuse_rejects_wrong_left_seq() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_pool, nf_e0, nf_e1, left, right) = epoch_fuse_setup(rng);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentEpochFuse,
            (
                NfSeqPoly::from_iter([nf_e1]),
                NfSeqPoly::from_iter([nf_e0]),
                NfSeqPoly::from_iter([]),
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
                NfSeqPoly::from_iter([]),
                NfSeqPoly::from_iter([nf_e1]),
                NfSeqPoly::from_iter([]),
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
fn verify_unspent_rejects_tip_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.query_nf(&note, EpochOffset(0)),
            user.query_nf(&note, EpochOffset(1))
        ],
        init_height,
        start_anchor,
    );
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);

    // Honest witness, but the tip poly's commitment no longer matches the
    // Unspent's present nullifier.
    let (mut witness, derivation) = user.verify_unspent_witness(
        rng,
        &unspent,
        &note,
        EpochIndex(0),
        EpochIndex(0),
        EpochIndex(1),
    );
    witness.1 = NfSeqPoly::from_iter([Nullifier::from(Fp::random(&mut *rng))]);

    let err = PROOF_SYSTEM
        .fuse(rng, pool::VerifyUnspent, witness, unspent, derivation)
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
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.query_nf(&note, EpochOffset(0)),
            user.query_nf(&note, EpochOffset(1))
        ],
        init_height,
        start_anchor,
    );
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);

    // Honest witness, but the elapsed poly's commitment no longer matches the
    // Unspent header's elapsed commitment.
    let (mut witness, derivation) = user.verify_unspent_witness(
        rng,
        &unspent,
        &note,
        EpochIndex(0),
        EpochIndex(0),
        EpochIndex(1),
    );
    witness.0 = NfSeqPoly::from_iter([Nullifier::from(Fp::random(&mut *rng))]);

    let err = PROOF_SYSTEM
        .fuse(rng, pool::VerifyUnspent, witness, unspent, derivation)
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
fn verify_unspent_rejects_nf_start_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.query_nf(&note, EpochOffset(0)),
            user.query_nf(&note, EpochOffset(1))
        ],
        init_height,
        start_anchor,
    );
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);

    // Forge the Unspent header's nf_start; elapsed, present_nf, and anchors stay
    // honest, so only the new range-start binding fires.
    let (anchor_prev, (epoch_start, _nf_start), elapsed, tip, anchor_last) = *unspent.data();
    let forged_unspent = unspent.proof().clone().carry::<pool::Unspent>((
        anchor_prev,
        (epoch_start, Nullifier::from(Fp::random(&mut *rng))),
        elapsed,
        tip,
        anchor_last,
    ));

    let (witness, derivation) = user.verify_unspent_witness(
        rng,
        &forged_unspent,
        &note,
        EpochIndex(0),
        EpochIndex(0),
        EpochIndex(1),
    );

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::VerifyUnspent,
            witness,
            forged_unspent,
            derivation,
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "VerifyUnspent: header nf_start does not match the verified range start"
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
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.query_nf(&phantom, EpochOffset(0)),
            user.query_nf(&phantom, EpochOffset(1))
        ],
        init_height,
        start_anchor,
    );
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    // Verify against the phantom's own derivation (E_0 = 0); the resulting
    // VerifiedUnspent carries the phantom's cm, which SpendableLift rejects.
    let verified = user.verify_unspent(
        rng,
        unspent,
        &phantom,
        EpochIndex(0),
        EpochIndex(0),
        EpochIndex(1),
    );

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
fn spendable_lift_rejects_epoch_discontinuity() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    let note = user.random_note(rng, 500);
    let init_height = mine_cm_block(rng, &mut pool, note.commitment());
    let spendable = user.spendable_init(rng, &note, &pool, init_height);
    let start_anchor = spendable.data().2;
    let present_epoch = spendable.data().1.0;

    let mut sync = SyncSim::new();
    sync.accept_delegation(
        0,
        alloc::vec![
            user.query_nf(&note, EpochOffset(0)),
            user.query_nf(&note, EpochOffset(1))
        ],
        init_height,
        start_anchor,
    );
    let target_height = BlockHeight(EPOCH_SIZE);
    while pool.height() < target_height {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }
    let unspent = sync.build_next_unspent(rng, 0, &pool, target_height);
    let verified = user.verify_unspent(
        rng,
        unspent,
        &note,
        EpochIndex(0),
        EpochIndex(0),
        EpochIndex(1),
    );

    // Forge the verified unspent to advertise a start_epoch that does not match
    // the lineage's present_epoch; cm, E_0, start_nf, and anchor stay honest, so
    // only the additive epoch-continuity guard fires.
    let (cm, sa, (_epoch_start, snf), (tip, enf), ea, e0) = *verified.data();
    let forged = verified.proof().clone().carry::<pool::VerifiedUnspent>((
        cm,
        sa,
        (present_epoch.next(), snf),
        (tip, enf),
        ea,
        e0,
    ));

    let err = PROOF_SYSTEM
        .fuse(rng, spendable::SpendableLift, (), spendable, forged)
        .err()
        .unwrap();

    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SpendableLift: segment does not start at the lineage epoch"
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
    let unspent = build_unspent_pcd_between_blocks(
        rng,
        &pool,
        &[user.query_nf(&note, EpochOffset(0))],
        init_height..=init_height,
    );
    let verified = user.verify_unspent(
        rng,
        unspent,
        &note,
        EpochIndex(0),
        EpochIndex(0),
        EpochIndex(0),
    );

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

/// Forged key-expansion witnesses are each rejected by the gate they violate.
/// A note's master and a foreign master are built once; each case forges a
/// witness off the trace's keyed cipher.
#[test]
fn nf_master_expand_rejects_forged_witnesses() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let note = user.random_note(rng, 500);
    let other = user.random_note(rng, 500);
    let mk = user.master_key(&note);
    let other_mk = user.master_key(&other);

    // The genuine complementary seeds thread the note's `mk`; each case forges
    // only the witness, so the violated relation rejects it.
    let left = user.note_master_half(rng, note, [0, 1, 2]);
    let right = user.note_master_half(rng, note, [3, 4, 5]);

    // Build the expansion-step witness from `builder_mk`'s trace, with quotients
    // honest for `builder_mk` (so the witness is well-formed; only the threaded
    // note `mk` disagrees in the mismatched/hybrid cases).
    let assemble = |builder_mk: NoteMasterKey, half: usize| {
        let (spectrum, half_keys) = builder_mk.derive_expanded_trace(half);
        witness::nf_master_expand(
            (*left.data(), *right.data()),
            &builder_mk,
            &spectrum,
            &half_keys,
            half,
        )
    };

    // Trace under a foreign keyset: round 0 (the first column) binds k_0, so the
    // boundary rejects it before the recurrence is reached.
    let mismatched = assemble(other_mk, 0);

    // Hybrid keyset sharing the round-0 key but a different mk_1: round 0 matches
    // (the boundary passes), rounds 1.. diverge (the row recurrence rejects).
    let hybrid_rounds = {
        let mut hybrid = mk;
        hybrid.0[1] += Fp::ONE;
        assemble(hybrid, 0)
    };

    // Honest trace and quotients but a tampered half-key poly: the decimation
    // identity binding `A` to the trace's final column fails.
    let forged_key = {
        let (trace, quotients, _honest_key, decimation_quotient, half) = assemble(mk, 0);
        let (_, even_keys) = mk.derive_expanded_trace(0);
        let mut tampered = even_keys;
        tampered[0] += Fp::ONE;
        let bad_key = ExpandedKey::half_key_poly(&tampered);
        (trace, quotients, bad_key, decimation_quotient, half)
    };

    let cases = [
        (
            "mismatched keyset",
            mismatched,
            "first column values identity fails at challenge",
        ),
        (
            "hybrid keyset wrong mk_1",
            hybrid_rounds,
            "row recurrence identity fails at challenge",
        ),
        (
            "forged key poly",
            forged_key,
            "strided column identity fails at challenge",
        ),
    ];

    for (label, witness, expected) in cases {
        let err = PROOF_SYSTEM
            .fuse(
                rng,
                delegation::NfMasterExpand,
                witness,
                left.clone(),
                right.clone(),
            )
            .err()
            .unwrap_or_else(|| panic!("{label}: expected rejection"));
        let ragu::Error::InvalidWitness(inner) = err else {
            panic!("expected InvalidWitness, got {err:?}");
        };
        assert_eq!(inner.to_string(), expected, "{label}");
    }
}

/// A key poly that does not match the certified keyset commitment is rejected
/// by the consumer's commit-equality check.
#[test]
fn derivation_rejects_mismatched_key_poly() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let note = user.random_note(rng, 500);
    let creation_epoch = EpochIndex(7);

    let mk = user.master_key(&note);

    let even_left = user.note_master_half(rng, note, [0, 1, 2]);
    let even_right = user.note_master_half(rng, note, [3, 4, 5]);
    let (even_spectrum, even_keys) = mk.derive_expanded_trace(0);
    let (keyset_even_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NfMasterExpand,
            witness::nf_master_expand(
                (*even_left.data(), *even_right.data()),
                &mk,
                &even_spectrum,
                &even_keys,
                0,
            ),
            even_left,
            even_right,
        )
        .unwrap();
    let odd_left = user.note_master_half(rng, note, [0, 1, 2]);
    let odd_right = user.note_master_half(rng, note, [3, 4, 5]);
    let (odd_spectrum, odd_keys) = mk.derive_expanded_trace(1);
    let (keyset_odd_pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NfMasterExpand,
            witness::nf_master_expand(
                (*odd_left.data(), *odd_right.data()),
                &mk,
                &odd_spectrum,
                &odd_keys,
                1,
            ),
            odd_left,
            odd_right,
        )
        .unwrap();

    // A half-key poly with a tampered output no longer matches its committed
    // half-keyset, so the consumer's commit-equality check rejects it.
    let keyset = ExpandedKey::from_halves(&even_keys, &odd_keys);
    let salts = mk.query_salts();
    let polys = keyset.derivation_polys(&salts);
    let key_a = ExpandedKey::half_key_poly(&even_keys);
    let key_b = ExpandedKey::half_key_poly(&odd_keys);
    let (_orig_a, good_b, good_polys, good_quotients, _) = witness::nullifier_derivation(
        (*keyset_even_pcd.data(), *keyset_odd_pcd.data()),
        &keyset,
        key_a,
        key_b,
        &mk,
        &polys,
        creation_epoch,
    );
    let mut tampered = even_keys;
    tampered[0] += Fp::ONE;
    let bad_key_a = ExpandedKey::half_key_poly(&tampered);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NullifierDerivationStep,
            (
                bad_key_a,
                good_b,
                good_polys,
                good_quotients,
                creation_epoch,
            ),
            keyset_even_pcd,
            keyset_odd_pcd,
        )
        .err()
        .unwrap_or_else(|| panic!("expected rejection"));
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "NullifierDerivationStep: even half-key poly does not match its commitment"
    );
}

/// Certify one expansion half (the `NfExpandedKeyset` PCD) for a note,
/// returning it with that half's keys.
fn keyset_half_pcd(
    user: &WalletSim,
    rng: &mut StdRng,
    note: Note,
    half: usize,
) -> (
    Pcd<delegation::NfExpandedKeyset>,
    [Fp; ExpandedKey::EK_HALF],
) {
    let mk = user.master_key(&note);
    let (spectrum, keys) = mk.derive_expanded_trace(half);
    let left = user.note_master_half(rng, note, [0, 1, 2]);
    let right = user.note_master_half(rng, note, [3, 4, 5]);
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NfMasterExpand,
            witness::nf_master_expand((*left.data(), *right.data()), &mk, &spectrum, &keys, half),
            left,
            right,
        )
        .expect("NfMasterExpand half");
    (pcd, keys)
}

fn assert_invalid(err: ragu::Error, expected: &str) {
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), expected);
}

/// The derivation step's seam rejects malformed half pairs: the same half twice
/// (the right-half pin), and halves from different notes (the cm seam). The
/// honest witness is never reached -- the seam checks fire before binding.
#[test]
#[expect(clippy::similar_names, reason = "note A vs note B half-key bindings")]
fn derivation_rejects_seam_violations() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let note_a = user.random_note(rng, 500);
    let note_b = user.random_note(rng, 500);
    let creation_epoch = EpochIndex(7);
    let mk_a = user.master_key(&note_a);

    let (even_a_pcd, even_a_keys) = keyset_half_pcd(&user, rng, note_a, 0);
    let (_odd_a_pcd, odd_a_keys) = keyset_half_pcd(&user, rng, note_a, 1);
    let (odd_b_pcd, odd_b_keys) = keyset_half_pcd(&user, rng, note_b, 1);

    let keyset_a = ExpandedKey::from_halves(&even_a_keys, &odd_a_keys);
    let polys = keyset_a.derivation_polys(&mk_a.query_salts());
    let even_a_header = *even_a_pcd.data();
    let make_witness = |right_header, key_b_keys: &[Fp; ExpandedKey::EK_HALF]| {
        witness::nullifier_derivation(
            (even_a_header, right_header),
            &keyset_a,
            ExpandedKey::half_key_poly(&even_a_keys),
            ExpandedKey::half_key_poly(key_b_keys),
            &mk_a,
            &polys,
            creation_epoch,
        )
    };

    // Case 1: the even half (half = 0) supplied as both Left and Right; the
    // right-half pin rejects it.
    let dup_witness = make_witness(even_a_header, &even_a_keys);
    let dup_err = PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NullifierDerivationStep,
            dup_witness,
            even_a_pcd.clone(),
            even_a_pcd.clone(),
        )
        .err()
        .unwrap_or_else(|| panic!("expected rejection: duplicated half"));
    assert_invalid(dup_err, "NullifierDerivationStep: right half must be 1");

    // Case 2: even from note A, odd from note B; the cm seam rejects it.
    let cross_witness = make_witness(*odd_b_pcd.data(), &odd_b_keys);
    let cross_err = PROOF_SYSTEM
        .fuse(
            rng,
            delegation::NullifierDerivationStep,
            cross_witness,
            even_a_pcd,
            odd_b_pcd,
        )
        .err()
        .unwrap_or_else(|| panic!("expected rejection: mismatched note"));
    assert_invalid(
        cross_err,
        "NullifierDerivationStep: half commitments do not match",
    );
}
