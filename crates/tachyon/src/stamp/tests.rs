#![allow(clippy::panic, reason = "test code")]

use alloc::{boxed::Box, string::ToString as _, vec, vec::Vec};

use ff::Field as _;
use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    action,
    constants::EPOCH_SIZE,
    fixtures::{
        PoolSim, WalletSim, build_output_stamp, random_block, random_block_with, shared_sk,
        spend_witness,
    },
    primitives::BlockHeight,
};

const WITHIN_EPOCH_ANCHOR_PAIRS: &[(BlockHeight, BlockHeight)] = &[
    (BlockHeight(8), BlockHeight(8)),
    (BlockHeight(0), BlockHeight(1)),
    (BlockHeight(2), BlockHeight(5)),
    (BlockHeight(0), BlockHeight(EPOCH_SIZE - 1)),
];

#[test]
fn merge_stamp_iff_matching_anchors() {
    for &(anchor_height_a, anchor_height_b) in WITHIN_EPOCH_ANCHOR_PAIRS {
        let rng = &mut StdRng::seed_from_u64(0);
        let user_a = WalletSim::random(rng);
        let user_b = WalletSim::random(rng);
        let mut pool = PoolSim::genesis(rng);

        pool.advance(
            usize::try_from(anchor_height_a.0 + 1).expect("fits"),
            |_| random_block(rng, 1, 50),
        );
        let anchor_a = pool.anchor();
        let note_a = user_a.random_note(200);
        let (stamp_a, plan_a) = build_output_stamp(rng, anchor_a, note_a);

        let n_between = anchor_height_b.0 - anchor_height_a.0;
        pool.advance(usize::try_from(n_between).expect("fits"), |_| {
            random_block(rng, 1, 50)
        });
        let anchor_b = pool.anchor();
        let note_b = user_b.random_note(300);
        let (stamp_b, plan_b) = build_output_stamp(rng, anchor_b, note_b);

        let result = ProofStamp::merge(
            rng,
            (stamp_a, BTreeSet::from_iter([plan_a.descriptor()])),
            (stamp_b, BTreeSet::from_iter([plan_b.descriptor()])),
        );
        assert_eq!(
            result.is_ok(),
            anchor_height_a == anchor_height_b,
            "merge with anchors {anchor_height_a:?} {anchor_height_b:?}"
        );
    }
}

#[test]
fn plan_prove_rejects_invalid_inputs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);

    let note_a = user.random_note(500);
    let note_b = user.random_note(700);
    pool.mine(random_block_with(
        rng,
        &[vec![note_a.commitment()], vec![note_b.commitment()]],
        50,
    ));
    let height = pool.height();
    let anchor = pool.anchor_at(height);
    let spend_epoch = height.epoch();

    let sp_a = user.fresh_spend(rng, &pool, height, &note_a);
    let sp_b = user.fresh_spend(rng, &pool, height, &note_b);
    let range_a = user.derived_range(rng, &note_a, spend_epoch, 2);
    let range_b = user.derived_range(rng, &note_b, spend_epoch, 2);

    let (rcv_a, theta_a, alpha_a) = spend_witness(rng, &note_a);
    let plan_a = action::Plan::spend(note_a, theta_a, rcv_a, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });

    let (rcv_b, theta_b, alpha_b) = spend_witness(rng, &note_b);
    let plan_b = action::Plan::spend(note_b, theta_b, rcv_b, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });

    let two_spends = || {
        alloc::vec![
            (plan_a.descriptor(), alpha_a, note_a, rcv_a),
            (plan_b.descriptor(), alpha_b, note_b, rcv_b),
        ]
    };

    // Empty plan: no actions at all.
    {
        let plan = Plan::new(alloc::vec![], alloc::vec![], anchor);
        let err = plan.prove(rng, &user.pak, alloc::vec![]).unwrap_err();
        assert!(matches!(err, ProveError::NoActions), "expected NoActions");
    }

    let bundle_a = || (range_a.clone(), sp_a.clone());
    let bundle_b = || (range_b.clone(), sp_b.clone());

    // Too few PCDs: 2 spends, 1 PCD.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![bundle_a()];
        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        assert!(
            matches!(err, ProveError::SpendableMismatch),
            "expected SpendableMismatch"
        );
    }

    // Too many PCDs: 2 spends, 3 PCDs.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![bundle_a(), bundle_b(), bundle_a()];
        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        assert!(
            matches!(err, ProveError::SpendableMismatch),
            "expected SpendableMismatch"
        );
    }

    // Correspondence swap: lengths match, pairing is wrong. SpendBind's
    // `spendable.cm == note.commitment()` check rejects the mismatched lineage.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![bundle_b(), bundle_a()];
        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        let ProveError::ProofFailed(ragu::Error::InvalidWitness(inner)) = err else {
            panic!("expected ProofFailed(InvalidWitness), got {err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "SpendBind: note does not match the spendable lineage"
        );
    }
}

/// `merge` populates `covered_actions` with the covered-actions digest of
/// the merged descriptor list, order-independently.
#[test]
fn merge_populates_covered_actions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user_a = WalletSim::random(rng);
    let user_b = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let anchor = pool.anchor();
    let note_a = user_a.random_note(200);
    let note_b = user_b.random_note(300);
    let (stamp_a, plan_a) = build_output_stamp(rng, anchor, note_a);
    let (stamp_b, plan_b) = build_output_stamp(rng, anchor, note_b);

    let mut descriptors = Vec::<[u8; 64]>::from_iter([plan_a.descriptor(), plan_b.descriptor()]);
    descriptors.sort_unstable();
    let expected = blake2b::action_descriptor_digest(&descriptors);

    let merged = ProofStamp::merge(
        rng,
        (stamp_a, BTreeSet::from_iter([plan_a.descriptor()])),
        (stamp_b, BTreeSet::from_iter([plan_b.descriptor()])),
    )
    .expect("merge");
    // `merge` sorts the concatenated descriptors into canonical order, so the
    // covered-actions digest is independent of the order they were passed in.
    assert_eq!(merged.coverage, expected);
}

/// The honest merge workflow refuses to combine two stamps whose tachygram
/// sets intersect. `MergeStamp` encodes the merged set as the polynomial
/// product of its inputs (a multiset union), but `prove_merge` witnesses the
/// deduplicated set union; the two coincide only for disjoint inputs. An
/// overlap makes `merged == left · right` unsatisfiable, so the product
/// relation fails and no proof is produced.
#[test]
fn merge_rejects_overlapping_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let anchor = pool.anchor();

    // Two output stamps for the same note share their sole tachygram (the note
    // commitment) but carry distinct descriptors (independent trapdoors), so
    // the action sets stay disjoint and the failure isolates to the tachygram
    // product relation.
    let note = wallet.random_note(200);
    let (stamp_a, plan_a) = build_output_stamp(rng, anchor, note);
    let (stamp_b, plan_b) = build_output_stamp(rng, anchor, note);
    assert_eq!(
        stamp_a.tachygrams, stamp_b.tachygrams,
        "tachygram sets must overlap"
    );
    assert_ne!(
        plan_a.descriptor(),
        plan_b.descriptor(),
        "action sets must stay disjoint"
    );

    let err = ProofStamp::merge(
        rng,
        (stamp_a, BTreeSet::from_iter([plan_a.descriptor()])),
        (stamp_b, BTreeSet::from_iter([plan_b.descriptor()])),
    )
    .expect_err("overlapping tachygram sets must not merge");

    let ProveError::MergeFailed(ragu::Error::InvalidWitness(inner)) = err else {
        panic!("expected MergeFailed(InvalidWitness), got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "poly product: product identity fails at challenge"
    );
}

/// A malicious prover could execute `MergeStamp` to prove a merge of
/// intersecting sets, but no verifier will accept such a proof.
#[test]
fn verify_rejects_maliciously_merged_overlapping_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let anchor = pool.anchor();

    let note = wallet.random_note(200);
    let (stamp_a, plan_a) = build_output_stamp(rng, anchor, note);
    let (stamp_b, plan_b) = build_output_stamp(rng, anchor, note);
    assert_eq!(
        stamp_a.tachygrams, stamp_b.tachygrams,
        "tachygram sets must overlap"
    );

    let app = &*PROOF_SYSTEM;

    let digest_a = plan_a.descriptor().digest().expect("action digest");
    let digest_b = plan_b.descriptor().digest().expect("action digest");

    let left_acts = ActionSetPoly::from_iter([digest_a]);
    let right_acts = ActionSetPoly::from_iter([digest_b]);
    let left_tg = stamp_a
        .tachygrams
        .iter()
        .copied()
        .collect::<TachygramSetPoly>();
    let right_tg = stamp_b
        .tachygrams
        .iter()
        .copied()
        .collect::<TachygramSetPoly>();

    let left_pcd =
        stamp_a
            .proof
            .carry::<StampHeader>((left_acts.commit(), left_tg.commit(), stamp_a.anchor));
    let right_pcd = stamp_b.proof.carry::<StampHeader>((
        right_acts.commit(),
        right_tg.commit(),
        stamp_b.anchor,
    ));

    // The malicious witness: the shared tachygram appears twice, so the merged
    // set polynomial equals `left · right` and the product relation holds. The
    // action sets are disjoint, so their set and multiset unions coincide.
    let merged_acts = ActionSetPoly::from_iter([digest_a, digest_b]);
    let malicious_merged_tg = stamp_a
        .tachygrams
        .iter()
        .chain(stamp_b.tachygrams.iter())
        .copied()
        .collect::<TachygramSetPoly>();

    let proof = {
        let (pcd, ()) = app
            .fuse(
                rng,
                MergeStamp,
                (
                    (left_acts, left_tg),
                    (merged_acts, malicious_merged_tg),
                    (right_acts, right_tg),
                ),
                left_pcd,
                right_pcd,
            )
            .expect("multiset merge must prove");
        Box::new(
            app.rerandomize(pcd, rng)
                .expect("rerandomize")
                .proof()
                .clone(),
        )
    };

    // The published stamp must bear a canonical deduplicated tachygram vector,
    // or it will be rejected at deserialization.
    let malicious_stamp = ProofStamp {
        coverage: blake2b::action_descriptor_digest(&Vec::<[u8; 64]>::from_iter(
            BTreeSet::from_iter([plan_a.descriptor(), plan_b.descriptor()]),
        )),
        anchor,
        tachygrams: stamp_a
            .tachygrams
            .union(&stamp_b.tachygrams)
            .copied()
            .collect(),
        proof,
    };

    let read_malicious_stamp = {
        let mut buf = Vec::new();
        malicious_stamp
            .write(&mut buf)
            .expect("write malicious stamp");
        ProofStamp::read(&*buf).expect("malicious stamp is wire-valid")
    };
    assert_eq!(read_malicious_stamp.tachygrams, malicious_stamp.tachygrams);

    // The malicious stamp will be rejected at verification, since the canonical
    // tachygram vector does not represent the multiset union necessary to
    // verify the malicious proof.
    let err = read_malicious_stamp
        .verify(rng, &[plan_a.descriptor(), plan_b.descriptor()])
        .expect_err("multiset-backed proof must not verify against the deduplicated set");
    let VerificationError::Disproved = err else {
        panic!("expected Disproved, got {err:?}");
    };
}

/// Bundle-validity rule 9 requires a proof stamp's tachygrams to be
/// distinct, not merely sorted; `read` must reject an adjacent duplicate
/// even though the sequence is non-decreasing.
#[test]
fn read_rejects_duplicate_tachygrams() {
    let tg = Tachygram::from(Fp::ONE);

    let mut buf = Vec::new();
    buf.extend_from_slice(&[0u8; 32]); // covered actions digest
    Anchor(Fp::ZERO).write(&mut buf).expect("write anchor");
    serialization::write_fp_list(&mut buf, &[Fp::from(tg), Fp::from(tg)])
        .expect("write tachygrams");

    let err = ProofStamp::read(&*buf).expect_err("duplicate tachygrams must be rejected");
    assert_eq!(err.to_string(), "tachygrams are not unique");
}

/// A strictly increasing tachygram sequence is unaffected by the
/// distinctness check.
#[test]
fn read_accepts_distinct_sorted_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let note = wallet.random_note(200);
    let (stamp, _plan) = build_output_stamp(rng, pool.anchor(), note);

    let mut buf = Vec::new();
    stamp.write(&mut buf).expect("write");
    ProofStamp::read(&*buf).expect("distinct sorted tachygrams must be accepted");
}

/// `hStampActionsTachyon` survives a `write`/`read` round-trip.
#[test]
fn covered_actions_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let note = wallet.random_note(200);
    let (stamp, _plan) = build_output_stamp(rng, pool.anchor(), note);

    let mut buf = Vec::new();
    stamp.write(&mut buf).expect("write");
    let decoded = ProofStamp::read(&*buf).expect("read");

    assert_eq!(decoded.coverage, stamp.coverage);
    assert_eq!(decoded.anchor, stamp.anchor);
    assert_eq!(decoded.tachygrams, stamp.tachygrams);
}
