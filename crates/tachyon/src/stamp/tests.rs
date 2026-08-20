#![allow(clippy::panic, clippy::too_many_lines, reason = "test code")]

use alloc::{boxed::Box, string::ToString as _, vec, vec::Vec};

use ff::Field as _;
use group::Group as _;
use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    action,
    constants::EPOCH_SIZE,
    fixtures::{
        PoolSim, WalletSim, anchor_steps_between, build_autonome, build_output_stamp,
        forge_overlapping_merge, random_action, random_block, random_block_with, shared_sk,
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

        pool.advance(anchor_height_a.0 + 1, |_| random_block(rng, 1, 50));
        let anchor_a = pool.anchor();
        let note_a = user_a.random_note(200);
        let (stamp_a, plan_a) = build_output_stamp(rng, anchor_a, note_a);

        let n_between = anchor_height_b.0 - anchor_height_a.0;
        pool.advance(n_between, |_| random_block(rng, 1, 50));
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

    // Correspondence swap: lengths match, pairing is wrong. Each pair is
    // internally consistent, so SpendBind binds it; the plan's note is the
    // odd one out, and SpendStamp's `note.commitment() == cm` check catches
    // it when the action is proven.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![bundle_b(), bundle_a()];
        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        let ProveError::ProofFailed(ragu::Error::InvalidWitness(inner)) = err else {
            panic!("expected ProofFailed(InvalidWitness), got {err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "SpendStamp: note does not match the spend"
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

/// Reusing a note as an output collides on both of its tachygrams, since the
/// commitment and the pad are each derived from the note's fields. The
/// nullifier-side analog is [`double_spend_cannot_aggregate`]; both reuse modes
/// are caught the same way once the collision lands in the tachygram set.
#[test]
fn double_output_cannot_aggregate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let anchor = pool.anchor();

    // Two output stamps for the same note carry the same commitment tachygram
    // but distinct descriptors (independent trapdoors), so the action sets stay
    // disjoint and the collision isolates to the tachygrams.
    let note = wallet.random_note(200);
    let (stamp_a, plan_a) = build_output_stamp(rng, anchor, note);
    let (stamp_b, plan_b) = build_output_stamp(rng, anchor, note);
    assert_eq!(
        stamp_a.tachygrams, stamp_b.tachygrams,
        "reused output commitment must collide"
    );
    assert_ne!(
        plan_a.descriptor(),
        plan_b.descriptor(),
        "action descriptors stay distinct"
    );

    let descriptors_a = BTreeSet::from_iter([plan_a.descriptor()]);
    let descriptors_b = BTreeSet::from_iter([plan_b.descriptor()]);

    // The honest merge refuses the overlap on the tachygram-set product relation.
    {
        let merge_err = ProofStamp::merge(
            rng,
            (stamp_a.clone(), descriptors_a.clone()),
            (stamp_b.clone(), descriptors_b.clone()),
        )
        .expect_err("overlapping tachygrams must not merge");
        let ProveError::MergeFailed(ragu::Error::InvalidWitness(inner)) = merge_err else {
            panic!("expected MergeFailed(InvalidWitness), got {merge_err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "MergeStamp: merged tachygram set must be the product of left and right tachygram sets"
        );
    }

    let evil_pcd = forge_overlapping_merge(
        rng,
        (&stamp_a, &Vec::from_iter(descriptors_a.clone())),
        (&stamp_b, &Vec::from_iter(descriptors_b.clone())),
    );

    let all_descriptors: Vec<action::Descriptor> =
        descriptors_a.union(&descriptors_b).copied().collect();

    // Publish the forgery as a coherent stamp: canonical deduplicated tachygrams
    // and the covered-actions digest over the merged descriptors, so `covers`
    // accepts it and only proof verification rejects it.
    let coverage = {
        let mut desc_bytes: Vec<[u8; 64]> = all_descriptors.iter().copied().collect();
        desc_bytes.sort_unstable();
        blake2b::action_descriptor_digest(&desc_bytes)
    };
    let tachygrams: BTreeSet<Tachygram> = stamp_a
        .tachygrams
        .union(&stamp_b.tachygrams)
        .copied()
        .collect();
    let stamp = ProofStamp {
        coverage,
        anchor: evil_pcd.data().2,
        tachygram_set: tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit(),
        tachygrams,
        proof: Box::new(evil_pcd.proof().clone()),
    };
    let digests: Vec<ActionDigest> = all_descriptors
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .collect();
    assert!(
        !stamp
            .verify_proof(rng, digests)
            .expect("proof system verification"),
        "multiset-backed proof must not verify against the deduplicated set"
    );
}

/// Reusing a note as a spend collides on the nullifiers: nullifiers are
/// independent of the spend randomization, so two autonome bundles spending one
/// note carry distinct action descriptors yet identical spend nullifiers. The
/// nullifier-side analog of [`double_output_cannot_aggregate`]: the collision
/// is caught by the tachygram set, not by action-descriptor uniqueness.
#[test]
fn double_spend_cannot_aggregate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let spend = wallet.random_note(1000);
    let output_a = wallet.random_note(700);
    let output_b = wallet.random_note(600);

    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(rng, &[vec![spend.commitment()]], 50));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    // Two spendable lineages for the SAME note produce identical nullifiers.
    let init_a = wallet.spendable_init(rng, &spend, &pool, cm_height);
    let sp_a = wallet.lift_over_creation_epoch(rng, &pool, &spend, cm_height, init_a);
    let init_b = wallet.spendable_init(rng, &spend, &pool, cm_height);
    let sp_b = wallet.lift_over_creation_epoch(rng, &pool, &spend, cm_height, init_b);
    let anchor = sp_a.data().2;
    assert_eq!(anchor, sp_b.data().2, "same-note lifts share an anchor");

    let spend_epoch = cm_height.epoch().next();
    let autonome_a = wallet.autonome(
        rng,
        anchor,
        vec![(spend, sp_a, spend_epoch)],
        vec![output_a],
    );
    let autonome_b = wallet.autonome(
        rng,
        anchor,
        vec![(spend, sp_b, spend_epoch)],
        vec![output_b],
    );

    let stamp_a = autonome_a.stamp.clone();
    let stamp_b = autonome_b.stamp.clone();

    let descriptors_a: BTreeSet<action::Descriptor> = autonome_a
        .actions
        .iter()
        .map(action::Action::descriptor)
        .collect();
    let descriptors_b: BTreeSet<action::Descriptor> = autonome_b
        .actions
        .iter()
        .map(action::Action::descriptor)
        .collect();
    assert!(
        descriptors_a.is_disjoint(&descriptors_b),
        "independent randomization gives distinct descriptors"
    );
    assert!(
        !stamp_a.tachygrams.is_disjoint(&stamp_b.tachygrams),
        "same-note spends share their nullifiers"
    );

    // The honest merge refuses the overlap on the tachygram-set product relation.
    {
        let merge_err = ProofStamp::merge(
            rng,
            (stamp_a.clone(), descriptors_a.clone()),
            (stamp_b.clone(), descriptors_b.clone()),
        )
        .expect_err("shared nullifiers must not merge");
        let ProveError::MergeFailed(ragu::Error::InvalidWitness(inner)) = merge_err else {
            panic!("expected MergeFailed(InvalidWitness), got {merge_err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "MergeStamp: merged tachygram set must be the product of left and right tachygram sets"
        );
    }

    let evil_pcd = forge_overlapping_merge(
        rng,
        (&stamp_a, &Vec::from_iter(descriptors_a.clone())),
        (&stamp_b, &Vec::from_iter(descriptors_b.clone())),
    );

    let all_descriptors: Vec<action::Descriptor> =
        descriptors_a.union(&descriptors_b).copied().collect();

    // Publish the forgery as a coherent stamp: the covered-actions digest over
    // the merged descriptors, and the canonical deduplicated nullifier set that
    // cannot reconstruct the doubled multiset the proof commits to.
    let coverage = {
        let mut desc_bytes: Vec<[u8; 64]> = all_descriptors.iter().copied().collect();
        desc_bytes.sort_unstable();
        blake2b::action_descriptor_digest(&desc_bytes)
    };
    let tachygrams: BTreeSet<Tachygram> = stamp_a
        .tachygrams
        .union(&stamp_b.tachygrams)
        .copied()
        .collect();
    let stamp = ProofStamp {
        coverage,
        anchor: evil_pcd.data().2,
        tachygram_set: tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit(),
        tachygrams,
        proof: Box::new(evil_pcd.proof().clone()),
    };

    let digests: Vec<ActionDigest> = all_descriptors
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .collect();
    assert!(
        !stamp
            .verify_proof(rng, digests)
            .expect("proof system verification"),
        "doubled-nullifier proof must not verify"
    );
}

/// A stamp cannot cover the same action twice. The honest merge refuses it on
/// the action-set product relation (the two contributors share the descriptor).
/// A forced-fuse forgery bypasses that, but every action carries a tachygram,
/// so the doubled action doubles its tachygram: verifying against `[d, d]`
/// matches the action accumulator while the published deduplicated tachygram
/// set fails to reconstruct the doubled one, so the proof is `Disproved`. The
/// wire-level duplicate tachygram is caught by
/// [`read_rejects_duplicate_tachygrams`].
#[test]
fn cannot_forge_stamp_covering_duplicated_action() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let anchor = pool.anchor();

    // One output stamp counted twice: both contributors share the descriptor.
    let note = wallet.random_note(200);
    let (output_stamp, plan) = build_output_stamp(rng, anchor, note);
    let descriptors = BTreeSet::from_iter([plan.descriptor()]);

    // The honest merge refuses the shared action on the action-set product
    // relation (checked before the tachygram product).
    {
        let merge_err = ProofStamp::merge(
            rng,
            (output_stamp.clone(), descriptors.clone()),
            (output_stamp.clone(), descriptors.clone()),
        )
        .expect_err("a duplicated action must not merge");
        let ProveError::MergeFailed(ragu::Error::InvalidWitness(inner)) = merge_err else {
            panic!("expected MergeFailed(InvalidWitness), got {merge_err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "MergeStamp: merged action set must be the product of left and right action sets"
        );
    }

    let evil_pcd = forge_overlapping_merge(
        rng,
        (&output_stamp, &Vec::from_iter(descriptors.clone())),
        (&output_stamp, &Vec::from_iter(descriptors.clone())),
    );

    let all_descriptors: Vec<action::Descriptor> = descriptors
        .iter()
        .chain(descriptors.iter())
        .copied()
        .collect();

    // Publish the forgery as a coherent stamp: the covered-actions digest over
    // the duplicated action, and the canonical deduplicated tachygram set that
    // cannot reconstruct the doubled multiset the proof commits to.
    let coverage = {
        let mut desc_bytes: Vec<[u8; 64]> = all_descriptors.iter().copied().collect();
        desc_bytes.sort_unstable();
        blake2b::action_descriptor_digest(&desc_bytes)
    };
    let tachygrams: BTreeSet<Tachygram> = output_stamp.tachygrams.iter().copied().collect();
    let stamp = ProofStamp {
        coverage,
        anchor: evil_pcd.data().2,
        tachygram_set: tachygrams
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit(),
        tachygrams,
        proof: Box::new(evil_pcd.proof().clone()),
    };

    // Verifying against the doubled descriptors makes the action accumulator
    // match; only the deduplicated tachygram set fails to reconstruct the
    // doubled tachygram the proof commits to.
    let digests: Vec<ActionDigest> = all_descriptors
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .collect();
    assert!(
        !stamp
            .verify_proof(rng, digests)
            .expect("proof system verification"),
        "a stamp covering a duplicated action must not verify"
    );
}

/// `verify_proof` checks the proof against exactly the multiset it is handed:
/// the deduplicated `{d}` matches the single-action proof, while the true
/// `[d, d]` reconstructs `(x−d)²` and does not. Detecting a duplicate is the
/// caller's obligation.
#[test]
fn verify_cannot_distinguish_a_deduplicated_duplicate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let anchor = pool.anchor();

    let note = wallet.random_note(200);
    let (stamp, plan) = build_output_stamp(rng, anchor, note);
    let descriptor = plan.descriptor();

    // Deduplicated to one action, it matches the single-action proof.
    let single = descriptor.digest().expect("action digest");
    assert!(
        stamp
            .verify_proof(rng, [single])
            .expect("proof system verification"),
        "the single covered action verifies"
    );

    // The true multiset is a different action polynomial: (x−d)² ≠ (x−d).
    assert!(
        !stamp
            .verify_proof(rng, [single, single])
            .expect("proof system verification"),
        "the doubled action must not verify"
    );
}

/// `verify_proof` reconstructs the action polynomial from the action digests it
/// is given, as a multiset: the exact covered actions verify (in any order),
/// and any deviation — a dropped, duplicated, extra, or substituted action —
/// reconstructs a different polynomial and does not verify.
#[test]
fn verify_proof_action_multiset_invariants() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let stamped = build_autonome(rng, &wallet, 1000, 700);

    let digests: Vec<ActionDigest> = stamped
        .actions
        .iter()
        .map(|action| action.descriptor().digest().expect("action digest"))
        .collect();

    // Permutation accepts.
    assert!(
        stamped
            .stamp
            .verify_proof(rng, [digests[1], digests[0]])
            .expect("proof system verification"),
        "permuted actions must verify"
    );

    // Drop rejects.
    {
        let mut dropped = digests.clone();
        dropped.pop();
        assert!(
            !stamped
                .stamp
                .verify_proof(rng, dropped)
                .expect("proof system verification"),
            "dropped action must not verify"
        );
    }

    // Duplicate rejects.
    {
        let mut duplicated = digests.clone();
        duplicated.push(digests[0]);
        assert!(
            !stamped
                .stamp
                .verify_proof(rng, duplicated)
                .expect("proof system verification"),
            "duplicated action must not verify"
        );
    }

    // Foreign-extra rejects.
    {
        let mut extended = digests.clone();
        extended.push(
            random_action(rng)
                .descriptor()
                .digest()
                .expect("action digest"),
        );
        assert!(
            !stamped
                .stamp
                .verify_proof(rng, extended)
                .expect("proof system verification"),
            "extra action must not verify"
        );
    }

    // Replace-with-foreign rejects.
    {
        let mut replaced = digests;
        replaced[0] = random_action(rng)
            .descriptor()
            .digest()
            .expect("action digest");
        assert!(
            !stamped
                .stamp
                .verify_proof(rng, replaced)
                .expect("proof system verification"),
            "replaced action must not verify"
        );
    }
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
    TachygramSetPoly::from_iter([tg])
        .commit()
        .write(&mut buf)
        .expect("write tachygram set commitment");
    serialization::write_compactsize(&mut buf, 2).expect("write tachygram count");
    serialization::write_fp(&mut buf, &Fp::from(tg)).expect("write tachygram");
    serialization::write_fp(&mut buf, &Fp::from(tg)).expect("write tachygram");

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
    assert_eq!(decoded.tachygram_set, stamp.tachygram_set);
    assert_eq!(decoded.tachygrams, stamp.tachygrams);
}

/// An honest stamp's carried commitment matches its published tachygrams.
#[test]
fn accumulating_accepts_honest_stamp() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let note = wallet.random_note(200);
    let (stamp, _plan) = build_output_stamp(rng, pool.anchor(), note);

    assert!(stamp.is_accumulating());
}

/// A carried commitment over the wrong tachygrams is rejected, and the
/// rejection reaches proof verification.
#[test]
fn accumulating_rejects_mismatched_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let note = wallet.random_note(200);
    let (honest, plan) = build_output_stamp(rng, pool.anchor(), note);

    // Publish the real tachygrams under a commitment to a different set.
    let other = Tachygram::from(Fp::random(&mut *rng));
    let forged = ProofStamp {
        tachygram_set: TachygramSetPoly::from_iter([other]).commit(),
        ..honest
    };

    assert!(!forged.is_accumulating());
    assert!(
        !forged
            .verify_proof(rng, [plan.digest().expect("valid plan")])
            .expect("verify"),
        "verification must reject an unconfirmed commitment"
    );
}

/// A lift lands on the anchor the chain itself produces, and leaves everything
/// but the anchor and the proof untouched.
#[test]
fn lift_lands_on_chain_anchor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(1, |_| random_block(rng, 1, 4));
    let stamp_height = pool.height();
    let note = wallet.random_note(200);
    let (stamp, plan) = build_output_stamp(rng, pool.anchor_at(stamp_height), note);
    let second_note = wallet.random_note(300);
    let (second_stamp, second_plan) =
        build_output_stamp(rng, pool.anchor_at(stamp_height), second_note);

    // A mix of stamp-bearing and empty blocks, so both link kinds are exercised.
    pool.advance(2, |_| random_block(rng, 1, 3));
    pool.advance(1, |_| random_block(rng, 1, 0));
    pool.advance(1, |_| random_block(rng, 1, 2));
    let target_height = pool.height();

    let steps = anchor_steps_between(
        &pool,
        stamp_height.next().expect("height < max")..=target_height,
    );
    assert!(
        steps.iter().any(|step| step.is_empty_block()),
        "the chain must cover the empty block"
    );

    // `advance` predicts the same anchor the proof lands on, so a caller can
    // pick links without proving.
    let epoch = stamp_height.epoch();
    let predicted = steps
        .iter()
        .fold(stamp.anchor, |anchor, step| step.advance(anchor, epoch));
    assert_eq!(predicted, pool.anchor_at(target_height));

    let segment = AnchorSegment::prove(
        rng,
        stamp.anchor,
        epoch,
        pool.anchor_at(target_height),
        &steps,
    )
    .expect("segment");

    let before = stamp.clone();
    let lifted = ProofStamp::lift(
        rng,
        (stamp, BTreeSet::from_iter([plan.descriptor()])),
        &segment,
    )
    .expect("lift");

    assert_eq!(
        lifted.anchor,
        pool.anchor_at(target_height),
        "lift must land on the chain's anchor at the target height"
    );
    assert_eq!(lifted.coverage, before.coverage, "coverage survives a lift");
    assert_eq!(
        lifted.tachygrams, before.tachygrams,
        "tachygrams survive a lift"
    );
    assert_eq!(
        lifted.tachygram_set, before.tachygram_set,
        "the tachygram commitment survives a lift"
    );

    // The lifted proof still verifies against the actions it covered before.
    assert!(
        lifted
            .verify_proof(rng, [plan.digest().expect("valid plan")])
            .expect("verify"),
        "a lifted stamp must still prove its own actions"
    );

    let lifted_second = ProofStamp::lift(
        rng,
        (
            second_stamp,
            BTreeSet::from_iter([second_plan.descriptor()]),
        ),
        &segment,
    )
    .expect("reuse segment");
    assert_eq!(
        lifted_second.anchor,
        pool.anchor_at(target_height),
        "a segment proof can be reused for another stamp at the same anchor"
    );
}

/// Lifting is what lets stamps built at different heights merge: the same pair
/// that `merge` rejects on mismatched anchors succeeds once one side is lifted.
#[test]
fn lift_enables_merge_across_anchors() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(1, |_| random_block(rng, 1, 4));
    let early_height = pool.height();
    let note_a = wallet.random_note(200);
    let (stamp_a, plan_a) = build_output_stamp(rng, pool.anchor_at(early_height), note_a);

    pool.advance(3, |_| random_block(rng, 1, 2));
    let late_height = pool.height();
    let note_b = wallet.random_note(300);
    let (stamp_b, plan_b) = build_output_stamp(rng, pool.anchor_at(late_height), note_b);

    let descriptors_a = BTreeSet::from_iter([plan_a.descriptor()]);
    let descriptors_b = BTreeSet::from_iter([plan_b.descriptor()]);

    // Mismatched anchors: no merge.
    assert!(
        ProofStamp::merge(
            rng,
            (stamp_a.clone(), descriptors_a.clone()),
            (stamp_b.clone(), descriptors_b.clone()),
        )
        .is_err(),
        "stamps at different anchors must not merge"
    );

    let steps = anchor_steps_between(
        &pool,
        early_height.next().expect("height < max")..=late_height,
    );
    let segment = AnchorSegment::prove(
        rng,
        stamp_a.anchor,
        early_height.epoch(),
        stamp_b.anchor,
        &steps,
    )
    .expect("segment");
    let lifted_a = ProofStamp::lift(rng, (stamp_a, descriptors_a.clone()), &segment).expect("lift");
    assert_eq!(
        lifted_a.anchor, stamp_b.anchor,
        "lift must reach b's anchor"
    );

    let merged = ProofStamp::merge(
        rng,
        (lifted_a, descriptors_a.clone()),
        (stamp_b, descriptors_b.clone()),
    )
    .expect("merge after lift");

    let digests = [
        plan_a.digest().expect("valid plan"),
        plan_b.digest().expect("valid plan"),
    ];
    assert!(
        merged.verify_proof(rng, digests).expect("verify"),
        "the merged stamp must cover both sides' actions"
    );
    assert!(
        merged.is_covering(descriptors_a.union(&descriptors_b).copied()),
        "the merged coverage digest must span both descriptor sets"
    );
}

/// Invalid steps and unusable segment shapes fail before stamp lifting.
#[test]
fn lift_rejects_unusable_segments() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(1, |_| random_block(rng, 1, 4));
    let stamp_height = pool.height();
    let note = wallet.random_note(200);
    let (stamp, plan) = build_output_stamp(rng, pool.anchor_at(stamp_height), note);
    let descriptors = BTreeSet::from_iter([plan.descriptor()]);

    let identity = TachygramSetCommit::from(pasta_curves::Eq::identity());
    let step_err = AnchorStep::stamp(identity).unwrap_err();
    assert!(
        matches!(step_err, AnchorStepError::IdentityTachygramSet),
        "identity commitments must be refused, got {step_err}"
    );

    let empty_err =
        AnchorSegment::prove(rng, stamp.anchor, stamp_height.epoch(), stamp.anchor, &[])
            .unwrap_err();
    assert!(
        matches!(empty_err, AnchorSegmentError::Empty),
        "an empty segment must be refused, got {empty_err}"
    );

    // The first block of epoch 1 includes a `next_epoch` transition that an
    // intra-epoch AnchorSegment cannot express, so its real chain endpoint
    // cannot be reached by folding only that block's steps.
    while pool.height() < BlockHeight(EPOCH_SIZE - 1) {
        pool.advance(1, |_| random_block(rng, 1, 1));
    }
    let pre_boundary = pool.anchor();
    pool.advance(1, |_| random_block(rng, 1, 2));
    let epoch_first = pool.height();
    let steps = anchor_steps_between(&pool, epoch_first..=epoch_first);
    let boundary_err = AnchorSegment::prove(
        rng,
        pre_boundary,
        epoch_first.epoch(),
        pool.anchor_at(epoch_first),
        &steps,
    )
    .unwrap_err();
    assert!(
        matches!(boundary_err, AnchorSegmentError::EndMismatch { .. }),
        "a segment that skips the epoch transition must be refused, got {boundary_err}"
    );

    let wrong_start = Anchor::default();
    let wrong_steps = [AnchorStep::empty_block()];
    let wrong_segment = AnchorSegment::prove(
        rng,
        wrong_start,
        EpochIndex(0),
        wrong_steps[0].advance(wrong_start, EpochIndex(0)),
        &wrong_steps,
    )
    .expect("valid segment at the wrong start");
    let start_err = ProofStamp::lift(rng, (stamp, descriptors), &wrong_segment).unwrap_err();
    assert!(
        matches!(start_err, ProveError::LiftStartMismatch { .. }),
        "a segment rooted away from the stamp must be refused, got {start_err}"
    );
}
