extern crate alloc;

use alloc::{boxed::Box, collections::BTreeSet, string::ToString as _, vec, vec::Vec};

use ff::Field as _;
use pasta_curves::Fp;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, Anchor, BlockHeight, CompactSize, EpochIndex, ProofStamp, Tachygram,
    TachygramSetPoly, action,
    constants::EPOCH_SIZE,
    digest::blake2b,
    stamp::{Plan, ProveError},
};

use crate::fixtures::{
    PoolSim, WalletSim, build_anchor_chain_pcd, build_autonome, build_output_stamp,
    forge_overlapping_merge, random_action, random_block, random_block_with, shared_sk,
    spend_witness,
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
    let anchor = pool.block(height).anchor();
    let spend_epoch = height.epoch();

    let sp_a = user.fresh_spend(rng, &pool, height, &note_a);
    let sp_b = user.fresh_spend(rng, &pool, height, &note_b);
    let spend_end = EpochIndex(spend_epoch.0 + 2);
    let range_a = user.derivation_pcd(rng, note_a, spend_epoch, spend_end);
    let range_b = user.derivation_pcd(rng, note_b, spend_epoch, spend_end);

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
        let ProveError::MissingPcd(reason) = err else {
            panic!("expected MissingPcd, got {err:?}");
        };
        assert_eq!(reason.to_string(), "no proof for no planned actions");
    }

    let bundle_a = || (range_a.clone(), sp_a.clone());
    let bundle_b = || (range_b.clone(), sp_b.clone());

    // Too few PCDs: 2 spends, 1 PCD.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![bundle_a()];

        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        let ProveError::MissingPcd(reason) = err else {
            panic!("expected MissingPcd, got {err:?}");
        };
        assert_eq!(
            reason.to_string(),
            "cannot prove 2 spend actions with 1 spendbind inputs"
        );
    }

    // Too many PCDs: 2 spends, 3 PCDs.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![bundle_a(), bundle_b(), bundle_a()];

        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        let ProveError::MissingPcd(reason) = err else {
            panic!("expected MissingPcd, got {err:?}");
        };
        assert_eq!(
            reason.to_string(),
            "cannot prove 2 spend actions with 3 spendbind inputs"
        );
    }

    // Correspondence swap: lengths match, pairing is wrong. The spend's note
    // key rebuilds a covering sequence that cannot match the mispaired
    // derivation's commitment, so SpendBind rejects.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![bundle_b(), bundle_a()];
        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(reason)) = err else {
            panic!("expected ProofFailed(InvalidWitness), got {err:?}");
        };
        assert_eq!(
            reason.to_string(),
            "SpendBind: covering sequence does not match header"
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
        let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner)) = merge_err else {
            panic!("expected ProofFailed(InvalidWitness), got {merge_err:?}");
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
    let sp_a = wallet.lift_to_epoch(rng, &pool, &spend, init_a, cm_height.epoch().next());
    let init_b = wallet.spendable_init(rng, &spend, &pool, cm_height);
    let sp_b = wallet.lift_to_epoch(rng, &pool, &spend, init_b, cm_height.epoch().next());
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
        let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner)) = merge_err else {
            panic!("expected ProofFailed(InvalidWitness), got {merge_err:?}");
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
        let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner)) = merge_err else {
            panic!("expected ProofFailed(InvalidWitness), got {merge_err:?}");
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
    let rng = &mut StdRng::seed_from_u64(0);

    let anchor = Anchor::from(Fp::random(&mut *rng));
    let tg = Tachygram::from(Fp::random(&mut *rng));
    let tg_set = [tg, tg];

    let mut buf = Vec::new();
    {
        buf.extend_from_slice(&[0u8; 32]); // dummy actions digest
        anchor.write(&mut buf).expect("write anchor");
        TachygramSetPoly::from_iter(tg_set)
            .commit()
            .write(&mut buf)
            .expect("write tachygram set commitment");

        CompactSize::from(u64::try_from(tg_set.len()).expect("tachygram count"))
            .write(&mut buf)
            .expect("write tachygram count");

        for write_tg in tg_set {
            write_tg.write(&mut buf).expect("write tachygram");
        }
    }

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

    let mut buf: Vec<u8> = Vec::new();
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

    assert_eq!(
        TachygramSetPoly::from_iter(stamp.tachygrams.clone()).commit(),
        stamp.tachygram_set
    );
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

    assert_ne!(
        TachygramSetPoly::from_iter(forged.tachygrams.clone()).commit(),
        forged.tachygram_set.clone()
    );
    assert!(
        !forged
            .verify_proof(rng, [plan.digest().expect("valid plan")])
            .expect("verify"),
        "verification must reject an unconfirmed commitment"
    );
}

/// A lift moves the anchor to the segment's end and leaves the stamp's
/// published data alone.
#[test]
fn lift_advances_a_stamp_anchor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(3, |_| random_block(rng, 1, 4));
    let note = wallet.random_note(200);
    let (stamp, _plan) = build_output_stamp(rng, pool.anchor(), note);
    let stamped_at = pool.height();

    pool.advance(2, |_| random_block(rng, 1, 4));
    let lifted_to = pool.height();
    let chain = build_anchor_chain_pcd(rng, &pool, stamped_at.next()..=lifted_to);

    let before = stamp.clone();
    let lifted = stamp
        .prove_lift(rng, [], chain)
        .expect("lift over a within-epoch segment");

    assert_eq!(lifted.anchor, pool.block(lifted_to).anchor());
    assert_eq!(lifted.coverage, before.coverage);
    assert_eq!(lifted.tachygram_set, before.tachygram_set);
    assert_eq!(lifted.tachygrams, before.tachygrams);
}

/// The header the lift rebuilds is the one the original proof was made
/// against, so the lifted stamp still verifies against its covered actions.
#[test]
fn lift_then_verify() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(3, |_| random_block(rng, 1, 4));
    let note = wallet.random_note(200);
    let (stamp, plan) = build_output_stamp(rng, pool.anchor(), note);
    let stamped_at = pool.height();
    let digest = plan.digest().expect("valid plan");

    pool.advance(2, |_| random_block(rng, 1, 4));
    let chain = build_anchor_chain_pcd(rng, &pool, stamped_at.next()..=pool.height());

    let lifted = stamp.prove_lift(rng, [digest], chain).expect("lift");

    assert!(
        lifted.verify_proof(rng, [digest]).expect("verify"),
        "a lifted stamp must verify against the actions it covers"
    );
}

/// A stamp covers the actions of the plan it was proven for, so lifting it
/// over their descriptors reaches the same action set the digest-taking core
/// is given directly, and the result verifies against their digests.
#[test]
fn lift_over_descriptors_then_verify() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(3, |_| random_block(rng, 1, 4));
    let note = wallet.random_note(200);
    let (stamp, covered_plan) = build_output_stamp(rng, pool.anchor(), note);
    let covered_descriptors = BTreeSet::from_iter([covered_plan.descriptor()]);
    let stamped_at = pool.height();

    // The stamps published after this one, each paired with the anchor it
    // absorbs into, which is what an `AnchorSeed` witnesses.
    pool.advance(2, |_| random_block(rng, 1, 4));
    let epoch = pool.height().epoch();
    let following_stamps = (stamped_at.0 + 1..=pool.height().0)
        .flat_map(|height| pool.block(BlockHeight(height)).stamp_commits())
        .scan(stamp.anchor, |anchor_before, tachygram_set| {
            let witness = (*anchor_before, epoch, tachygram_set);
            *anchor_before = anchor_before.next_stamp(epoch, &tachygram_set).unwrap();
            Some(witness)
        })
        .collect();

    let lifted = stamp
        .lift(rng, &covered_descriptors, following_stamps)
        .expect("lift over the covered descriptors");

    assert!(
        lifted
            .verify_proof(rng, [covered_plan.digest().expect("valid plan")])
            .expect("verify"),
        "a lifted stamp must verify against the actions it covers"
    );
}

/// A segment from an unrelated chain does not root at the stamp's anchor.
#[test]
fn lift_rejects_a_foreign_chain() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    pool.advance(3, |_| random_block(rng, 1, 4));

    let note = wallet.random_note(200);
    let (stamp, _plan) = build_output_stamp(rng, pool.anchor(), note);

    let mut foreign = PoolSim::genesis(rng);
    foreign.advance(3, |_| random_block(rng, 1, 4));
    let chain = build_anchor_chain_pcd(rng, &foreign, BlockHeight(1)..=foreign.height());

    stamp
        .prove_lift(rng, [], chain)
        .expect_err("a segment from another chain must not lift a stamp");
}

/// A lift takes the caller's word for the covered action set, so a wrong
/// digest list is caught at verification rather than at prove time.
#[test]
fn lift_rejects_wrong_digests() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(3, |_| random_block(rng, 1, 4));
    let note = wallet.random_note(200);
    let (stamp, plan) = build_output_stamp(rng, pool.anchor(), note);
    let stamped_at = pool.height();
    let digest = plan.digest().expect("valid plan");
    let foreign_digest = random_action(rng).digest().expect("valid action");

    pool.advance(2, |_| random_block(rng, 1, 4));
    let chain = build_anchor_chain_pcd(rng, &pool, stamped_at.next()..=pool.height());

    let lifted = stamp
        .prove_lift(rng, [foreign_digest], chain)
        .expect("the lift itself cannot see the wrong action set");

    assert!(
        !lifted.verify_proof(rng, [digest]).expect("verify"),
        "a stamp lifted under a forged action set must not verify"
    );
}

/// Stamps taken at different anchors cannot merge until one is lifted onto
/// the other's anchor.
#[test]
fn merge_after_lift() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user_a = WalletSim::random(rng);
    let user_b = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(3, |_| random_block(rng, 1, 4));
    let note_a = user_a.random_note(200);
    let (stamp_a, plan_a) = build_output_stamp(rng, pool.anchor(), note_a);
    let height_a = pool.height();

    pool.advance(3, |_| random_block(rng, 1, 4));
    let note_b = user_b.random_note(300);
    let (stamp_b, plan_b) = build_output_stamp(rng, pool.anchor(), note_b);
    let height_b = pool.height();

    let (desc_a, desc_b) = (
        BTreeSet::from_iter([plan_a.descriptor()]),
        BTreeSet::from_iter([plan_b.descriptor()]),
    );

    ProofStamp::merge(
        rng,
        (stamp_a.clone(), desc_a.clone()),
        (stamp_b.clone(), desc_b.clone()),
    )
    .expect_err("mismatched anchors must not merge");

    let chain = build_anchor_chain_pcd(rng, &pool, height_a.next()..=height_b);
    let lifted_a = stamp_a
        .prove_lift(rng, [plan_a.digest().expect("valid plan")], chain)
        .expect("lift onto the later anchor");

    assert_eq!(lifted_a.anchor, stamp_b.anchor);
    ProofStamp::merge(rng, (lifted_a, desc_a), (stamp_b, desc_b))
        .expect("a lifted stamp merges with one at the anchor it was lifted to");
}
