extern crate alloc;

use alloc::{boxed::Box, collections::BTreeSet, string::ToString as _, vec, vec::Vec};

use ff::Field as _;
use pasta_curves::Fp;
use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, Anchor, BlockHeight, CompactSize, ProofStamp, Tachygram, TachygramSetCommit,
    TachygramSetPoly, action,
    constants::EPOCH_SIZE,
    fee,
    stamp::{self, ProveError},
    value,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_autonome, build_lift_span, build_output_plan, build_output_stamp,
    fee_digests, forge_overlapping_merge, random_action, random_block, random_block_with,
    shared_sk, spend_witness, stamp_coverage,
};

const WITHIN_EPOCH_ANCHOR_PAIRS: &[(BlockHeight, BlockHeight)] = &[
    (BlockHeight(8), BlockHeight(8)),
    (BlockHeight(0), BlockHeight(1)),
    (BlockHeight(2), BlockHeight(5)),
    (BlockHeight(0), BlockHeight(EPOCH_SIZE - 1)),
];

#[test]
fn stamp_merge_iff_matching_anchors() {
    for &(anchor_height_a, anchor_height_b) in WITHIN_EPOCH_ANCHOR_PAIRS {
        let rng = &mut StdRng::seed_from_u64(0);
        let user_a = WalletSim::random(rng);
        let user_b = WalletSim::random(rng);
        let mut pool = PoolSim::genesis(rng);

        pool.advance(anchor_height_a.0 + 1, |_| random_block(rng, 1, 50));
        let anchor_a = pool.anchor();
        let note_a = user_a.random_note(200);
        let (stamp_a, plan_a, fee_a) = build_output_stamp(rng, anchor_a, note_a);

        let n_between = anchor_height_b.0 - anchor_height_a.0;
        pool.advance(n_between, |_| random_block(rng, 1, 50));
        let anchor_b = pool.anchor();
        let note_b = user_b.random_note(300);
        let (stamp_b, plan_b, fee_b) = build_output_stamp(rng, anchor_b, note_b);

        let result = stamp_a.merge(
            rng,
            (BTreeSet::from_iter([plan_a.descriptor()]), [fee_a].into()),
            (
                stamp_b,
                BTreeSet::from_iter([plan_b.descriptor()]),
                [fee_b].into(),
            ),
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
    let other = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    // Same value, so swapped notes differ only in their commitments.
    let note_a = user.random_note(500);
    let note_b = user.random_note(500);
    pool.mine(random_block_with(
        rng,
        &[vec![note_a.commitment(), note_b.commitment()]],
        50,
    ));
    let height = pool.height();

    let sp_a = user.fresh_spend(rng, &pool, height, &note_a);
    let sp_b = user.fresh_spend(rng, &pool, height, &note_b);
    let anchor = sp_a.data().2;
    assert_eq!(
        anchor,
        sp_b.data().2,
        "same-stamp spendables share an anchor"
    );

    let (rcv_a, theta_a) = spend_witness(rng);
    let plan_a = action::Plan::spend(note_a, theta_a, rcv_a, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });

    let (rcv_b, theta_b) = spend_witness(rng);
    let plan_b = action::Plan::spend(note_b, theta_b, rcv_b, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });

    let foreign_a = action::Plan::spend(note_a, theta_a, rcv_a, |alpha| {
        other.pak.ak.derive_action_public(&alpha)
    });

    let two_spends = || {
        alloc::vec![
            (plan_a.descriptor(), theta_a, rcv_a),
            (plan_b.descriptor(), theta_b, rcv_b),
        ]
    };
    let max_fee_note = user.random_note(0);
    let fee_digest = fee::Descriptor {
        max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
        value: value::Positive::ZERO,
    }
    .digest()
    .expect("fee digest");

    let zero = value::Positive::ZERO;

    let secret_a = user.secret_pcd(rng, note_a);
    let secret_b = user.secret_pcd(rng, note_b);
    let bundle_a = || (secret_a.clone(), sp_a.clone(), vec![]);
    let bundle_b = || (secret_b.clone(), sp_b.clone(), vec![]);

    // Too few PCDs: 2 spends, 1 PCD.
    {
        let plan = stamp::Plan::new(two_spends(), alloc::vec![], anchor, max_fee_note, zero);
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
        let plan = stamp::Plan::new(two_spends(), alloc::vec![], anchor, max_fee_note, zero);
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

    // Correspondence swap: lengths match, pairing is wrong. Each spend's secret
    // carries another note of the same value, so only `alpha` tells them apart.
    // The swapped actions prove, and the stamp does not verify as the plan's.
    {
        let plan = stamp::Plan::new(two_spends(), alloc::vec![], anchor, max_fee_note, zero);
        let pcds = alloc::vec![bundle_b(), bundle_a()];
        let stamp = plan
            .prove(rng, &user.pak, pcds)
            .expect("swapped spends prove");
        let planned = [
            plan_a.digest().expect("action digest"),
            plan_b.digest().expect("action digest"),
            fee_digest,
        ];
        assert!(
            !stamp
                .verify_proof(rng, planned)
                .expect("proof system verification"),
            "a stamp of swapped notes must not verify as the planned actions"
        );
    }

    // Foreign descriptor: a single spend whose planned `rk` is under another
    // wallet's `ak`. The spend proves under this wallet's `ak`, and the stamp
    // does not verify as the plan's.
    {
        let plan = stamp::Plan::new(
            alloc::vec![(foreign_a.descriptor(), theta_a, rcv_a)],
            alloc::vec![],
            anchor,
            max_fee_note,
            zero,
        );
        let stamp = plan
            .prove(rng, &user.pak, alloc::vec![bundle_a()])
            .expect("foreign spend proves");
        assert!(
            !stamp
                .verify_proof(
                    rng,
                    [foreign_a.digest().expect("action digest"), fee_digest]
                )
                .expect("proof system verification"),
            "a stamp under another ak must not verify as the planned action"
        );
    }
}

/// A spend anchored before the plan's anchor, in the same epoch, lifts to it
/// along anchor spans and merges with an output proved at the plan's anchor.
/// The spans may abut or overlap. Without spans, or with spans that end
/// elsewhere, the spend does not reach the plan's anchor; spans with a gap
/// between them do not lift.
#[test]
fn plan_prove_lifts_a_spend_along_spans() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis(rng);

    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 3));
    let cm_height = pool.height();
    pool.advance(2, |_| random_block(rng, 1, 2));
    let plan_height = pool.height();
    assert_eq!(cm_height.epoch(), plan_height.epoch(), "one epoch");
    let middle = cm_height.next().unwrap();

    let spendable = user.fresh_spend(rng, &pool, cm_height, &note);
    let spend_anchor = spendable.data().2;
    let plan_anchor = pool.block(plan_height).anchor();
    assert_ne!(spend_anchor, plan_anchor, "the spend needs a lift");

    let (rcv, theta) = spend_witness(rng);
    let spend = action::Plan::spend(note, theta, rcv, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });
    let (out_rcv, out_theta, output) = build_output_plan(rng, user.random_note(200));
    let secret = user.secret_pcd(rng, note);
    let max_fee_note = user.random_note(0);
    let prove = |prove_rng: &mut StdRng, spans| {
        stamp::Plan::new(
            vec![(spend.descriptor(), theta, rcv)],
            vec![(output.descriptor(), out_theta, output.note, out_rcv)],
            plan_anchor,
            max_fee_note,
            value::Positive::ZERO,
        )
        .prove(
            prove_rng,
            &user.pak,
            vec![(secret.clone(), spendable.clone(), spans)],
        )
    };
    let digests = [
        spend.digest().expect("action digest"),
        output.digest().expect("action digest"),
        fee::Descriptor {
            max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
            value: value::Positive::ZERO,
        }
        .digest()
        .expect("fee digest"),
    ];

    let one = vec![build_lift_span(rng, &pool, cm_height..=plan_height)];
    let abutting = vec![
        build_lift_span(rng, &pool, cm_height..=cm_height),
        build_lift_span(rng, &pool, middle..=plan_height),
    ];
    let overlapping = vec![
        build_lift_span(rng, &pool, cm_height..=middle),
        build_lift_span(rng, &pool, middle..=plan_height),
    ];
    for (label, spans) in [
        ("one span", one),
        ("abutting spans", abutting),
        ("overlapping spans", overlapping),
    ] {
        let stamp = prove(rng, spans).expect(label);
        assert_eq!(stamp.anchor, plan_anchor, "{label}");
        assert!(
            stamp
                .verify_proof(rng, digests)
                .expect("proof system verification"),
            "{label}: the stamp proves the planned actions at the plan's anchor"
        );
    }

    let short = vec![build_lift_span(rng, &pool, cm_height..=middle)];
    for (label, spans) in [("no spans", vec![]), ("spans ending short", short)] {
        let err = prove(rng, spans).unwrap_err();
        let ProveError::MissingPcd(reason) = err else {
            panic!("{label}: expected MissingPcd, got {err:?}");
        };
        assert_eq!(
            reason.to_string(),
            "spend 0 does not reach the plan's anchor",
            "{label}"
        );
    }

    let gapped = vec![
        build_lift_span(rng, &pool, cm_height..=cm_height),
        build_lift_span(rng, &pool, plan_height..=plan_height),
    ];
    let err = prove(rng, gapped).unwrap_err();
    let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner)) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "ActionLift: actions anchor is neither the span's start nor a member"
    );
}

/// `merge` populates `covered_actions` with the covered-actions digest of
/// the merged descriptor list, order-independently, and keeps the receiver's
/// fee.
#[test]
fn merge_populates_covered_actions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user_a = WalletSim::random(rng);
    let user_b = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let anchor = pool.anchor();
    let note_a = user_a.random_note(200);
    let note_b = user_b.random_note(300);
    let (stamp_a, plan_a, fee_a) = build_output_stamp(rng, anchor, note_a);
    let (stamp_b, plan_b, fee_b) = build_output_stamp(rng, anchor, note_b);

    let mut descriptors = Vec::<[u8; 64]>::from_iter([plan_a.descriptor(), plan_b.descriptor()]);
    descriptors.sort_unstable();
    let expected = stamp_coverage(&descriptors, &[fee_a, fee_b]);

    let receiver_fee = stamp_a.fee;
    let merged = stamp_a
        .merge(
            rng,
            (BTreeSet::from_iter([plan_a.descriptor()]), [fee_a].into()),
            (
                stamp_b,
                BTreeSet::from_iter([plan_b.descriptor()]),
                [fee_b].into(),
            ),
        )
        .expect("merge");
    // `merge` sorts the concatenated descriptors into canonical order, so the
    // covered-actions digest is independent of the order they were passed in.
    assert_eq!(merged.coverage, expected);
    assert_eq!(merged.fee, receiver_fee);
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
    let (stamp_a, plan_a, fee_a) = build_output_stamp(rng, anchor, note);
    let (stamp_b, plan_b, fee_b) = build_output_stamp(rng, anchor, note);
    assert_eq!(
        stamp_a.tachygrams.intersection(&stamp_b.tachygrams).count(),
        2,
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
        let merge_err = stamp_a
            .clone()
            .merge(
                rng,
                (descriptors_a.clone(), [fee_a].into()),
                (stamp_b.clone(), descriptors_b.clone(), [fee_b].into()),
            )
            .expect_err("overlapping tachygrams must not merge");
        let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner)) = merge_err else {
            panic!("expected ProofFailed(InvalidWitness), got {merge_err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets"
        );
    }

    let evil_pcd = forge_overlapping_merge(
        rng,
        (&stamp_a, &Vec::from_iter(descriptors_a.clone()), &[fee_a]),
        (&stamp_b, &Vec::from_iter(descriptors_b.clone()), &[fee_b]),
    );

    let all_descriptors: Vec<action::Descriptor> =
        descriptors_a.union(&descriptors_b).copied().collect();

    // Publish the forgery as a coherent stamp: canonical deduplicated tachygrams
    // and the covered-actions digest over the merged descriptors, so `covers`
    // accepts it and only proof verification rejects it.
    let coverage = {
        let mut desc_bytes: Vec<[u8; 64]> = all_descriptors.iter().copied().collect();
        desc_bytes.sort_unstable();
        stamp_coverage(&desc_bytes, &[fee_a, fee_b])
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
        fee: stamp_a.fee,
    };
    let digests: Vec<ActionDigest> = all_descriptors
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([fee_a, fee_b]))
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
    let sp_a = wallet.spendable_at(rng, &pool, &spend, cm_height.epoch().next().unwrap());
    let sp_b = wallet.spendable_at(rng, &pool, &spend, cm_height.epoch().next().unwrap());
    let anchor = sp_a.data().2;
    assert_eq!(anchor, sp_b.data().2, "same-note lifts share an anchor");

    let autonome_a = wallet.autonome(rng, anchor, vec![(spend, sp_a)], vec![output_a]);
    let autonome_b = wallet.autonome(rng, anchor, vec![(spend, sp_b)], vec![output_b]);

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

    let fees = [autonome_a.fee_descriptor(), autonome_b.fee_descriptor()];
    // The honest merge refuses the overlap on the tachygram-set product relation.
    {
        let merge_err = stamp_a
            .clone()
            .merge(
                rng,
                (descriptors_a.clone(), [fees[0]].into()),
                (stamp_b.clone(), descriptors_b.clone(), [fees[1]].into()),
            )
            .expect_err("shared nullifiers must not merge");
        let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner)) = merge_err else {
            panic!("expected ProofFailed(InvalidWitness), got {merge_err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets"
        );
    }

    let evil_pcd = forge_overlapping_merge(
        rng,
        (&stamp_a, &Vec::from_iter(descriptors_a.clone()), &fees[..1]),
        (&stamp_b, &Vec::from_iter(descriptors_b.clone()), &fees[1..]),
    );

    let all_descriptors: Vec<action::Descriptor> =
        descriptors_a.union(&descriptors_b).copied().collect();

    // Publish the forgery as a coherent stamp: the covered-actions digest over
    // the merged descriptors, and the canonical deduplicated nullifier set that
    // cannot reconstruct the doubled multiset the proof commits to.
    let coverage = {
        let mut desc_bytes: Vec<[u8; 64]> = all_descriptors.iter().copied().collect();
        desc_bytes.sort_unstable();
        stamp_coverage(&desc_bytes, &fees)
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
        fee: stamp_a.fee,
    };

    let digests: Vec<ActionDigest> = all_descriptors
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests(fees))
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
    let (output_stamp, plan, fee) = build_output_stamp(rng, anchor, note);
    let descriptors = BTreeSet::from_iter([plan.descriptor()]);
    let fees = BTreeSet::from([fee]);

    // The honest merge refuses the shared action on the action-set product
    // relation (checked before the tachygram product).
    {
        let merge_err = output_stamp
            .clone()
            .merge(
                rng,
                (descriptors.clone(), fees.clone()),
                (output_stamp.clone(), descriptors.clone(), fees),
            )
            .expect_err("a duplicated action must not merge");
        let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner)) = merge_err else {
            panic!("expected ProofFailed(InvalidWitness), got {merge_err:?}");
        };
        assert_eq!(
            inner.to_string(),
            "StampMerge: merged action set must be the product of left and right action sets"
        );
    }

    let evil_pcd = forge_overlapping_merge(
        rng,
        (&output_stamp, &Vec::from_iter(descriptors.clone()), &[fee]),
        (&output_stamp, &Vec::from_iter(descriptors.clone()), &[fee]),
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
        stamp_coverage(&desc_bytes, &[fee])
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
        fee: output_stamp.fee,
    };

    // Verifying against the doubled descriptors makes the action accumulator
    // match; only the deduplicated tachygram set fails to reconstruct the
    // doubled tachygram the proof commits to.
    let digests: Vec<ActionDigest> = all_descriptors
        .iter()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests([fee, fee]))
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
    let (stamp, plan, fee_descriptor) = build_output_stamp(rng, anchor, note);
    let descriptor = plan.descriptor();
    let fee_digest = fee_descriptor.digest().expect("fee digest");

    // Deduplicated to one action, it matches the single-action proof.
    let single = descriptor.digest().expect("action digest");
    assert!(
        stamp
            .verify_proof(rng, [single, fee_digest])
            .expect("proof system verification"),
        "the single covered action verifies"
    );

    // The true multiset is a different action polynomial: (x−d)² ≠ (x−d).
    assert!(
        !stamp
            .verify_proof(rng, [single, single, fee_digest])
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
        .chain([stamped.fee_descriptor().digest().expect("fee digest")])
        .collect();

    // Permutation accepts.
    assert!(
        stamped
            .stamp
            .verify_proof(rng, digests.iter().rev().copied())
            .expect("proof system verification"),
        "permuted actions must verify"
    );

    // Drop rejects.
    for index in [0, digests.len() - 1] {
        let mut dropped = digests.clone();
        dropped.remove(index);
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
        buf.extend_from_slice(&0u64.to_le_bytes()); // fee
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

/// Every covered action publishes tachygrams, so a proof stamp never carries
/// an empty set. `read` rejects the count before reading any member.
#[test]
fn read_rejects_empty_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);

    let anchor = Anchor::from(Fp::random(&mut *rng));

    let mut buf = Vec::new();
    {
        buf.extend_from_slice(&0u64.to_le_bytes()); // fee
        buf.extend_from_slice(&[0u8; 32]); // dummy actions digest
        anchor.write(&mut buf).expect("write anchor");
        TachygramSetCommit::default()
            .write(&mut buf)
            .expect("write tachygram set commitment");

        CompactSize::from(0u64)
            .write(&mut buf)
            .expect("write tachygram count");
    }

    let err = ProofStamp::read(&*buf).expect_err("an empty tachygram set must be rejected");
    assert_eq!(err.to_string(), "no tachygrams");
}

/// The set polynomial carries a constant term alongside its roots, so the
/// members must number fewer than the rank's coefficients. `read` rejects the
/// count before reading any member, so the oversized set is never allocated.
#[test]
fn read_rejects_too_many_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);

    let anchor = Anchor::from(Fp::random(&mut *rng));
    let n_tachygrams = u64::try_from(ProductionRank::num_coeffs()).expect("rank fits u64");

    let mut buf = Vec::new();
    {
        buf.extend_from_slice(&0u64.to_le_bytes()); // fee
        buf.extend_from_slice(&[0u8; 32]); // dummy actions digest
        anchor.write(&mut buf).expect("write anchor");
        TachygramSetCommit::default()
            .write(&mut buf)
            .expect("write tachygram set commitment");

        CompactSize::from(n_tachygrams)
            .write(&mut buf)
            .expect("write tachygram count");
    }

    let err = ProofStamp::read(&*buf).expect_err("an oversized tachygram set must be rejected");
    assert_eq!(err.to_string(), "too many tachygrams");
}

/// A strictly increasing tachygram sequence is unaffected by the
/// distinctness check.
#[test]
fn read_accepts_distinct_sorted_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let note = wallet.random_note(200);
    let (stamp, _plan, _) = build_output_stamp(rng, pool.anchor(), note);

    let mut buf = Vec::new();
    stamp.write(&mut buf).expect("write");
    ProofStamp::read(&*buf).expect("distinct sorted tachygrams must be accepted");
}

/// `hStampCoverageTachyon` and the fee survive a `write`/`read` round-trip.
#[test]
fn covered_actions_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let note = wallet.random_note(200);
    let (stamp, _plan, _) = build_output_stamp(rng, pool.anchor(), note);

    let mut buf: Vec<u8> = Vec::new();
    stamp.write(&mut buf).expect("write");
    let decoded = ProofStamp::read(&*buf).expect("read");

    assert_eq!(decoded.fee, stamp.fee);
    assert_eq!(decoded.coverage, stamp.coverage);
    assert_eq!(decoded.anchor, stamp.anchor);
    assert_eq!(decoded.tachygram_set, stamp.tachygram_set);
    assert_eq!(decoded.tachygrams, stamp.tachygrams);
}

/// An honest stamp's carried commitment matches its published tachygrams.
#[test]
fn honest_stamp_commits_to_its_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let note = wallet.random_note(200);
    let (stamp, _plan, _) = build_output_stamp(rng, pool.anchor(), note);

    assert_eq!(
        TachygramSetPoly::from_iter(stamp.tachygrams.clone()).commit(),
        stamp.tachygram_set
    );
}

/// A carried commitment over the wrong tachygrams is rejected, and the
/// rejection reaches proof verification.
#[test]
fn verify_proof_rejects_mismatched_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let note = wallet.random_note(200);
    let (honest, plan, fee_descriptor) = build_output_stamp(rng, pool.anchor(), note);
    let fee_digest = fee_descriptor.digest().expect("fee digest");

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
            .verify_proof(rng, [plan.digest().expect("valid plan"), fee_digest])
            .expect("verify"),
        "verification must reject an unconfirmed commitment"
    );
}

/// The proof binds `tachygram_set`, not the published `tachygrams`. A stamp
/// publishing a tampered list under its honest commitment verifies, which is
/// what `Bundle::verify_tachygrams` is for.
#[test]
fn proof_alone_does_not_bind_the_published_list() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let note = wallet.random_note(200);
    let (honest, plan, fee_descriptor) = build_output_stamp(rng, pool.anchor(), note);
    let fee_digest = fee_descriptor.digest().expect("fee digest");

    // Swap one published tachygram for another, keeping the count and the
    // carried commitment untouched.
    let mut tampered_list = honest.tachygrams.clone();
    let dropped = *tampered_list.iter().next().expect("a published tachygram");
    tampered_list.remove(&dropped);
    tampered_list.insert(Tachygram::from(Fp::random(&mut *rng)));

    assert_eq!(tampered_list.len(), honest.tachygrams.len());

    let tampered = ProofStamp {
        tachygrams: tampered_list,
        ..honest
    };

    assert_ne!(
        TachygramSetPoly::from_iter(tampered.tachygrams.clone()).commit(),
        tampered.tachygram_set.clone()
    );

    assert!(
        tampered
            .verify_proof(rng, [plan.digest().expect("valid plan"), fee_digest])
            .expect("verify"),
        "the proof is over the carried commitment, which is untouched here"
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
    let (stamp, plan, fee_descriptor) = build_output_stamp(rng, pool.anchor(), note);
    let stamped_at = pool.height();

    pool.advance(2, |_| random_block(rng, 1, 4));
    let lifted_to = pool.height();
    let span = build_lift_span(rng, &pool, stamped_at.next().unwrap()..=lifted_to);

    let before = stamp.clone();
    let lifted = stamp
        .lift(
            rng,
            &BTreeSet::from([plan.descriptor()]),
            &BTreeSet::from([fee_descriptor]),
            vec![span],
        )
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
    let (stamp, plan, fee_descriptor) = build_output_stamp(rng, pool.anchor(), note);
    let stamped_at = pool.height();
    let digest = plan.digest().expect("valid plan");
    let fee_digest = fee_descriptor.digest().expect("fee digest");

    pool.advance(2, |_| random_block(rng, 1, 4));
    let span = build_lift_span(rng, &pool, stamped_at.next().unwrap()..=pool.height());

    let lifted = stamp
        .lift(
            rng,
            &BTreeSet::from([plan.descriptor()]),
            &BTreeSet::from([fee_descriptor]),
            vec![span],
        )
        .expect("lift");

    assert!(
        lifted
            .verify_proof(rng, [digest, fee_digest])
            .expect("verify"),
        "a lifted stamp must verify against the actions it covers"
    );
}

/// A stamp covers the actions of the plan it was proven for, so lifting it
/// over their descriptors rebuilds the action set it was proven against, and
/// the result verifies against their digests.
#[test]
fn lift_over_descriptors_then_verify() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(3, |_| random_block(rng, 1, 4));
    let note = wallet.random_note(200);
    let (stamp, covered_plan, fee_descriptor) = build_output_stamp(rng, pool.anchor(), note);
    let covered_descriptors = BTreeSet::from_iter([covered_plan.descriptor()]);
    let fee_descriptors = BTreeSet::from_iter([fee_descriptor]);
    let stamped_at = pool.height();
    let fee_digest = fee_descriptor.digest().expect("fee digest");

    pool.advance(2, |_| random_block(rng, 1, 4));
    let span = build_lift_span(rng, &pool, stamped_at.next().unwrap()..=pool.height());

    let lifted = stamp
        .lift(rng, &covered_descriptors, &fee_descriptors, vec![span])
        .expect("lift over the covered descriptors");

    assert!(
        lifted
            .verify_proof(
                rng,
                [covered_plan.digest().expect("valid plan"), fee_digest]
            )
            .expect("verify"),
        "a lifted stamp must verify against the actions it covers"
    );
}

/// A span from an unrelated chain neither starts at nor holds the stamp's
/// anchor.
#[test]
fn lift_rejects_a_foreign_span() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);
    pool.advance(3, |_| random_block(rng, 1, 4));

    let note = wallet.random_note(200);
    let (stamp, plan, fee_descriptor) = build_output_stamp(rng, pool.anchor(), note);

    let mut foreign = PoolSim::genesis(rng);
    foreign.advance(3, |_| random_block(rng, 1, 4));
    let span = build_lift_span(rng, &foreign, BlockHeight(1)..=foreign.height());

    let err = stamp
        .lift(
            rng,
            &BTreeSet::from([plan.descriptor()]),
            &BTreeSet::from([fee_descriptor]),
            vec![span],
        )
        .unwrap_err();
    let ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner)) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "StampLift: stamp anchor is neither the span's start nor a member"
    );
}

/// A lift takes the caller's word for the covered action set, so a wrong
/// descriptor list is caught at verification rather than at prove time.
#[test]
fn lift_rejects_wrong_digests() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    pool.advance(3, |_| random_block(rng, 1, 4));
    let note = wallet.random_note(200);
    let (stamp, plan, fee_descriptor) = build_output_stamp(rng, pool.anchor(), note);
    let stamped_at = pool.height();
    let digest = plan.digest().expect("valid plan");
    let foreign = random_action(rng).descriptor();
    let fee_digest = fee_descriptor.digest().expect("fee digest");

    pool.advance(2, |_| random_block(rng, 1, 4));
    let span = build_lift_span(rng, &pool, stamped_at.next().unwrap()..=pool.height());

    let lifted = stamp
        .lift(
            rng,
            &BTreeSet::from([foreign]),
            &BTreeSet::from([fee_descriptor]),
            vec![span],
        )
        .expect("the lift itself cannot see the wrong action set");

    assert!(
        !lifted
            .verify_proof(rng, [digest, fee_digest])
            .expect("verify"),
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
    let (stamp_a, plan_a, fee_a) = build_output_stamp(rng, pool.anchor(), note_a);
    let height_a = pool.height();

    pool.advance(3, |_| random_block(rng, 1, 4));
    let note_b = user_b.random_note(300);
    let (stamp_b, plan_b, fee_b) = build_output_stamp(rng, pool.anchor(), note_b);
    let height_b = pool.height();

    let (desc_a, desc_b) = (
        BTreeSet::from_iter([plan_a.descriptor()]),
        BTreeSet::from_iter([plan_b.descriptor()]),
    );
    let (fee_set_a, fee_set_b) = (BTreeSet::from([fee_a]), BTreeSet::from([fee_b]));

    stamp_a
        .clone()
        .merge(
            rng,
            (desc_a.clone(), fee_set_a.clone()),
            (stamp_b.clone(), desc_b.clone(), fee_set_b.clone()),
        )
        .expect_err("mismatched anchors must not merge");

    let span = build_lift_span(rng, &pool, height_a.next().unwrap()..=height_b);
    let lifted_a = stamp_a
        .lift(rng, &desc_a, &fee_set_a, vec![span])
        .expect("lift onto the later anchor");

    assert_eq!(lifted_a.anchor, stamp_b.anchor);
    lifted_a
        .merge(rng, (desc_a, fee_set_a), (stamp_b, desc_b, fee_set_b))
        .expect("a lifted stamp merges with one at the anchor it was lifted to");
}

/// `merge` requires each side's descriptor list to match the actions its
/// stamp attests, but deliberately performs no pre-check.
/// `Bundle::verify_coverage` is the caller's check and returns the descriptor
/// set to pass to `merge`. This test models a caller that skips it, spends the
/// merge compute, and produces a stamp that does not verify against the true
/// covered actions.
///
/// The foreign descriptor changes the merged union. A simple left/right swap
/// preserves that union, which mock ragu cannot distinguish because it does
/// not validate child proofs against their carried headers.
#[test]
fn mismatched_merge_descriptors_fail_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user_a = WalletSim::random(rng);
    let user_b = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let anchor = pool.anchor();

    let bundle_a = user_a.autonome(
        rng,
        anchor,
        alloc::vec![],
        alloc::vec![user_a.random_note(200)],
    );
    let bundle_b = user_b.autonome(
        rng,
        anchor,
        alloc::vec![],
        alloc::vec![user_b.random_note(300)],
    );
    let (descriptors_a, fees_a) = bundle_a
        .verify_coverage(&[], &[])
        .expect("first bundle coverage");
    let (descriptors_b, fees_b) = bundle_b
        .verify_coverage(&[], &[])
        .expect("second bundle coverage");
    let foreign = random_action(rng).descriptor();

    let digests: Vec<ActionDigest> = descriptors_a
        .iter()
        .chain(&descriptors_b)
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests(fees_a.iter().chain(&fees_b).copied()))
        .collect();

    // `Bundle::verify_coverage` returned the attested input. A caller that
    // ignores it can instead assemble this mismatched descriptor set.
    let foreign_descriptors = BTreeSet::from_iter([foreign]);
    assert!(
        descriptors_a.is_disjoint(&foreign_descriptors),
        "the foreign descriptor must not overlap the other merge input"
    );
    assert!(
        !bundle_b
            .stamp
            .is_covering(foreign_descriptors.clone(), fees_b.iter().copied()),
        "the foreign descriptor must not be covered by the second stamp"
    );

    // The merge itself does not pre-check, and the mismatch violates no step
    // relation: proving succeeds and the compute is spent.
    let merged = bundle_a
        .stamp
        .clone()
        .merge(
            rng,
            (descriptors_a.clone(), fees_a.clone()),
            (bundle_b.stamp.clone(), foreign_descriptors, fees_b.clone()),
        )
        .expect("merge performs no coverage pre-check");

    // An honest verifier reconstructs the header from the true covered
    // actions, which the mismatched proof does not attest.
    assert!(
        !merged
            .verify_proof(rng, digests.clone())
            .expect("proof system verification"),
        "a merge fed descriptors its stamp does not attest must be disproved"
    );

    // Control: the same stamps merged under their attested descriptors
    // produce a stamp the same verifier accepts.
    let honest = bundle_a
        .stamp
        .merge(
            rng,
            (descriptors_a, fees_a),
            (bundle_b.stamp, descriptors_b, fees_b),
        )
        .expect("merge");
    assert!(
        honest
            .verify_proof(rng, digests)
            .expect("proof system verification"),
        "the attested descriptor lists produce a verifying merge"
    );
}
