extern crate alloc;

use alloc::{boxed::Box, collections::BTreeSet, string::ToString as _, vec, vec::Vec};

use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, Anchor, BlockHeight, CompactSize, ProofStamp, Tachygram, TachygramSetPoly,
    action,
    constants::EPOCH_SIZE,
    entropy::ActionEntropy,
    fee,
    stamp::{self, ProveError},
    value,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_autonome, build_lift_span, build_output_plan, build_output_stamp,
    forge_overlapping_merge, random_action, random_block, random_block_with, shared_sk,
    stamp_coverage,
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
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));

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
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));

    let note_a = user.random_note(500);
    let note_b = user.random_note(500);
    pool.mine(random_block_with(
        rng,
        &[vec![note_a.commitment(), note_b.commitment()]],
        50,
    ));
    let height = pool.height();

    let sp_a = user.spendable_init(rng, &note_a, &pool, height);
    let sp_b = user.spendable_init(rng, &note_b, &pool, height);
    let anchor = sp_a.data().2;
    assert_eq!(anchor, sp_b.data().2);

    let (rcv_a, theta_a) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let plan_a = action::Plan::spend(note_a, theta_a, rcv_a, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });

    let (rcv_b, theta_b) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
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
    .unwrap();

    let zero = value::Positive::ZERO;

    let secret_a = user.secret_pcd(rng, note_a);
    let secret_b = user.secret_pcd(rng, note_b);
    let bundle_a = || (secret_a.clone(), sp_a.clone(), vec![]);
    let bundle_b = || (secret_b.clone(), sp_b.clone(), vec![]);

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

    {
        let plan = stamp::Plan::new(two_spends(), alloc::vec![], anchor, max_fee_note, zero);
        let pcds = alloc::vec![bundle_b(), bundle_a()];
        let stamp = plan.prove(rng, &user.pak, pcds).unwrap();
        let planned = [
            plan_a.digest().unwrap(),
            plan_b.digest().unwrap(),
            fee_digest,
        ];
        assert!(!stamp.verify_proof(rng, planned).unwrap());
    }

    {
        let plan = stamp::Plan::new(
            alloc::vec![(foreign_a.descriptor(), theta_a, rcv_a)],
            alloc::vec![],
            anchor,
            max_fee_note,
            zero,
        );
        let stamp = plan.prove(rng, &user.pak, alloc::vec![bundle_a()]).unwrap();
        assert!(
            !stamp
                .verify_proof(rng, [foreign_a.digest().unwrap(), fee_digest])
                .unwrap()
        );
    }
}

#[test]
fn plan_prove_lifts_a_spend_along_spans() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));

    let note = user.random_note(500);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 3));
    let cm_height = pool.height();
    pool.advance(2, |_| random_block(rng, 1, 2));
    let plan_height = pool.height();
    assert_eq!(cm_height.epoch(), plan_height.epoch());
    let middle = cm_height.next().unwrap();

    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let spend_anchor = spendable.data().2;
    let plan_anchor = pool.block(plan_height).anchor();
    assert_ne!(spend_anchor, plan_anchor);

    let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
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
        spend.digest().unwrap(),
        output.digest().unwrap(),
        fee::Descriptor {
            max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
            value: value::Positive::ZERO,
        }
        .digest()
        .unwrap(),
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
            stamp.verify_proof(rng, digests).unwrap(),
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
    if let Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err))) = prove(rng, gapped)
    {
        assert_eq!(
            err.to_string(),
            "ActionLift: actions anchor is neither the span's start nor a member"
        );
    } else {
        panic!();
    }
}

#[test]
fn merge_populates_covered_actions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user_a = WalletSim::random(rng);
    let user_b = WalletSim::random(rng);
    let pool = PoolSim::genesis_with(random_block(rng, 1, 50));
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
        .unwrap();
    assert_eq!(merged.coverage, expected);
    assert_eq!(merged.fee, receiver_fee);
}

#[test]
fn double_output_cannot_aggregate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let anchor = pool.anchor();

    let note = wallet.random_note(200);
    let (stamp_a, plan_a, fee_a) = build_output_stamp(rng, anchor, note);
    let (stamp_b, plan_b, fee_b) = build_output_stamp(rng, anchor, note);
    assert_eq!(
        stamp_a.tachygrams.intersection(&stamp_b.tachygrams).count(),
        2
    );
    assert_ne!(plan_a.descriptor(), plan_b.descriptor());

    let descriptors_a = BTreeSet::from_iter([plan_a.descriptor()]);
    let descriptors_b = BTreeSet::from_iter([plan_b.descriptor()]);

    {
        if let Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err))) =
            stamp_a.clone().merge(
                rng,
                (descriptors_a.clone(), [fee_a].into()),
                (stamp_b.clone(), descriptors_b.clone(), [fee_b].into()),
            )
        {
            assert_eq!(
                err.to_string(),
                "StampMerge: merged tachygram set must be the product of left and right tachygram sets"
            );
        } else {
            panic!();
        }
    }

    let evil_pcd = forge_overlapping_merge(
        rng,
        (&stamp_a, &Vec::from_iter(descriptors_a.clone()), &[fee_a]),
        (&stamp_b, &Vec::from_iter(descriptors_b.clone()), &[fee_b]),
    );

    let all_descriptors: Vec<action::Descriptor> =
        descriptors_a.union(&descriptors_b).copied().collect();

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
        .map(|desc| desc.digest().unwrap())
        .chain(
            [fee_a, fee_b]
                .into_iter()
                .map(|descriptor| descriptor.digest().unwrap()),
        )
        .collect();
    assert!(!stamp.verify_proof(rng, digests).unwrap());
}

#[test]
fn double_spend_cannot_aggregate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());

    let spend = wallet.random_note(1000);
    let output_a = wallet.random_note(700);
    let output_b = wallet.random_note(600);

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(rng, &[vec![spend.commitment()]], 50));
    let cm_height = pool.height();
    while pool.height() < BlockHeight(EPOCH_SIZE) {
        pool.advance(1, |_| random_block(rng, 1, 2));
    }

    let sp_a = wallet.spendable_at(rng, &pool, &spend, cm_height.epoch().next().unwrap());
    let sp_b = wallet.spendable_at(rng, &pool, &spend, cm_height.epoch().next().unwrap());
    let anchor = sp_a.data().2;
    assert_eq!(anchor, sp_b.data().2);

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
    assert!(descriptors_a.is_disjoint(&descriptors_b));
    assert!(!stamp_a.tachygrams.is_disjoint(&stamp_b.tachygrams));

    let fees = [autonome_a.fee_descriptor(), autonome_b.fee_descriptor()];
    {
        if let Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err))) =
            stamp_a.clone().merge(
                rng,
                (descriptors_a.clone(), [fees[0]].into()),
                (stamp_b.clone(), descriptors_b.clone(), [fees[1]].into()),
            )
        {
            assert_eq!(
                err.to_string(),
                "StampMerge: merged tachygram set must be the product of left and right tachygram sets"
            );
        } else {
            panic!();
        }
    }

    let evil_pcd = forge_overlapping_merge(
        rng,
        (&stamp_a, &Vec::from_iter(descriptors_a.clone()), &fees[..1]),
        (&stamp_b, &Vec::from_iter(descriptors_b.clone()), &fees[1..]),
    );

    let all_descriptors: Vec<action::Descriptor> =
        descriptors_a.union(&descriptors_b).copied().collect();

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
        .map(|desc| desc.digest().unwrap())
        .chain(
            fees.into_iter()
                .map(|descriptor| descriptor.digest().unwrap()),
        )
        .collect();
    assert!(!stamp.verify_proof(rng, digests).unwrap());
}

#[test]
fn cannot_forge_stamp_covering_duplicated_action() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let anchor = pool.anchor();

    let note = wallet.random_note(200);
    let (output_stamp, plan, fee) = build_output_stamp(rng, anchor, note);
    let descriptors = BTreeSet::from_iter([plan.descriptor()]);
    let fees = BTreeSet::from([fee]);

    {
        if let Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err))) =
            output_stamp.clone().merge(
                rng,
                (descriptors.clone(), fees.clone()),
                (output_stamp.clone(), descriptors.clone(), fees),
            )
        {
            assert_eq!(
                err.to_string(),
                "StampMerge: merged action set must be the product of left and right action sets"
            );
        } else {
            panic!();
        }
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

    let digests: Vec<ActionDigest> = all_descriptors
        .iter()
        .map(|desc| desc.digest().unwrap())
        .chain(
            [fee, fee]
                .into_iter()
                .map(|descriptor| descriptor.digest().unwrap()),
        )
        .collect();
    assert!(!stamp.verify_proof(rng, digests).unwrap());
}

#[test]
fn verify_proof_action_multiset_invariants() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let stamped = build_autonome(rng, &wallet, 1000, 700);

    let digests: Vec<ActionDigest> = stamped
        .actions
        .iter()
        .map(|action| action.descriptor().digest().unwrap())
        .chain([stamped.fee_descriptor().digest().unwrap()])
        .collect();

    assert!(
        stamped
            .stamp
            .verify_proof(rng, digests.iter().rev().copied())
            .unwrap()
    );

    for index in [0, digests.len() - 1] {
        let mut dropped = digests.clone();
        dropped.remove(index);
        assert!(!stamped.stamp.verify_proof(rng, dropped).unwrap());
    }

    {
        let mut duplicated = digests.clone();
        duplicated.push(digests[0]);
        assert!(!stamped.stamp.verify_proof(rng, duplicated).unwrap());
    }

    {
        let mut extended = digests.clone();
        extended.push(random_action(rng).descriptor().digest().unwrap());
        assert!(!stamped.stamp.verify_proof(rng, extended).unwrap());
    }

    {
        let mut replaced = digests;
        replaced[0] = random_action(rng).descriptor().digest().unwrap();
        assert!(!stamped.stamp.verify_proof(rng, replaced).unwrap());
    }
}

#[test]
fn read_rejects_malformed_tachygram_lists() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let tachygram = Tachygram::random(rng);
    for (count, tachygrams, expected) in [
        (2, vec![tachygram, tachygram], "tachygrams are not unique"),
        (0, vec![], "no tachygrams"),
        (
            u64::try_from(ProductionRank::num_coeffs()).unwrap(),
            vec![],
            "too many tachygrams",
        ),
    ] {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.extend_from_slice(&[0u8; 32]);
        anchor.write(&mut buf).unwrap();
        TachygramSetPoly::from_iter(tachygrams.iter().copied())
            .commit()
            .write(&mut buf)
            .unwrap();
        CompactSize::from(count).write(&mut buf).unwrap();
        for listed in tachygrams {
            listed.write(&mut buf).unwrap();
        }
        assert_eq!(ProofStamp::read(&*buf).unwrap_err().to_string(), expected);
    }
}

#[test]
fn covered_actions_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = wallet.random_note(200);
    let (stamp, _plan, _) = build_output_stamp(rng, pool.anchor(), note);

    let mut buf: Vec<u8> = Vec::new();
    stamp.write(&mut buf).unwrap();
    let decoded = ProofStamp::read(&*buf).unwrap();

    assert_eq!(decoded.fee, stamp.fee);
    assert_eq!(decoded.coverage, stamp.coverage);
    assert_eq!(decoded.anchor, stamp.anchor);
    assert_eq!(decoded.tachygram_set, stamp.tachygram_set);
    assert_eq!(decoded.tachygrams, stamp.tachygrams);
}

#[test]
fn honest_stamp_commits_to_its_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = wallet.random_note(200);
    let (stamp, _plan, _) = build_output_stamp(rng, pool.anchor(), note);

    assert_eq!(
        TachygramSetPoly::from_iter(stamp.tachygrams.clone()).commit(),
        stamp.tachygram_set
    );
}

#[test]
fn verify_proof_rejects_mismatched_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let note = wallet.random_note(200);
    let (honest, plan, fee_descriptor) = build_output_stamp(rng, pool.anchor(), note);
    let fee_digest = fee_descriptor.digest().unwrap();

    let other = Tachygram::random(rng);
    let forged = ProofStamp {
        tachygram_set: TachygramSetPoly::from_iter([other]).commit(),
        ..honest
    };
    assert!(
        !forged
            .verify_proof(rng, [plan.digest().unwrap(), fee_digest])
            .unwrap()
    );
}

#[test]
fn lift_moves_the_anchor_and_keeps_the_proof_valid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(3, |_| random_block(rng, 1, 4));
    let note = wallet.random_note(200);
    let (stamp, plan, fee_descriptor) = build_output_stamp(rng, pool.anchor(), note);
    let stamped_at = pool.height();
    pool.advance(2, |_| random_block(rng, 1, 4));
    let lifted_to = pool.height();
    let fees = BTreeSet::from([fee_descriptor]);
    let digests = [plan.digest().unwrap(), fee_descriptor.digest().unwrap()];

    let span = build_lift_span(rng, &pool, stamped_at.next().unwrap()..=lifted_to);
    let lifted = stamp
        .clone()
        .lift(rng, &BTreeSet::from([plan.descriptor()]), &fees, vec![span])
        .unwrap();
    assert_eq!(lifted.anchor, pool.block(lifted_to).anchor());
    assert_eq!(lifted.coverage, stamp.coverage);
    assert_eq!(lifted.tachygram_set, stamp.tachygram_set);
    assert_eq!(lifted.tachygrams, stamp.tachygrams);
    assert!(lifted.verify_proof(rng, digests).unwrap());

    let foreign = BTreeSet::from([random_action(rng).descriptor()]);
    let foreign_span = build_lift_span(rng, &pool, stamped_at.next().unwrap()..=lifted_to);
    let misdescribed = stamp
        .lift(rng, &foreign, &fees, vec![foreign_span])
        .unwrap();
    assert!(!misdescribed.verify_proof(rng, digests).unwrap());
}

#[test]
fn lift_rejects_a_foreign_span() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(3, |_| random_block(rng, 1, 4));

    let note = wallet.random_note(200);
    let (stamp, plan, fee_descriptor) = build_output_stamp(rng, pool.anchor(), note);

    let mut foreign = PoolSim::genesis_with(random_block(rng, 1, 50));
    foreign.advance(3, |_| random_block(rng, 1, 4));
    let span = build_lift_span(rng, &foreign, BlockHeight(1)..=foreign.height());

    if let Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err))) = stamp.lift(
        rng,
        &BTreeSet::from([plan.descriptor()]),
        &BTreeSet::from([fee_descriptor]),
        vec![span],
    ) {
        assert_eq!(
            err.to_string(),
            "StampLift: stamp anchor is neither the span's start nor a member"
        );
    } else {
        panic!();
    }
}

#[test]
fn merge_after_lift() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user_a = WalletSim::random(rng);
    let user_b = WalletSim::random(rng);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));

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
        .unwrap_err();

    let span = build_lift_span(rng, &pool, height_a.next().unwrap()..=height_b);
    let lifted_a = stamp_a.lift(rng, &desc_a, &fee_set_a, vec![span]).unwrap();

    assert_eq!(lifted_a.anchor, stamp_b.anchor);
    lifted_a
        .merge(rng, (desc_a, fee_set_a), (stamp_b, desc_b, fee_set_b))
        .unwrap();
}

#[test]
fn mismatched_merge_descriptors_fail_verification() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user_a = WalletSim::random(rng);
    let user_b = WalletSim::random(rng);
    let pool = PoolSim::genesis_with(random_block(rng, 1, 50));
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
    let (descriptors_a, fees_a) = bundle_a.verify_coverage(&[], &[]).unwrap();
    let (descriptors_b, fees_b) = bundle_b.verify_coverage(&[], &[]).unwrap();
    let foreign = random_action(rng).descriptor();

    let digests: Vec<ActionDigest> = descriptors_a
        .iter()
        .chain(&descriptors_b)
        .map(|desc| desc.digest().unwrap())
        .chain(
            fees_a
                .iter()
                .chain(&fees_b)
                .copied()
                .map(|descriptor| descriptor.digest().unwrap()),
        )
        .collect();

    let foreign_descriptors = BTreeSet::from_iter([foreign]);
    assert!(descriptors_a.is_disjoint(&foreign_descriptors));
    assert!(
        !bundle_b
            .stamp
            .is_covering(foreign_descriptors.clone(), fees_b.iter().copied())
    );

    let merged = bundle_a
        .stamp
        .clone()
        .merge(
            rng,
            (descriptors_a.clone(), fees_a.clone()),
            (bundle_b.stamp.clone(), foreign_descriptors, fees_b.clone()),
        )
        .unwrap();

    assert!(!merged.verify_proof(rng, digests.clone()).unwrap());

    let honest = bundle_a
        .stamp
        .merge(
            rng,
            (descriptors_a, fees_a),
            (bundle_b.stamp, descriptors_b, fees_b),
        )
        .unwrap();
    assert!(honest.verify_proof(rng, digests).unwrap());
}
