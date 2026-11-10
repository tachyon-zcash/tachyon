extern crate alloc;

use alloc::{boxed::Box, collections::BTreeSet, string::ToString as _, vec, vec::Vec};
use core::assert_matches;

use corez::io;
use ragu_circuits::polynomials::{ProductionRank, Rank as _};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, Anchor, CompactSize, ProofStamp, Tachygram, TachygramSetPoly, action,
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

    let (rcv_a, theta_a) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let plan_a = action::Plan::spend(note_a, theta_a, rcv_a, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });
    let (rcv_b, theta_b) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let plan_b = action::Plan::spend(note_b, theta_b, rcv_b, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });
    let max_fee_note = user.random_note(0);
    let fee_digest = fee::Descriptor {
        cv_feemax: max_fee_note.cv_feemax(),
        v_fee: value::Positive::ZERO,
    }
    .digest()
    .unwrap();
    let secret_a = user.secret_pcd(rng, note_a);
    let secret_b = user.secret_pcd(rng, note_b);
    let plan = stamp::Plan::new(
        vec![
            (plan_a.descriptor(), theta_a, rcv_a),
            (plan_b.descriptor(), theta_b, rcv_b),
        ],
        vec![],
        anchor,
        max_fee_note,
        value::Positive::ZERO,
    );

    for (pcds, expected) in [
        (
            vec![(secret_a.clone(), sp_a.clone(), vec![])],
            "cannot prove 2 spend actions with 1 spendbind inputs",
        ),
        (
            vec![
                (secret_a.clone(), sp_a.clone(), vec![]),
                (secret_b.clone(), sp_b.clone(), vec![]),
                (secret_a.clone(), sp_a.clone(), vec![]),
            ],
            "cannot prove 2 spend actions with 3 spendbind inputs",
        ),
    ] {
        assert_matches!(
            plan.clone().prove(rng, &user.pak, pcds),
            Err(ProveError::MissingPcd(reason)) if reason.to_string() == expected
        );
    }

    let swapped = plan
        .prove(
            rng,
            &user.pak,
            vec![
                (secret_b, sp_b, vec![]),
                (secret_a.clone(), sp_a.clone(), vec![]),
            ],
        )
        .unwrap();
    assert!(
        !swapped
            .verify_proof(
                rng,
                [
                    plan_a.digest().unwrap(),
                    plan_b.digest().unwrap(),
                    fee_digest
                ]
            )
            .unwrap()
    );

    let foreign_a = action::Plan::spend(note_a, theta_a, rcv_a, |alpha| {
        other.pak.ak.derive_action_public(&alpha)
    });
    let foreign = stamp::Plan::new(
        vec![(foreign_a.descriptor(), theta_a, rcv_a)],
        vec![],
        anchor,
        max_fee_note,
        value::Positive::ZERO,
    )
    .prove(rng, &user.pak, vec![(secret_a, sp_a, vec![])])
    .unwrap();
    assert!(
        !foreign
            .verify_proof(rng, [foreign_a.digest().unwrap(), fee_digest])
            .unwrap()
    );
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
    let middle = cm_height.next().unwrap();

    let spendable = user.spendable_init(rng, &note, &pool, cm_height);
    let plan_anchor = pool.block(plan_height).anchor();

    let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let spend = action::Plan::spend(note, theta, rcv, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });
    let (out_rcv, out_theta, output) = build_output_plan(rng, user.random_note(200));
    let secret = user.secret_pcd(rng, note);
    let max_fee_note = user.random_note(0);
    let plan = stamp::Plan::new(
        vec![(spend.descriptor(), theta, rcv)],
        vec![(output.descriptor(), out_theta, output.note, out_rcv)],
        plan_anchor,
        max_fee_note,
        value::Positive::ZERO,
    );
    let digests = [
        spend.digest().unwrap(),
        output.digest().unwrap(),
        fee::Descriptor {
            cv_feemax: max_fee_note.cv_feemax(),
            v_fee: value::Positive::ZERO,
        }
        .digest()
        .unwrap(),
    ];

    for spans in [
        vec![build_lift_span(rng, &pool, cm_height..=plan_height)],
        vec![
            build_lift_span(rng, &pool, cm_height..=cm_height),
            build_lift_span(rng, &pool, middle..=plan_height),
        ],
        vec![
            build_lift_span(rng, &pool, cm_height..=middle),
            build_lift_span(rng, &pool, middle..=plan_height),
        ],
    ] {
        let stamp = plan
            .clone()
            .prove(
                rng,
                &user.pak,
                vec![(secret.clone(), spendable.clone(), spans)],
            )
            .unwrap();
        assert_eq!(stamp.anchor, plan_anchor);
        assert!(stamp.verify_proof(rng, digests).unwrap());
    }

    for spans in [
        vec![],
        vec![build_lift_span(rng, &pool, cm_height..=middle)],
    ] {
        assert_matches!(
            plan.clone().prove(
                rng,
                &user.pak,
                vec![(secret.clone(), spendable.clone(), spans)],
            ),
            Err(ProveError::MissingPcd(reason))
                if reason.to_string() == "spend 0 does not reach the plan's anchor"
        );
    }

    let gapped = vec![
        build_lift_span(rng, &pool, cm_height..=cm_height),
        build_lift_span(rng, &pool, plan_height..=plan_height),
    ];
    assert_matches!(
        plan.prove(rng, &user.pak, vec![(secret, spendable, gapped)]),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err))) if err.to_string()
            == "ActionLift: actions anchor is neither the span's start nor a member"
    );
}

#[test]
fn overlapping_stamps_cannot_aggregate() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let output = wallet.random_note(200);
    let spend = wallet.random_note(1000);
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(rng, &[vec![spend.commitment()]], 50));
    let spendable = wallet.spendable_init(rng, &spend, &pool, pool.height());
    let anchor = spendable.data().2;

    let (output_a, plan_a, fee_a) = build_output_stamp(rng, anchor, output);
    let (output_b, plan_b, fee_b) = build_output_stamp(rng, anchor, output);
    let spend_a = wallet.autonome(
        rng,
        anchor,
        vec![(spend, spendable.clone())],
        vec![wallet.random_note(700)],
    );
    let spend_b = wallet.autonome(
        rng,
        anchor,
        vec![(spend, spendable)],
        vec![wallet.random_note(600)],
    );

    for ((left, left_descriptors, left_fees), (right, right_descriptors, right_fees), expected) in [
        (
            (
                output_a.clone(),
                BTreeSet::from([plan_a.descriptor()]),
                BTreeSet::from([fee_a]),
            ),
            (
                output_b,
                BTreeSet::from([plan_b.descriptor()]),
                BTreeSet::from([fee_b]),
            ),
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        ),
        (
            (
                spend_a.stamp.clone(),
                spend_a.descriptors().collect(),
                BTreeSet::from([spend_a.fee_descriptor()]),
            ),
            (
                spend_b.stamp.clone(),
                spend_b.descriptors().collect(),
                BTreeSet::from([spend_b.fee_descriptor()]),
            ),
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        ),
        (
            (
                output_a.clone(),
                BTreeSet::from([plan_a.descriptor()]),
                BTreeSet::from([fee_a]),
            ),
            (
                output_a,
                BTreeSet::from([plan_a.descriptor()]),
                BTreeSet::from([fee_a]),
            ),
            "StampMerge: merged action set must be the product of left and right action sets",
        ),
    ] {
        assert_matches!(
            left.clone().merge(
                rng,
                (left_descriptors.clone(), left_fees.clone()),
                (right.clone(), right_descriptors.clone(), right_fees.clone()),
            ),
            Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err)))
                if err.to_string() == expected
        );

        let forged = forge_overlapping_merge(
            rng,
            (
                &left,
                &left_descriptors.iter().copied().collect(),
                &left_fees.iter().copied().collect::<Vec<_>>(),
            ),
            (
                &right,
                &right_descriptors.iter().copied().collect(),
                &right_fees.iter().copied().collect::<Vec<_>>(),
            ),
        );
        let descriptors: Vec<action::Descriptor> = left_descriptors
            .iter()
            .chain(&right_descriptors)
            .copied()
            .collect();
        let fees: Vec<fee::Descriptor> = left_fees.iter().chain(&right_fees).copied().collect();
        let tachygrams: BTreeSet<Tachygram> =
            left.tachygrams.union(&right.tachygrams).copied().collect();
        let stamp = ProofStamp {
            coverage: stamp_coverage(descriptors.iter().copied(), &fees),
            anchor: forged.data().1,
            tachygram_set: tachygrams
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit(),
            tachygrams,
            proof: Box::new(forged.proof().clone()),
            fee: left.fee,
        };
        let digests: Vec<ActionDigest> = descriptors
            .iter()
            .map(|desc| desc.digest().unwrap())
            .chain(fees.iter().map(|descriptor| descriptor.digest().unwrap()))
            .collect();
        assert!(!stamp.verify_proof(rng, digests).unwrap());
    }
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

    for edited in [
        digests[1..].to_vec(),
        digests[..digests.len() - 1].to_vec(),
        [digests.as_slice(), &digests[..1]].concat(),
        [
            digests.as_slice(),
            &[random_action(rng).descriptor().digest().unwrap()],
        ]
        .concat(),
        [
            &[random_action(rng).descriptor().digest().unwrap()],
            &digests[1..],
        ]
        .concat(),
    ] {
        assert!(!stamped.stamp.verify_proof(rng, edited).unwrap());
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
        assert_eq!(
            ProofStamp::<stamp::Uncompressed>::read(&*buf)
                .unwrap_err()
                .to_string(),
            expected
        );
    }
}

#[test]
fn read_rejects_wrong_proof_size() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let anchor = Anchor::random(rng);
    let (stamp, ..) = build_output_stamp(rng, anchor, wallet.random_note(200));
    let compressed_size = <stamp::Compressed as stamp::Proof>::encoded_len();
    let uncompressed_size = <stamp::Uncompressed as stamp::Proof>::encoded_len();

    {
        let proof = stamp.proof.to_bytes().unwrap();
        let mut bytes = Vec::new();
        stamp.write(&mut bytes).unwrap();
        let mut prefix = Vec::new();
        CompactSize::try_from(proof.len())
            .unwrap()
            .write(&mut prefix)
            .unwrap();
        bytes.truncate(bytes.len() - proof.len() - prefix.len());
        CompactSize::try_from(compressed_size)
            .unwrap()
            .write(&mut bytes)
            .unwrap();
        bytes.extend_from_slice(&proof);
        let mut reader = bytes.as_slice();
        let err = ProofStamp::<stamp::Uncompressed>::read(&mut reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(reader.len(), proof.len() - compressed_size);
    }

    let compressed = stamp.compress(rng).unwrap();
    {
        let proof = compressed.proof.to_bytes().unwrap();
        let mut bytes = Vec::new();
        compressed.write(&mut bytes).unwrap();
        let mut prefix = Vec::new();
        CompactSize::try_from(proof.len())
            .unwrap()
            .write(&mut prefix)
            .unwrap();
        bytes.truncate(bytes.len() - proof.len() - prefix.len());
        CompactSize::try_from(uncompressed_size)
            .unwrap()
            .write(&mut bytes)
            .unwrap();
        let err = ProofStamp::<stamp::Compressed>::read(&*bytes).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "proof size exceeds transport bound");
    }
}

#[test]
fn output_stamp_round_trips_and_binds_its_tachygram_set() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let anchor = Anchor::random(rng);
    let (stamp, plan, fee_descriptor) = build_output_stamp(rng, anchor, wallet.random_note(200));

    let mut buf: Vec<u8> = Vec::new();
    stamp.write(&mut buf).unwrap();
    let decoded = ProofStamp::<stamp::Uncompressed>::read(&*buf).unwrap();
    assert_eq!(decoded.fee, stamp.fee);
    assert_eq!(decoded.coverage, stamp.coverage);
    assert_eq!(decoded.anchor, stamp.anchor);
    assert_eq!(decoded.tachygram_set, stamp.tachygram_set);
    assert_eq!(decoded.tachygrams, stamp.tachygrams);

    let forged = ProofStamp {
        tachygram_set: TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit(),
        ..stamp
    };
    assert!(
        !forged
            .verify_proof(
                rng,
                [plan.digest().unwrap(), fee_descriptor.digest().unwrap()]
            )
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
        .lift(
            rng,
            &BTreeSet::from([plan.descriptor()]),
            &fees,
            vec![span.clone()],
        )
        .unwrap();
    assert_eq!(lifted.anchor, pool.block(lifted_to).anchor());
    assert_eq!(lifted.coverage, stamp.coverage);
    assert_eq!(lifted.tachygram_set, stamp.tachygram_set);
    assert_eq!(lifted.tachygrams, stamp.tachygrams);
    assert!(lifted.verify_proof(rng, digests).unwrap());

    let mut bytes = Vec::new();
    stamp.write(&mut bytes).unwrap();
    let decoded = ProofStamp::<stamp::Uncompressed>::read(&*bytes).unwrap();
    let lifted_decoded = decoded
        .lift(
            rng,
            &BTreeSet::from([plan.descriptor()]),
            &fees,
            vec![span.clone()],
        )
        .unwrap();
    assert_eq!(lifted_decoded.anchor, pool.block(lifted_to).anchor());
    assert!(lifted_decoded.verify_proof(rng, digests).unwrap());

    let foreign = BTreeSet::from([random_action(rng).descriptor()]);
    assert_matches!(
        stamp.lift(rng, &foreign, &fees, vec![span]),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(_)))
    );
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

    assert_matches!(
        stamp_a.clone().merge(
            rng,
            (desc_a.clone(), fee_set_a.clone()),
            (stamp_b.clone(), desc_b.clone(), fee_set_b.clone()),
        ),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err)))
            if err.to_string() == "StampMerge: anchors must match"
    );

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
    let anchor = Anchor::random(rng);

    let bundle_a = user_a.autonome(rng, anchor, vec![], vec![user_a.random_note(200)]);
    let bundle_b = user_b.autonome(rng, anchor, vec![], vec![user_b.random_note(300)]);
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

    assert_matches!(
        bundle_a.stamp.clone().merge(
            rng,
            (descriptors_a.clone(), fees_a.clone()),
            (
                bundle_b.stamp.clone(),
                BTreeSet::from([foreign]),
                fees_b.clone(),
            ),
        ),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(_)))
    );

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
