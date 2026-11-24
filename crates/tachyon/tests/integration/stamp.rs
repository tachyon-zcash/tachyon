extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString as _,
    vec,
    vec::Vec,
};
use core::assert_matches;

use corez::io;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, BlockHeight, CompactSize, ProofStamp, Tachygram, TachygramSetPoly,
    VerificationError, action,
    bundle::{self, VerifyCoverageError},
    entropy::ActionEntropy,
    fee,
    stamp::{
        self, ProveError,
        proof::transaction::{Transaction, TransactionMerge},
    },
    value, witness,
};

use super::fixtures::application;
use crate::fixtures::{
    mock_sighash, mock_txid,
    pool::PoolSim,
    wallet::{
        WalletSim, alice, alice_output_note, bob, later_output, lifted, merged, output_plan,
        random_action, shared_sk, spend,
    },
};

#[test]
fn plan_prove_rejects_invalid_inputs() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let other = WalletSim::random(rng);
    let pool = PoolSim::shared();
    let note_a = PoolSim::shared_note(500);
    let note_b = PoolSim::shared_note(700);
    let height = BlockHeight(1);

    let sp_a = user.spendable_init(app, pool, &note_a, height);
    let sp_b = user.spendable_init(app, pool, &note_b, height);
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
    .digest(max_fee_note.commitment().into());
    let secret_a = user.note_secret(app, note_a);
    let secret_b = user.note_secret(app, note_b);
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
            plan.clone().prove(rng, app, &user.pak, pcds),
            Err(ProveError::MissingPcd(reason)) if reason.to_string() == expected
        );
    }

    let (swapped, swapped_pairs, ..) = plan
        .prove(
            rng,
            app,
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
                app,
                [
                    plan_a.digest(swapped_pairs[&plan_a.descriptor()]),
                    plan_b.digest(swapped_pairs[&plan_b.descriptor()]),
                    fee_digest
                ]
            )
            .unwrap()
    );

    let foreign_a = action::Plan::spend(note_a, theta_a, rcv_a, |alpha| {
        other.pak.ak.derive_action_public(&alpha)
    });
    let (foreign, foreign_pairs, ..) = stamp::Plan::new(
        vec![(foreign_a.descriptor(), theta_a, rcv_a)],
        vec![],
        anchor,
        max_fee_note,
        value::Positive::ZERO,
    )
    .prove(rng, app, &user.pak, vec![(secret_a, sp_a, vec![])])
    .unwrap();
    assert!(
        !foreign
            .verify_proof(
                rng,
                app,
                [
                    foreign_a.digest(foreign_pairs[&foreign_a.descriptor()]),
                    fee_digest
                ]
            )
            .unwrap()
    );
}

#[test]
fn plan_prove_lifts_a_spend_along_spans() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let pool = PoolSim::shared();
    let note = PoolSim::shared_note(500);
    let cm_height = BlockHeight(1);
    let middle = BlockHeight(2);
    let plan_height = BlockHeight(3);
    let spendable = user.spendable_init(app, pool, &note, cm_height);
    let plan_anchor = pool.block(plan_height).anchor();

    let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
    let spend = action::Plan::spend(note, theta, rcv, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });
    let output = output_plan(rng, user.random_note(200));
    let secret = user.note_secret(app, note);
    let max_fee_note = user.random_note(0);
    let plan = stamp::Plan::new(
        vec![(spend.descriptor(), theta, rcv)],
        vec![(output.descriptor(), output.theta, output.note, output.rcv)],
        plan_anchor,
        max_fee_note,
        value::Positive::ZERO,
    );

    for spans in [
        vec![pool.anchor_span(app, cm_height..=plan_height)],
        vec![
            pool.anchor_span(app, cm_height..=middle),
            pool.anchor_span(app, plan_height..=plan_height),
        ],
        vec![
            pool.anchor_span(app, cm_height..=middle),
            pool.anchor_span(app, middle..=plan_height),
        ],
    ] {
        let (stamp, pairs, cm_change, v_fee) = plan
            .clone()
            .prove(
                rng,
                app,
                &user.pak,
                vec![(secret.clone(), spendable.clone(), spans)],
            )
            .unwrap();
        assert!(pairs.values().all(|&(first, second)| first < second));
        let digests: Vec<ActionDigest> = pairs
            .iter()
            .map(|(desc, &pair)| desc.digest(pair))
            .chain([fee::Descriptor {
                cv_feemax: max_fee_note.cv_feemax(),
                v_fee,
            }
            .digest(cm_change)])
            .collect();
        assert_eq!(stamp.anchor, plan_anchor);
        assert!(stamp.verify_proof(rng, app, digests).unwrap());
    }

    for spans in [vec![], vec![pool.anchor_span(app, cm_height..=middle)]] {
        assert_matches!(
            plan.clone().prove(
                rng,
                app,
                &user.pak,
                vec![(secret.clone(), spendable.clone(), spans)],
            ),
            Err(ProveError::MissingPcd(reason))
                if reason.to_string() == "spend 0 does not reach the plan's anchor"
        );
    }

    let gapped = vec![
        pool.anchor_span(app, cm_height..=cm_height),
        pool.anchor_span(app, plan_height..=plan_height),
    ];
    let (forged, pairs, cm_change, v_fee) = plan
        .prove(rng, app, &user.pak, vec![(secret, spendable, gapped)])
        .unwrap();
    let digests: Vec<ActionDigest> = pairs
        .iter()
        .map(|(desc, &pair)| desc.digest(pair))
        .chain([fee::Descriptor {
            cv_feemax: max_fee_note.cv_feemax(),
            v_fee,
        }
        .digest(cm_change)])
        .collect();
    assert!(!forged.verify_proof(rng, app, digests).unwrap());
}

#[test]
fn overlapping_stamps_with_distinct_actions_fail_bundle_coverage() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let pool = PoolSim::shared();
    let anchor = pool.mint_anchor();
    let (_, alice_bundle) = alice(app);
    let (_, output_b) = wallet.bundle(
        app,
        anchor,
        &[],
        &[alice_output_note()],
        wallet.random_note(0),
        value::Positive::ZERO,
    );
    let (_, spend_a) = spend(app);
    let note = PoolSim::shared_note(1000);
    let spendable = wallet.spendable_init(app, pool, &note, BlockHeight(1));
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let spend_plan = action::Plan::spend(note, theta, rcv, |alpha| {
        wallet.pak.ak.derive_action_public(&alpha)
    });
    let output = output_plan(rng, wallet.random_note(600));
    let plan = bundle::Plan::new(vec![spend_plan], vec![output], wallet.random_note(0));
    let signatures = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap();
    let proof = plan
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(
            rng,
            app,
            &wallet.pak,
            vec![(wallet.note_secret(app, note), spendable, vec![])],
        )
        .unwrap();
    let spend_b = plan.assemble(signatures, proof);
    for (left, right) in [(&alice_bundle, &output_b), (&spend_a, &spend_b)] {
        let aggregate = merged(app, left, right);
        let left_digests = left.verify_covered(&[]).unwrap().0;
        let right_digests = right.verify_covered(&[]).unwrap().0;
        let digests = [left_digests.as_slice(), right_digests.as_slice()].concat();
        let union: BTreeSet<_> = digests.iter().copied().collect();
        assert_eq!(union.len(), digests.len());
        assert!(aggregate.stamp.verify_proof(rng, app, union).unwrap());
        let sighash = mock_sighash(aggregate.commitment());
        assert_matches!(
            aggregate.verify(rng, app, &sighash, &[&right.clone().strip()]),
            Err(VerificationError::Coverage(
                VerifyCoverageError::DuplicateTachygrams
            ))
        );

        // Removing the right leaves must retain the tachygrams also
        // contributed by the surviving left leaves.
        let [left_pairs, right_pairs]: [BTreeMap<_, _>; 2] = [left, right].map(|bundle| {
            bundle
                .actions
                .iter()
                .zip(&bundle.action_auth)
                .map(|(&descriptor, &(_, pair))| (descriptor, pair))
                .collect()
        });
        let all_pairs = left_pairs.into_iter().chain(right_pairs.clone()).collect();
        let all_fees = BTreeMap::from([(left.fee, left.fee_auth), (right.fee, right.fee_auth)]);
        let quotient = aggregate
            .stamp
            .unmerge(
                rng,
                app,
                (&all_pairs, &all_fees),
                (
                    right.stamp.clone(),
                    mock_txid(right),
                    &right_pairs,
                    &BTreeMap::from([(right.fee, right.fee_auth)]),
                ),
            )
            .unwrap();
        assert_eq!(quotient.tachygram_set, left.stamp.tachygram_set);
        let restored = bundle::Bundle {
            stamp: quotient,
            ..left.clone()
        };
        restored.verify(rng, app, &sighash, &[]).unwrap();
    }
}

#[test]
fn self_merge_requires_both_copies_of_the_action_digests() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, bundle) = alice(app);
    let (digests, _) = bundle.verify_covered(&[]).unwrap();
    let mut stamp = bundle.stamp;
    let commit = ActionSetPoly::from_iter(digests.iter().copied()).commit();
    let header = (app.bridge_hash(commit.into()).unwrap().into(), stamp.anchor);
    let input = stamp.proof.clone().carry::<Transaction>(header);
    let doubled_digests = [digests.as_slice(), digests.as_slice()].concat();
    let (missing_factor, ()) = app
        .fuse(
            rng,
            TransactionMerge,
            witness::transaction_merge(
                (header, header),
                ActionSetPoly::from_iter(doubled_digests[1..].iter().copied()),
            ),
            input.clone(),
            input.clone(),
        )
        .unwrap();
    assert!(!app.verify_uncompressed(&missing_factor, &mut *rng).unwrap());
    let (doubled, ()) = app
        .fuse(
            rng,
            TransactionMerge,
            witness::transaction_merge(
                (header, header),
                ActionSetPoly::from_iter(doubled_digests.iter().copied()),
            ),
            input.clone(),
            input,
        )
        .unwrap();
    *stamp.proof = doubled.into_parts().0;
    assert!(stamp.verify_proof(rng, app, doubled_digests).unwrap());
    assert!(!stamp.verify_proof(rng, app, digests).unwrap());
}

#[test]
fn verify_proof_action_multiset_invariants() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, stamped) = spend(app);

    let (digests, _) = stamped.verify_covered(&[]).unwrap();

    assert!(
        stamped
            .stamp
            .verify_proof(rng, app, digests.iter().rev().copied())
            .unwrap()
    );

    for edited in [
        digests[1..].to_vec(),
        digests[..digests.len() - 1].to_vec(),
        [digests.as_slice(), &digests[..1]].concat(),
        [
            digests.as_slice(),
            &[random_action(rng)
                .0
                .digest((Tachygram::random(rng), Tachygram::random(rng)))],
        ]
        .concat(),
        [
            &[random_action(rng)
                .0
                .digest((Tachygram::random(rng), Tachygram::random(rng)))],
            &digests[1..],
        ]
        .concat(),
    ] {
        assert!(!stamped.stamp.verify_proof(rng, app, edited).unwrap());
    }
}

#[test]
fn read_rejects_wrong_proof_size() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(app);
    let stamp = alice.stamp;
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

    let compressed = stamp.compress(rng, app).unwrap();
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
fn output_stamp_round_trips_and_bundle_checks_its_tachygram_set() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(app);
    let (digests, _) = alice.verify_covered(&[]).unwrap();
    let stamp = &alice.stamp;

    let mut buf: Vec<u8> = Vec::new();
    stamp.write(&mut buf).unwrap();
    let mut decoded = ProofStamp::<stamp::Uncompressed>::read(&*buf).unwrap();
    assert_eq!(decoded.adjuncts, stamp.adjuncts);
    assert_eq!(decoded.anchor, stamp.anchor);
    assert_eq!(decoded.tachygram_set, stamp.tachygram_set);
    decoded.tachygram_set = TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit();
    assert!(
        decoded
            .verify_proof(rng, app, digests.iter().copied())
            .unwrap()
    );
    let compressed = decoded.clone().compress(rng, app).unwrap();
    assert!(compressed.verify_proof(rng, app, digests).unwrap());
    let bundle = zcash_tachyon::Bundle {
        stamp: decoded,
        ..alice
    };
    assert_matches!(
        bundle.verify(rng, app, &mock_sighash(bundle.commitment()), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::WrongTachygramSet
        ))
    );
}

#[test]
fn lift_moves_the_anchor_and_keeps_the_proof_valid() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let (_, alice) = alice(app);
    let (digests, _) = alice.verify_covered(&[]).unwrap();
    let descriptors: BTreeMap<_, _> = alice
        .actions
        .iter()
        .zip(&alice.action_auth)
        .map(|(&desc, &(_, pair))| (desc, pair))
        .collect();
    let fees = BTreeMap::from([(alice.fee, alice.fee_auth)]);
    let fee_digest = alice.fee.digest(alice.fee_auth);
    let stamp = alice.stamp.clone();
    let lifted_to = BlockHeight(2);

    let span = pool.anchor_span(app, BlockHeight(1)..=lifted_to);
    let lifted = lifted(app, &alice, pool, BlockHeight(1)..=lifted_to).stamp;
    assert_eq!(lifted.anchor, pool.block(lifted_to).anchor());
    assert_eq!(lifted.adjuncts, stamp.adjuncts);
    assert_eq!(lifted.tachygram_set, stamp.tachygram_set);
    assert!(
        lifted
            .verify_proof(rng, app, digests.iter().copied())
            .unwrap()
    );

    let mut bytes = Vec::new();
    stamp.write(&mut bytes).unwrap();
    let decoded = ProofStamp::<stamp::Uncompressed>::read(&*bytes).unwrap();
    let lifted_decoded = decoded
        .lift(rng, app, &descriptors, &fees, vec![span.clone()])
        .unwrap();
    assert_eq!(lifted_decoded.anchor, pool.block(lifted_to).anchor());
    assert_eq!(lifted_decoded.adjuncts, stamp.adjuncts);
    assert!(lifted_decoded.verify_proof(rng, app, digests).unwrap());

    let foreign = random_action(rng).0;
    let pair = *descriptors.values().next().unwrap();
    let mismatched_descriptors = BTreeMap::from([(foreign, pair)]);
    let mismatched = stamp
        .lift(rng, app, &mismatched_descriptors, &fees, vec![span])
        .unwrap();
    assert!(
        !mismatched
            .verify_proof(rng, app, [foreign.digest(pair), fee_digest],)
            .unwrap()
    );
}

#[test]
fn empty_lift_does_not_digest_invalid_coverage() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, bundle) = alice(app);
    let mut invalid = bundle.clone().strip();
    invalid.actions[0].cv = value::Trapdoor::ZERO.commit(value::Positive::ZERO);
    invalid.fee.cv_feemax = invalid.actions[0].cv;
    let descriptors = invalid
        .actions
        .iter()
        .zip(&invalid.action_auth)
        .map(|(&desc, &(_, pair))| (desc, pair))
        .collect();
    let fees = BTreeMap::from([(invalid.fee, invalid.fee_auth)]);

    // Even unusable coverage maps must not be inspected for an empty lift.
    bundle
        .stamp
        .clone()
        .lift(rng, app, &descriptors, &fees, vec![])
        .unwrap();
    bundle.lift(rng, app, &[invalid.as_dyn()], vec![]).unwrap();
}

#[test]
fn merge_after_lift() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let (_, bundle_a) = alice(app);
    let (_, bundle_b) = later_output(app);
    let stamp_a = &bundle_a.stamp;
    let stamp_b = &bundle_b.stamp;
    let desc_a = bundle_a
        .actions
        .iter()
        .zip(&bundle_a.action_auth)
        .map(|(&desc, &(_, pair))| (desc, pair))
        .collect();
    let fees_a = BTreeMap::from([(bundle_a.fee, bundle_a.fee_auth)]);
    let desc_b = bundle_b
        .actions
        .iter()
        .zip(&bundle_b.action_auth)
        .map(|(&desc, &(_, pair))| (desc, pair))
        .collect();
    let fees_b = BTreeMap::from([(bundle_b.fee, bundle_b.fee_auth)]);

    let digests: Vec<ActionDigest> = bundle_a
        .verify_covered(&[])
        .unwrap()
        .0
        .into_iter()
        .chain(bundle_b.verify_covered(&[]).unwrap().0)
        .collect();
    let unlifted = stamp_a
        .clone()
        .merge(
            rng,
            app,
            (&desc_a, &fees_a),
            (stamp_b.clone(), mock_txid(&bundle_b), &desc_b, &fees_b),
        )
        .unwrap();
    assert!(
        !unlifted
            .verify_proof(rng, app, digests.iter().copied())
            .unwrap()
    );

    let lifted_a = lifted(app, &bundle_a, pool, BlockHeight(1)..=BlockHeight(2));

    assert_eq!(lifted_a.stamp.anchor, stamp_b.anchor);
    let combined = merged(app, &lifted_a, &bundle_b);
    assert_eq!(combined.stamp.anchor, lifted_a.stamp.anchor);
    assert!(combined.stamp.verify_proof(rng, app, digests).unwrap());
}

#[test]
fn mismatched_merge_descriptors_fail_verification() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, bundle_a) = alice(app);
    let (_, bundle_b) = bob(app);
    let foreign = random_action(rng).0;
    let desc_a = bundle_a
        .actions
        .iter()
        .zip(&bundle_a.action_auth)
        .map(|(&desc, &(_, pair))| (desc, pair))
        .collect();
    let fees_a = BTreeMap::from([(bundle_a.fee, bundle_a.fee_auth)]);
    let desc_b = BTreeMap::from([(foreign, bundle_b.action_auth[0].1)]);
    let fees_b = BTreeMap::from([(bundle_b.fee, bundle_b.fee_auth)]);

    let digests: Vec<ActionDigest> = bundle_a
        .verify_covered(&[])
        .unwrap()
        .0
        .into_iter()
        .chain(bundle_b.verify_covered(&[]).unwrap().0)
        .collect();

    let mismatched = bundle_a
        .stamp
        .clone()
        .merge(
            rng,
            app,
            (&desc_a, &fees_a),
            (
                bundle_b.stamp.clone(),
                mock_txid(&bundle_b),
                &desc_b,
                &fees_b,
            ),
        )
        .unwrap();
    let mismatched_digests: Vec<ActionDigest> = bundle_a
        .verify_covered(&[])
        .unwrap()
        .0
        .into_iter()
        .chain([
            foreign.digest(bundle_b.action_auth[0].1),
            bundle_b.fee.digest(bundle_b.fee_auth),
        ])
        .collect();
    assert!(
        !mismatched
            .verify_proof(rng, app, mismatched_digests)
            .unwrap()
    );

    let honest = merged(app, &bundle_a, &bundle_b).stamp;
    assert!(honest.verify_proof(rng, app, digests).unwrap());
}
