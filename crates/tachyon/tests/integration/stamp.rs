extern crate alloc;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    string::ToString as _,
    vec,
    vec::Vec,
};
use core::assert_matches;

use corez::io;
use ragu_circuits::polynomials::ProductionRank;
use ragu_core::pasta::Pasta;
use rand::{SeedableRng as _, rngs::StdRng};
use rand_core::CryptoRng;
use udon::curve::Projective as _;
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, BlockHeight, CompactSize, ProofStamp, Tachygram, TachygramSetPoly,
    action, bundle,
    entropy::ActionEntropy,
    fee,
    stamp::{
        self, ProveError,
        proof::{
            App,
            stamp::{Stamp, StampMerge},
        },
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

fn forge_overlapping_merge<RNG: CryptoRng>(
    rng: &mut RNG,
    app: &App<'_>,
    (stamp_a, stamp_b): (
        &ProofStamp<stamp::Uncompressed>,
        &ProofStamp<stamp::Uncompressed>,
    ),
    (digests, tachygrams): (&[ActionDigest], &[Tachygram]),
) -> ragu::Pcd<Pasta, ProductionRank, Stamp> {
    let left_pcd = stamp_a.proof.clone().carry::<Stamp>((
        app.bridge_hash(stamp_a.tachygram_set.as_ref().to_affine())
            .unwrap()
            .into(),
        stamp_a.anchor,
    ));
    let right_pcd = stamp_b.proof.clone().carry::<Stamp>((
        app.bridge_hash(stamp_b.tachygram_set.as_ref().to_affine())
            .unwrap()
            .into(),
        stamp_b.anchor,
    ));

    let merged_acts = digests.iter().copied().collect::<ActionSetPoly>();
    let merged_tg = tachygrams.iter().copied().collect::<TachygramSetPoly>();

    let (pcd, ()) = app
        .fuse(
            rng,
            StampMerge,
            witness::stamp_merge(
                (*left_pcd.data(), *right_pcd.data()),
                merged_acts,
                merged_tg,
            ),
            left_pcd,
            right_pcd,
        )
        .unwrap();

    pcd
}

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
    .digest(max_fee_note.commitment().into())
    .unwrap();
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

    let swapped = plan
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
    let swapped_pairs: BTreeMap<_, _> = BTreeSet::from([plan_a.descriptor(), plan_b.descriptor()])
        .into_iter()
        .zip(
            swapped
                .tachygrams
                .as_chunks::<2>()
                .0
                .iter()
                .copied()
                .map(<(Tachygram, Tachygram)>::from),
        )
        .collect();
    assert!(
        !swapped
            .verify_proof(
                rng,
                app,
                [
                    plan_a.digest(swapped_pairs[&plan_a.descriptor()]).unwrap(),
                    plan_b.digest(swapped_pairs[&plan_b.descriptor()]).unwrap(),
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
    .prove(rng, app, &user.pak, vec![(secret_a, sp_a, vec![])])
    .unwrap();
    assert!(
        !foreign
            .verify_proof(
                rng,
                app,
                [
                    foreign_a
                        .digest((foreign.tachygrams[0], foreign.tachygrams[1]))
                        .unwrap(),
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
    let (out_rcv, out_theta, output) = output_plan(rng, user.random_note(200));
    let secret = user.note_secret(app, note);
    let max_fee_note = user.random_note(0);
    let plan = stamp::Plan::new(
        vec![(spend.descriptor(), theta, rcv)],
        vec![(output.descriptor(), out_theta, output.note, out_rcv)],
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
        let stamp = plan
            .clone()
            .prove(
                rng,
                app,
                &user.pak,
                vec![(secret.clone(), spendable.clone(), spans)],
            )
            .unwrap();
        assert!(
            stamp
                .tachygrams
                .as_chunks::<2>()
                .0
                .iter()
                .all(|&[first, second]| first < second)
        );
        let digests: Vec<ActionDigest> = BTreeSet::from([spend.descriptor(), output.descriptor()])
            .into_iter()
            .zip(stamp.tachygrams.as_chunks::<2>().0)
            .map(|(desc, &pair)| desc.digest(pair.into()).unwrap())
            .chain([fee::Descriptor {
                cv_feemax: max_fee_note.cv_feemax(),
                v_fee: value::Positive::ZERO,
            }
            .digest(*stamp.tachygrams.last().unwrap())
            .unwrap()])
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
    assert_matches!(
        plan.prove(rng, app, &user.pak, vec![(secret, spendable, gapped)]),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err))) if err.to_string()
            == "ActionLift: actions anchor is neither the span's start nor a member"
    );
}

#[test]
fn overlapping_stamps_cannot_aggregate() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let pool = PoolSim::shared();
    let anchor = pool.mint_anchor();
    let (_, alice_bundle) = alice(app);
    let alice_note = alice_output_note();
    let covered_a = alice_bundle.covered();
    let output_a = alice_bundle.stamp;
    let (_, _, plan_b) = output_plan(rng, alice_note);
    let max_fee_note = wallet.random_note(0);
    let output_b = bundle::Plan::new(vec![], vec![plan_b], max_fee_note)
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(rng, app, &wallet.pak, vec![])
        .unwrap();
    let covered_b = (
        vec![plan_b.descriptor()],
        fee::Descriptor {
            cv_feemax: max_fee_note.cv_feemax(),
            v_fee: value::Positive::ZERO,
        },
        output_b.tachygrams.clone(),
    );
    let (_, spend_a) = spend(app);
    let note = PoolSim::shared_note(1000);
    let spendable = wallet.spendable_init(app, pool, &note, BlockHeight(1));
    let rcv = value::Trapdoor::random(rng);
    let theta = ActionEntropy::random(rng);
    let spend_plan = action::Plan::spend(note, theta, rcv, |alpha| {
        wallet.pak.ak.derive_action_public(&alpha)
    });
    let (_, _, output) = output_plan(rng, wallet.random_note(600));
    let plan = bundle::Plan::new(vec![spend_plan], vec![output], wallet.random_note(0));
    let signed = plan
        .sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap();
    let second_spend_stamp = plan
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(
            rng,
            app,
            &wallet.pak,
            vec![(wallet.note_secret(app, note), spendable, vec![])],
        )
        .unwrap();
    let spend_b = signed.stamp(second_spend_stamp);

    for ((left, left_covered), (right, right_covered), expected) in [
        (
            (output_a.clone(), vec![covered_a.clone()]),
            (output_b, vec![covered_b]),
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        ),
        (
            (spend_a.stamp.clone(), vec![spend_a.covered()]),
            (spend_b.stamp.clone(), vec![spend_b.covered()]),
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        ),
        (
            (output_a.clone(), vec![covered_a.clone()]),
            (output_a, vec![covered_a]),
            "StampMerge: merged action set must be the product of left and right action sets",
        ),
    ] {
        assert_matches!(
            left.clone().merge(
                rng,
                app,
                left_covered.clone(),
                (right.clone(), [0; 32], right_covered.clone()),
            ),
            Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err)))
                if err.to_string() == expected
        );

        let mut digests = Vec::new();
        let mut merged_tachygrams = Vec::new();
        for (descriptors, fee_descriptor, tachygrams) in
            left_covered.into_iter().chain(right_covered)
        {
            merged_tachygrams.extend(tachygrams.iter().copied());
            let (&fee_change, pairs) = tachygrams.split_last().unwrap();
            for (descriptor, &pair) in descriptors.iter().zip(pairs.as_chunks::<2>().0) {
                digests.push(descriptor.digest(pair.into()).unwrap());
            }
            digests.push(fee_descriptor.digest(fee_change).unwrap());
        }
        let forged =
            forge_overlapping_merge(rng, app, (&left, &right), (&digests, &merged_tachygrams));
        let stamp = ProofStamp {
            anchor: forged.data().1,
            tachygram_set: merged_tachygrams
                .iter()
                .copied()
                .collect::<BTreeSet<Tachygram>>()
                .into_iter()
                .collect::<TachygramSetPoly>()
                .commit(),
            adjuncts: BTreeSet::new(),
            proof: Box::new(forged.proof().clone()),
            fee: left.fee,
            tachygrams: left.tachygrams.clone(),
        };
        assert!(!stamp.verify_proof(rng, app, digests).unwrap());
    }
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
                .digest((Tachygram::random(rng), Tachygram::random(rng)))
                .unwrap()],
        ]
        .concat(),
        [
            &[random_action(rng)
                .digest((Tachygram::random(rng), Tachygram::random(rng)))
                .unwrap()],
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
    let n_actions = (stamp.tachygrams.len() - 1) / 2;
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
        let err = ProofStamp::<stamp::Uncompressed>::read(&mut reader, n_actions).unwrap_err();
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
        let err = ProofStamp::<stamp::Compressed>::read(&*bytes, n_actions).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "proof size exceeds transport bound");
    }
}

#[test]
fn output_stamp_round_trips_and_binds_its_tachygram_set() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(app);
    let (digests, _) = alice.verify_covered(&[]).unwrap();
    let stamp = alice.stamp;

    let mut buf: Vec<u8> = Vec::new();
    stamp.write(&mut buf).unwrap();
    let decoded =
        ProofStamp::<stamp::Uncompressed>::read(&*buf, (stamp.tachygrams.len() - 1) / 2).unwrap();
    assert_eq!(decoded.fee, stamp.fee);
    assert_eq!(decoded.tachygrams, stamp.tachygrams);
    assert_eq!(decoded.adjuncts, stamp.adjuncts);
    assert_eq!(decoded.anchor, stamp.anchor);
    assert_eq!(decoded.tachygram_set, stamp.tachygram_set);

    let forged = ProofStamp {
        tachygram_set: TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit(),
        ..stamp
    };
    assert!(!forged.verify_proof(rng, app, digests).unwrap());
}

#[test]
fn lift_moves_the_anchor_and_keeps_the_proof_valid() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let (_, alice) = alice(app);
    let (digests, _) = alice.verify_covered(&[]).unwrap();
    let (_, fee_descriptor, tachygrams) = alice.covered();
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
    let decoded =
        ProofStamp::<stamp::Uncompressed>::read(&*bytes, (stamp.tachygrams.len() - 1) / 2).unwrap();
    let lifted_decoded = decoded
        .lift(rng, app, vec![alice.covered()], vec![span.clone()])
        .unwrap();
    assert_eq!(lifted_decoded.anchor, pool.block(lifted_to).anchor());
    assert_eq!(lifted_decoded.adjuncts, stamp.adjuncts);
    assert!(lifted_decoded.verify_proof(rng, app, digests).unwrap());

    let foreign = vec![(
        vec![random_action(rng).descriptor()],
        fee_descriptor,
        tachygrams,
    )];
    assert_matches!(
        stamp.lift(rng, app, foreign, vec![span]),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(_)))
    );
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

    assert_matches!(
        stamp_a.clone().merge(
            rng,
            app,
            vec![bundle_a.covered()],
            (
                stamp_b.clone(),
                mock_txid(&bundle_b),
                vec![bundle_b.covered()]
            ),
        ),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err)))
            if err.to_string() == "StampMerge: anchors must match"
    );

    let lifted_a = lifted(app, &bundle_a, pool, BlockHeight(1)..=BlockHeight(2));

    assert_eq!(lifted_a.stamp.anchor, stamp_b.anchor);
    let combined = merged(app, &lifted_a, &bundle_b);
    assert_eq!(combined.stamp.anchor, lifted_a.stamp.anchor);
}

#[test]
fn mismatched_merge_descriptors_fail_verification() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, bundle_a) = alice(app);
    let (_, bundle_b) = bob(app);
    let foreign = random_action(rng).descriptor();

    let digests: Vec<ActionDigest> = bundle_a
        .verify_covered(&[])
        .unwrap()
        .0
        .into_iter()
        .chain(bundle_b.verify_covered(&[]).unwrap().0)
        .collect();

    assert_matches!(
        bundle_a.stamp.clone().merge(
            rng,
            app,
            vec![bundle_a.covered()],
            (
                bundle_b.stamp.clone(),
                mock_txid(&bundle_b),
                vec![(
                    vec![foreign],
                    bundle_b.fee_descriptor(),
                    bundle_b.stamp.tachygrams.clone(),
                )],
            ),
        ),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(_)))
    );

    let honest = merged(app, &bundle_a, &bundle_b).stamp;
    assert!(honest.verify_proof(rng, app, digests).unwrap());
}
