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
    (stamp_a, descriptors_a, fee_descriptors_a): (
        &ProofStamp<stamp::Uncompressed>,
        &BTreeMap<action::Descriptor, (Tachygram, Tachygram)>,
        &[fee::Descriptor],
    ),
    (stamp_b, descriptors_b, fee_descriptors_b): (
        &ProofStamp<stamp::Uncompressed>,
        &BTreeMap<action::Descriptor, (Tachygram, Tachygram)>,
        &[fee::Descriptor],
    ),
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

    let merged_acts = descriptors_a
        .iter()
        .chain(descriptors_b.iter())
        .map(|(desc, pair)| ActionDigest::new(*desc, *pair).unwrap())
        .chain(
            fee_descriptors_a
                .iter()
                .chain(fee_descriptors_b)
                .copied()
                .map(|descriptor| descriptor.digest().unwrap()),
        )
        .collect::<ActionSetPoly>();
    let merged_tg = descriptors_a
        .values()
        .chain(descriptors_b.values())
        .copied()
        .flat_map(<[Tachygram; 2]>::from)
        .chain(
            fee_descriptors_a
                .iter()
                .chain(fee_descriptors_b)
                .map(|fee| fee.fee_change),
        )
        .collect::<TachygramSetPoly>();

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
        fee_change: max_fee_note.commitment().into(),
    }
    .digest()
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
        .zip(swapped.tachygrams.pairs.iter().copied())
        .collect();
    assert!(
        !swapped
            .verify_proof(
                rng,
                app,
                [
                    ActionDigest::new(plan_a.descriptor(), swapped_pairs[&plan_a.descriptor()])
                        .unwrap(),
                    ActionDigest::new(plan_b.descriptor(), swapped_pairs[&plan_b.descriptor()])
                        .unwrap(),
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
                    ActionDigest::new(foreign_a.descriptor(), foreign.tachygrams.pairs[0]).unwrap(),
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
                .pairs
                .iter()
                .all(|&(first, second)| first < second)
        );
        let digests: Vec<ActionDigest> = BTreeSet::from([spend.descriptor(), output.descriptor()])
            .into_iter()
            .zip(&stamp.tachygrams.pairs)
            .map(|(desc, &pair)| ActionDigest::new(desc, pair).unwrap())
            .chain([fee::Descriptor {
                cv_feemax: max_fee_note.cv_feemax(),
                v_fee: value::Positive::ZERO,
                fee_change: stamp.tachygrams.fee_change,
            }
            .digest()
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
    let descriptor_a = alice_bundle.descriptors().next().unwrap();
    let pair_a = alice_bundle.stamp.tachygrams.pairs[0];
    let output_a = alice_bundle.stamp.clone();
    let fee_a = alice_bundle.fee_descriptor();
    let (_, _, plan_b) = output_plan(rng, alice_note);
    let max_fee_note = wallet.random_note(0);
    let output_b = bundle::Plan::new(vec![], vec![plan_b], max_fee_note)
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(rng, app, &wallet.pak, vec![])
        .unwrap();
    let pair_b = output_b.tachygrams.pairs[0];
    let fee_b = fee::Descriptor {
        cv_feemax: max_fee_note.cv_feemax(),
        v_fee: value::Positive::ZERO,
        fee_change: output_b.tachygrams.fee_change,
    };
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
    let spend_b = signed.stamp(second_spend_stamp).unwrap();

    for ((left, left_descriptors, left_fees), (right, right_descriptors, right_fees), expected) in [
        (
            (
                output_a.clone(),
                BTreeMap::from([(descriptor_a, pair_a)]),
                BTreeSet::from([fee_a]),
            ),
            (
                output_b,
                BTreeMap::from([(plan_b.descriptor(), pair_b)]),
                BTreeSet::from([fee_b]),
            ),
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        ),
        (
            (
                spend_a.stamp.clone(),
                spend_a.action_tachygrams().collect(),
                BTreeSet::from([spend_a.fee_descriptor()]),
            ),
            (
                spend_b.stamp.clone(),
                spend_b.action_tachygrams().collect(),
                BTreeSet::from([spend_b.fee_descriptor()]),
            ),
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        ),
        (
            (
                output_a.clone(),
                BTreeMap::from([(descriptor_a, pair_a)]),
                BTreeSet::from([fee_a]),
            ),
            (
                output_a,
                BTreeMap::from([(descriptor_a, pair_a)]),
                BTreeSet::from([fee_a]),
            ),
            "StampMerge: merged action set must be the product of left and right action sets",
        ),
    ] {
        assert_matches!(
            left.clone().merge(
                rng,
                app,
                (left_descriptors.clone(), left_fees.clone()),
                (
                    right.clone(),
                    [0; 32],
                    right_descriptors.clone(),
                    right_fees.clone()
                ),
            ),
            Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(err)))
                if err.to_string() == expected
        );

        let forged = forge_overlapping_merge(
            rng,
            app,
            (
                &left,
                &left_descriptors,
                &left_fees.iter().copied().collect::<Vec<_>>(),
            ),
            (
                &right,
                &right_descriptors,
                &right_fees.iter().copied().collect::<Vec<_>>(),
            ),
        );
        let fees: Vec<fee::Descriptor> = left_fees.iter().chain(&right_fees).copied().collect();
        let tachygrams: BTreeSet<Tachygram> = left_descriptors
            .values()
            .chain(right_descriptors.values())
            .copied()
            .flat_map(<[Tachygram; 2]>::from)
            .chain(fees.iter().map(|fee| fee.fee_change))
            .collect();
        let stamp = ProofStamp {
            anchor: forged.data().1,
            tachygram_set: tachygrams
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit(),
            adjuncts: BTreeSet::new(),
            proof: Box::new(forged.proof().clone()),
            fee: left.fee,
            tachygrams: left.tachygrams.clone(),
        };
        let digests: Vec<ActionDigest> = left_descriptors
            .iter()
            .chain(&right_descriptors)
            .map(|(desc, pair)| ActionDigest::new(*desc, *pair).unwrap())
            .chain(fees.iter().map(|descriptor| descriptor.digest().unwrap()))
            .collect();
        assert!(!stamp.verify_proof(rng, app, digests).unwrap());
    }
}

#[test]
fn verify_proof_action_multiset_invariants() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, stamped) = spend(app);

    let digests: Vec<ActionDigest> = stamped
        .actions()
        .map(|action| action.digest().unwrap())
        .chain([stamped.fee_descriptor().digest().unwrap()])
        .collect();

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
        [digests.as_slice(), &[random_action(rng).digest().unwrap()]].concat(),
        [&[random_action(rng).digest().unwrap()], &digests[1..]].concat(),
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
    let n_actions = stamp.tachygrams.pairs.len();
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
    let digest = alice.actions().next().unwrap().digest().unwrap();
    let fee_descriptor = alice.fee_descriptor();
    let stamp = alice.stamp;

    let mut buf: Vec<u8> = Vec::new();
    stamp.write(&mut buf).unwrap();
    let decoded =
        ProofStamp::<stamp::Uncompressed>::read(&*buf, stamp.tachygrams.pairs.len()).unwrap();
    assert_eq!(decoded.fee, stamp.fee);
    assert_eq!(decoded.tachygrams, stamp.tachygrams);
    assert_eq!(decoded.adjuncts, stamp.adjuncts);
    assert_eq!(decoded.anchor, stamp.anchor);
    assert_eq!(decoded.tachygram_set, stamp.tachygram_set);

    let forged = ProofStamp {
        tachygram_set: TachygramSetPoly::from_iter([Tachygram::random(rng)]).commit(),
        ..stamp
    };
    assert!(
        !forged
            .verify_proof(rng, app, [digest, fee_descriptor.digest().unwrap()])
            .unwrap()
    );
}

#[test]
fn lift_moves_the_anchor_and_keeps_the_proof_valid() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let (_, alice) = alice(app);
    let digest = alice.actions().next().unwrap().digest().unwrap();
    let pair = alice.stamp.tachygrams.pairs[0];
    let descriptors = alice.action_tachygrams().collect();
    let fee_descriptor = alice.fee_descriptor();
    let stamp = alice.stamp.clone();
    let lifted_to = BlockHeight(2);
    let fees = BTreeSet::from([fee_descriptor]);
    let digests = [digest, fee_descriptor.digest().unwrap()];

    let span = pool.anchor_span(app, BlockHeight(1)..=lifted_to);
    let lifted = lifted(app, &alice, pool, BlockHeight(1)..=lifted_to).stamp;
    assert_eq!(lifted.anchor, pool.block(lifted_to).anchor());
    assert_eq!(lifted.adjuncts, stamp.adjuncts);
    assert_eq!(lifted.tachygram_set, stamp.tachygram_set);
    assert!(lifted.verify_proof(rng, app, digests).unwrap());

    let mut bytes = Vec::new();
    stamp.write(&mut bytes).unwrap();
    let decoded =
        ProofStamp::<stamp::Uncompressed>::read(&*bytes, stamp.tachygrams.pairs.len()).unwrap();
    let lifted_decoded = decoded
        .lift(rng, app, &descriptors, &fees, vec![span.clone()])
        .unwrap();
    assert_eq!(lifted_decoded.anchor, pool.block(lifted_to).anchor());
    assert_eq!(lifted_decoded.adjuncts, stamp.adjuncts);
    assert!(lifted_decoded.verify_proof(rng, app, digests).unwrap());

    let foreign = BTreeMap::from([(random_action(rng).descriptor, pair)]);
    assert_matches!(
        stamp.lift(rng, app, &foreign, &fees, vec![span]),
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

    let (desc_a, desc_b): (BTreeMap<_, _>, BTreeMap<_, _>) = (
        bundle_a.action_tachygrams().collect(),
        bundle_b.action_tachygrams().collect(),
    );
    let (fee_set_a, fee_set_b) = (
        BTreeSet::from([bundle_a.fee_descriptor()]),
        BTreeSet::from([bundle_b.fee_descriptor()]),
    );

    assert_matches!(
        stamp_a.clone().merge(
            rng,
            app,
            (desc_a, fee_set_a),
            (stamp_b.clone(), mock_txid(&bundle_b), desc_b, fee_set_b),
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
    let fees_a = BTreeSet::from([bundle_a.fee_descriptor()]);
    let fees_b = BTreeSet::from([bundle_b.fee_descriptor()]);
    let descriptors_a: BTreeMap<_, _> = bundle_a.action_tachygrams().collect();
    let descriptors_b: BTreeMap<_, _> = bundle_b.action_tachygrams().collect();
    let foreign = random_action(rng).descriptor;

    let digests: Vec<ActionDigest> = descriptors_a
        .iter()
        .chain(&descriptors_b)
        .map(|(desc, pair)| ActionDigest::new(*desc, *pair).unwrap())
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
            app,
            (descriptors_a, fees_a),
            (
                bundle_b.stamp.clone(),
                mock_txid(&bundle_b),
                BTreeMap::from([(foreign, bundle_b.stamp.tachygrams.pairs[0])]),
                fees_b,
            ),
        ),
        Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(_)))
    );

    let honest = merged(app, &bundle_a, &bundle_b).stamp;
    assert!(honest.verify_proof(rng, app, digests).unwrap());
}
