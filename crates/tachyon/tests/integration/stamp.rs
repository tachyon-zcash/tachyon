extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString as _,
    vec,
    vec::Vec,
};
use core::assert_matches;

use corez::io;
use polynomials::AggregatorRank;
use ragu::{
    Pcd,
    circuits::polynomials,
    pasta::Pasta,
    pcd::profile::{Aggregator, Profiled},
};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, BlockHeight, Bundle, Stamp, Tachygram, TachygramSetPoly, VerificationError,
    action, bundle,
    entropy::ActionEntropy,
    fee,
    stamp::{
        self, ProveError,
        proof::{
            HEADER_SIZE,
            transaction::{Transaction, TransactionMerge},
        },
    },
    value, witness,
};

use super::fixtures::{application, trailer_prefix};
use crate::fixtures::{
    aggregator::{aggregated, aggregator, imported, proves, raw_import, verify_on},
    mock_sighash, mock_txid,
    pool::PoolSim,
    wallet::{
        WalletSim, alice, alice_output_note, compressed, later_output, lifted, output_plan,
        random_action, shared_sk, spend,
    },
};

/// Merge two transactions by hand under the aggregator profile, committing to
/// their deduplicated union, which is not the product of their sets when they
/// overlap.
fn forge_overlapping_merge(
    rng: &mut StdRng,
    app: &ragu::Application<
        'static,
        Profiled<Pasta, Aggregator<HEADER_SIZE>>,
        AggregatorRank,
        HEADER_SIZE,
        ragu::AcceleratedProver,
    >,
    (left, right): (
        &Bundle<Stamp<stamp::Uncompressed>>,
        &Bundle<Stamp<stamp::Uncompressed>>,
    ),
) -> Pcd<Profiled<Pasta, Aggregator<HEADER_SIZE>>, AggregatorRank, Transaction> {
    let (left_pcd, right_pcd) = (raw_import(rng, app, left), raw_import(rng, app, right));
    let mut digests = BTreeSet::new();
    let mut tachygrams = BTreeSet::new();
    for bundle in [left, right] {
        digests.extend(bundle.verify_covered().unwrap().0);
        tachygrams.extend(
            bundle
                .actions
                .iter()
                .flat_map(|action| <[Tachygram; 2]>::from(action.tachygrams))
                .chain([bundle.fee_auth]),
        );
    }
    let (pcd, ()) = app
        .fuse(
            rng,
            TransactionMerge,
            witness::transaction_merge(
                (*left_pcd.data(), *right_pcd.data()),
                digests.into_iter().collect(),
                tachygrams.into_iter().collect(),
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
    let fee_digest = fee::Descriptor {
        cv_feemax: max_fee_note.cv_feemax(),
        v_fee: value::Positive::ZERO,
    }
    .digest(Tachygram::from(
        max_fee_note.fee_change(value::Positive::ZERO).commitment(),
    ));

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
        let (stamp, pairs) = plan
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
            .chain([fee_digest])
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
    let (forged, pairs) = plan
        .prove(rng, app, &user.pak, vec![(secret, spendable, gapped)])
        .unwrap();
    let digests: Vec<ActionDigest> = pairs
        .iter()
        .map(|(desc, &pair)| desc.digest(pair))
        .chain([fee_digest])
        .collect();
    assert!(!forged.verify_proof(rng, app, digests).unwrap());
}

#[test]
fn overlapping_stamps_cannot_aggregate() {
    let wallet_app = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let pool = PoolSim::shared();
    let anchor = pool.mint_anchor();
    let (_, output_a) = alice(wallet_app);
    let plan_b = bundle::Plan::new(
        vec![],
        vec![output_plan(rng, alice_output_note())],
        wallet.random_note(0),
    );
    let signatures_b = plan_b
        .sign(
            rng,
            &mock_sighash(plan_b.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap();
    let proof_b = plan_b
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(rng, wallet_app, &wallet.pak, vec![])
        .unwrap();
    let output_b = plan_b.assemble(signatures_b, proof_b.0, proof_b.1, value::Positive::ZERO);
    let (_, spend_a) = spend(wallet_app);
    let note = PoolSim::shared_note(1000);
    let spendable = wallet.spendable_init(wallet_app, pool, &note, BlockHeight(1));
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
    let (stamp_b, pairs_b) = plan
        .stamp_plan(anchor, value::Positive::ZERO)
        .prove(
            rng,
            wallet_app,
            &wallet.pak,
            vec![(wallet.note_secret(wallet_app, note), spendable, vec![])],
        )
        .unwrap();
    let spend_b = plan.assemble(signatures, stamp_b, pairs_b, value::Positive::ZERO);

    for (left, right, expected) in [
        (&output_a, &output_b, "two outputs of the same note"),
        (&spend_a, &spend_b, "a spend reproven in both stamps"),
        (&output_a, &output_a, "a stamp merged with itself"),
    ] {
        // Coverage refuses the repeated leaves before the proof.
        let merged = imported(app, left)
            .merge(rng, app, imported(app, right), mock_txid(right))
            .unwrap();
        let stripped = compressed(wallet_app, right).strip();
        assert!(
            matches!(
                verify_on(app, rng, left, merged, &[&stripped]),
                Err(VerificationError::Coverage(_))
            ),
            "{expected}"
        );

        // A merge that hides the overlap does not verify.
        let forged = forge_overlapping_merge(rng, app, (left, right));
        assert!(
            !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
            "{expected}"
        );
    }
}

#[test]
fn verify_proof_action_multiset_invariants() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, stamped) = spend(app);

    let (digests, _) = stamped.verify_covered().unwrap();

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
fn full_wallet_stamp_has_a_fixed_trailer() {
    let app = &application();
    let (_, body) = alice(app);
    let mut bytes = Vec::new();
    body.stamp.write(&mut bytes).unwrap();
    let frame = body.stamp.proof.to_bytes().unwrap();
    assert_eq!(
        bytes,
        [trailer_prefix(&body.stamp).as_slice(), &frame].concat()
    );
    bytes.pop();
    assert_eq!(
        Stamp::<stamp::Uncompressed>::read(bytes.as_slice())
            .unwrap_err()
            .kind(),
        io::ErrorKind::UnexpectedEof
    );
}

#[test]
fn output_stamp_round_trips_and_binds_its_tachygram_set() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, alice) = alice(app);
    let (digests, _) = alice.verify_covered().unwrap();
    let stamp = alice.stamp;

    let mut buf: Vec<u8> = Vec::new();
    stamp.write(&mut buf).unwrap();
    let decoded = Stamp::<stamp::Uncompressed>::read(&*buf).unwrap();
    assert_eq!(decoded.anchor, stamp.anchor);
    assert_eq!(decoded.tachygram_set, stamp.tachygram_set);
    assert!(
        decoded
            .verify_proof(rng, app, digests.iter().copied())
            .unwrap()
    );

    let forged = Stamp {
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
    let (digests, _) = alice.verify_covered().unwrap();
    let descriptors: BTreeMap<_, _> = alice
        .actions
        .iter()
        .map(|action| (action.descriptor, action.tachygrams))
        .collect();
    let fees = BTreeMap::from([(alice.fee, alice.fee_auth)]);
    let fee_digest = alice.fee.digest(alice.fee_auth);
    let stamp = alice.stamp.clone();
    let lifted_to = BlockHeight(2);

    let span = pool.anchor_span(app, BlockHeight(1)..=lifted_to);
    let lifted = lifted(app, &alice, pool, BlockHeight(1)..=lifted_to).stamp;
    assert_eq!(lifted.anchor, pool.block(lifted_to).anchor());
    assert_eq!(lifted.tachygram_set, stamp.tachygram_set);
    assert!(
        lifted
            .verify_proof(rng, app, digests.iter().copied())
            .unwrap()
    );

    let mut bytes = Vec::new();
    stamp.write(&mut bytes).unwrap();
    let decoded = Stamp::<stamp::Uncompressed>::read(&*bytes).unwrap();
    let lifted_decoded = decoded
        .lift(rng, app, &descriptors, &fees, vec![span.clone()])
        .unwrap();
    assert_eq!(lifted_decoded.anchor, pool.block(lifted_to).anchor());
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
    let mut invalid = bundle;
    invalid.actions[0].descriptor.cv = value::Trapdoor::ZERO.commit(value::Positive::ZERO);
    invalid.fee.cv_feemax = invalid.actions[0].descriptor.cv;
    let descriptors = invalid
        .actions
        .iter()
        .map(|action| (action.descriptor, action.tachygrams))
        .collect();
    let fees = BTreeMap::from([(invalid.fee, invalid.fee_auth)]);

    // Even unusable coverage maps must not be inspected for an empty lift.
    invalid
        .stamp
        .clone()
        .lift(rng, app, &descriptors, &fees, vec![])
        .unwrap();
    invalid.lift(rng, app, vec![]).unwrap();
}

#[test]
fn merge_after_lift() {
    let wallet = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let (_, bundle_a) = alice(wallet);
    let (_, bundle_b) = later_output(wallet);
    let digests: Vec<ActionDigest> = bundle_a
        .verify_covered()
        .unwrap()
        .0
        .into_iter()
        .chain(bundle_b.verify_covered().unwrap().0)
        .collect();

    let unlifted = imported(app, &bundle_a)
        .merge(rng, app, imported(app, &bundle_b), mock_txid(&bundle_b))
        .unwrap();
    assert!(!proves(app, rng, unlifted, &digests));

    // The wallet lifts its own transaction before publishing it.
    let lifted_a = lifted(wallet, &bundle_a, pool, BlockHeight(1)..=BlockHeight(2));
    assert_eq!(lifted_a.stamp.anchor, bundle_b.stamp.anchor);
    let combined = aggregated(app, &lifted_a, &bundle_b);
    assert_eq!(combined.anchor(), lifted_a.stamp.anchor);
    assert!(proves(app, rng, combined, &digests));
}
