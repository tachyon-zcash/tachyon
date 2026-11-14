extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString as _,
    vec,
};
use core::assert_matches;

use rand::{SeedableRng as _, rngs::StdRng};
use udon::curve::Projective as _;
use zcash_tachyon::{
    ActionDigest, Anchor, Bundle, Note, Tachygram, TachygramSetPoly, VerificationError,
    VerifyCoverageError, bundle,
    constants::MAX_MONEY,
    fee,
    stamp::{
        self, Proof as _, ProofStamp,
        proof::{
            App, output,
            stamp::{Actions, FeeFuse, FeeSeed, OutputAction, Stamp},
        },
    },
    value, witness,
};

use super::fixtures::application;
use crate::fixtures::{
    PoolSim, WalletSim, build_lift_span, build_output_plan, mock_sighash, mock_wtxid, random_block,
    random_block_with, shared_sk, stamp_coverage,
};

fn fee_less_output_bundle(
    rng: &mut StdRng,
    app: &App<'_>,
    wallet: &WalletSim,
    anchor: Anchor,
    max_fee_note: Note,
) -> Bundle<ProofStamp<stamp::Uncompressed>> {
    let (rcv, theta, output_plan) = build_output_plan(rng, wallet.random_note(500));
    let (bind_pcd, ()) = app
        .seed(
            rng,
            output::OutputBind,
            witness::output_bind(((), ()), output_plan.note, rcv),
        )
        .unwrap();
    let (cm, pad, _cv) = *bind_pcd.data();
    let (pcd, ()) = app
        .fuse(
            rng,
            OutputAction,
            witness::output_action((*bind_pcd.data(), ()), theta, anchor),
            bind_pcd,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    let stamp = ProofStamp {
        coverage: stamp_coverage([output_plan.descriptor()], &[]),
        anchor,
        tachygram_set: TachygramSetPoly::from_iter([cm, pad]).commit(),
        proof: Box::new(pcd.proof().clone()),
        fee: value::Positive::ZERO,
        fee_change: max_fee_note.commitment().into(),
    };

    let plan = bundle::Plan::new(vec![], vec![output_plan], max_fee_note);
    plan.sign(
        rng,
        &mock_sighash(plan.commitment().unwrap()),
        &wallet.sk.derive_auth_private(),
    )
    .unwrap()
    .stamp(
        stamp,
        &BTreeMap::from([(output_plan.descriptor(), (cm.min(pad), cm.max(pad)))]),
    )
    .unwrap()
}

#[test]
fn fee_fuse_binds_its_sets() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_fee_note = wallet.random_note(300);
    let anchor = Anchor::random(rng);
    let left = fee_less_output_bundle(rng, app, &wallet, anchor, max_fee_note);

    let action_digests: BTreeSet<ActionDigest> = left
        .actions
        .iter()
        .map(|action| action.digest().unwrap())
        .collect();
    let valid = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(120).unwrap(),
        &action_digests,
        &left
            .actions
            .iter()
            .flat_map(|action| <[Tachygram; 2]>::from(action.tg))
            .collect(),
    );
    let other = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(50).unwrap(),
        &action_digests,
        &left
            .actions
            .iter()
            .flat_map(|action| <[Tachygram; 2]>::from(action.tg))
            .collect(),
    );

    for (corrupt, expected) in [
        (
            {
                let mut corrupt = valid.clone();
                corrupt.1 = value::Positive::try_from(301).unwrap();
                corrupt
            },
            "FeeFuse: change is out of range",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.2.0 = other.2.0.clone();
                corrupt
            },
            "FeeFuse: output action set must be the product of left and fee action sets",
        ),
        (
            {
                let mut corrupt = valid;
                corrupt.2.1 = other.2.1;
                corrupt
            },
            "FeeFuse: output tachygram set must be the product of left and fee tachygram sets",
        ),
    ] {
        assert_matches!(
            app
                .fuse(
                    rng,
                    FeeFuse,
                    corrupt,
                    left.stamp.proof.clone().carry::<Actions>(anchor),
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
    }
}

#[test]
fn fee_fuse_slack_boundaries() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let left = fee_less_output_bundle(rng, app, &wallet, anchor, wallet.random_note(300));
    let digests = left
        .actions
        .iter()
        .map(|action| action.digest().unwrap())
        .collect();
    let left_pcd = left.stamp.proof.clone().carry::<Actions>(anchor);
    for (maximum, fee) in [
        (0, 0),
        (1, 0),
        (1, 1),
        (1000, 1000),
        (MAX_MONEY, 0),
        (MAX_MONEY, MAX_MONEY),
    ] {
        let note = wallet.random_note(maximum);
        let witness = witness::fee_fuse(
            (anchor, ()),
            note,
            value::Positive::try_from(fee).unwrap(),
            &digests,
            &left
                .actions
                .iter()
                .flat_map(|action| <[Tachygram; 2]>::from(action.tg))
                .collect(),
        );
        let (pcd, ()) = app
            .fuse(
                rng,
                FeeFuse,
                witness.clone(),
                left_pcd.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(app.verify_differential(&pcd, &mut *rng).unwrap());
        if maximum < MAX_MONEY {
            let mut corrupt = witness;
            corrupt.1 = value::Positive::try_from(maximum + 1).unwrap();
            assert_matches!(
                app.fuse(
                    rng,
                    FeeFuse,
                    corrupt,
                    left_pcd.clone(),
                    app.bootstrap_proof().clone().carry::<()>(()),
                ).err(),
                Some(ragu_core::Error::InvalidWitness(err))
                    if err.to_string() == "FeeFuse: change is out of range"
            );
        }
    }
}

#[test]
fn fee_is_chosen_after_signing_up_to_the_max_and_applies_once() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, max_fee_note) =
        wallet.fee_bundle(rng, app, 1000, 700, 300);
    let sighash = mock_sighash(signed.commitment());

    let fees = [0u64, 120, 300];
    let bundles = fees.map(|fee| {
        let (stamp, pairs) = bundle_plan
            .stamp_plan(anchor, value::Positive::try_from(fee).unwrap())
            .prove(rng, app, &wallet.pak, spend_pcds.clone())
            .unwrap();
        signed.clone().stamp(stamp, &pairs).unwrap()
    });
    for bundle in &bundles {
        assert_eq!(bundle.commitment(), signed.commitment());
        bundle
            .verify(rng, app, &sighash, &mock_wtxid(bundle).into(), &[])
            .unwrap();
    }

    let [_, once, _] = bundles;
    let digests: BTreeSet<_> = once
        .actions
        .iter()
        .map(|action| action.digest().unwrap())
        .chain([once.fee_descriptor().digest().unwrap()])
        .collect();
    let repeated_witness = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(0).unwrap(),
        &digests,
        &once
            .actions
            .iter()
            .flat_map(|action| <[Tachygram; 2]>::from(action.tg))
            .chain([once.stamp.fee_change])
            .collect(),
    );
    assert_matches!(
        app.fuse(
            rng,
            FeeFuse,
            repeated_witness.clone(),
            once.stamp.proof.clone().carry::<Actions>(anchor),
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .err(),
        Some(ragu_core::Error::InvalidWitness(_))
    );
    let mut twice_stamp = once.stamp.clone();
    twice_stamp.tachygram_set = repeated_witness.2.1.commit();
    twice_stamp.coverage = [0; 32];
    let mut twice = Bundle {
        stamp: twice_stamp,
        ..once
    };

    assert_matches!(
        twice.verify(rng, app, &sighash, &mock_wtxid(&twice).into(), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::StampActionsMismatch
        ))
    );

    twice.stamp.coverage = stamp_coverage(twice.descriptors(), &[twice.fee_descriptor()]);

    let published_digests: Vec<ActionDigest> = twice
        .actions
        .iter()
        .map(|action| action.digest().unwrap())
        .chain([twice.fee_descriptor().digest().unwrap()])
        .collect();
    assert!(!twice.verify_proof(rng, app, &published_digests).unwrap());
}

#[test]
fn verify_rejects_a_fee_descriptor_shared_by_two_covered_bundles() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, _) = wallet.fee_bundle(rng, app, 1000, 700, 300);
    let sighash = mock_sighash(signed.commitment());

    let (stamp, pairs) = bundle_plan
        .stamp_plan(anchor, value::Positive::try_from(120).unwrap())
        .prove(rng, app, &wallet.pak, spend_pcds)
        .unwrap();
    let mut aggregate = signed.stamp(stamp, &pairs).unwrap();
    let fee_bearing = wallet.autonome(rng, app, anchor, vec![], vec![wallet.random_note(500)]);
    aggregate.stamp = aggregate
        .stamp
        .clone()
        .merge(
            rng,
            app,
            (
                aggregate.action_tachygrams().collect(),
                [aggregate.fee_descriptor()].into(),
            ),
            (
                fee_bearing.stamp.clone(),
                fee_bearing.action_tachygrams().collect(),
                [fee_bearing.fee_descriptor()].into(),
            ),
        )
        .unwrap();

    let mut adjunct = fee_bearing.strip(mock_wtxid(&aggregate));
    adjunct.cv_feemax = aggregate.cv_feemax;
    adjunct.stamp.fee = aggregate.stamp.fee;
    assert_matches!(
        aggregate.verify(
            rng,
            app,
            &sighash,
            &mock_wtxid(&aggregate).into(),
            &[&adjunct]
        ),
        Err(VerificationError::Coverage(
            VerifyCoverageError::DuplicateFees
        ))
    );
}

#[test]
fn verify_rejects_a_stamp_without_its_fee() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_fee_note = wallet.random_note(300);
    let anchor = Anchor::random(rng);
    let mut fee_less = fee_less_output_bundle(rng, app, &wallet, anchor, max_fee_note);
    let sighash = mock_sighash(fee_less.commitment());

    assert_matches!(
        fee_less.verify(rng, app, &sighash, &mock_wtxid(&fee_less).into(), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::StampActionsMismatch
        ))
    );

    fee_less.stamp.coverage = stamp_coverage(fee_less.descriptors(), &[fee_less.fee_descriptor()]);
    fee_less.stamp.tachygram_set = fee_less
        .actions
        .iter()
        .flat_map(|action| <[Tachygram; 2]>::from(action.tg))
        .chain([fee_less.stamp.fee_change])
        .collect::<TachygramSetPoly>()
        .commit();
    assert_matches!(
        fee_less.verify(rng, app, &sighash, &mock_wtxid(&fee_less).into(), &[]),
        Err(VerificationError::Disproved)
    );
}

#[test]
fn fee_applies_over_a_fee_bearing_adjunct() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let (bundle_plan, signed, spend_pcds, anchor, max_fee_note) =
        wallet.fee_bundle(rng, app, 1000, 700, 300);
    let sighash = mock_sighash(signed.commitment());

    let adjunct_max_fee_note = wallet.random_note(100);
    let (adjunct_plan, adjunct_signed, _) = wallet.signed(
        rng,
        app,
        vec![],
        vec![wallet.random_note(500)],
        adjunct_max_fee_note,
    );
    let (stamp, pairs) = adjunct_plan
        .stamp_plan(anchor, value::Positive::try_from(40).unwrap())
        .prove(rng, app, &wallet.pak, vec![])
        .unwrap();
    let adjunct = adjunct_signed.stamp(stamp, &pairs).unwrap();

    let (aggregate_stamp, aggregate_descriptors) = bundle_plan
        .stamp_plan(anchor, value::Positive::try_from(120).unwrap())
        .prove(rng, app, &wallet.pak, spend_pcds)
        .unwrap();
    let aggregate_fee_descriptors = BTreeSet::from([fee::Descriptor {
        cv_feemax: max_fee_note.cv_feemax(),
        v_fee: aggregate_stamp.fee,
        fee_change: aggregate_stamp.fee_change,
    }]);

    let merged_stamp = aggregate_stamp
        .merge(
            rng,
            app,
            (aggregate_descriptors.clone(), aggregate_fee_descriptors),
            (
                adjunct.stamp.clone(),
                adjunct.action_tachygrams().collect(),
                [adjunct.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    let aggregate = signed.stamp(merged_stamp, &aggregate_descriptors).unwrap();

    let final_id = mock_wtxid(&aggregate);
    aggregate
        .verify(
            rng,
            app,
            &sighash,
            &final_id.into(),
            &[&adjunct.strip(final_id)],
        )
        .unwrap();
}

#[test]
fn fee_bearing_aggregates_merge_and_lift() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let notes: Vec<Note> = [1000, 900, 800, 700]
        .map(|value| wallet.random_note(value))
        .into();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    let commitments: Vec<_> = notes.iter().map(Note::commitment).collect();
    pool.mine(random_block_with(rng, &[commitments], 1));
    let [mut left, left_auto, mut right, right_auto] = [0, 1, 2, 3].map(|i| {
        let spendable = wallet.spendable_init(rng, app, &notes[i], &pool, pool.height());
        let anchor = spendable.data().2;
        let (plan, signed, pcds) = wallet.signed(
            rng,
            app,
            vec![(notes[i], spendable)],
            vec![wallet.random_note(500)],
            wallet.random_note(100),
        );
        let (stamp, pairs) = plan
            .stamp_plan(anchor, value::Positive::try_from(40).unwrap())
            .prove(rng, app, &wallet.pak, pcds)
            .unwrap();
        signed.stamp(stamp, &pairs).unwrap()
    });
    let sighash = mock_sighash(left.commitment());

    for (bundle, auto) in [(&mut left, &left_auto), (&mut right, &right_auto)] {
        bundle.stamp = bundle
            .stamp
            .clone()
            .merge(
                rng,
                app,
                (
                    bundle.action_tachygrams().collect(),
                    [bundle.fee_descriptor()].into(),
                ),
                (
                    auto.stamp.clone(),
                    auto.action_tachygrams().collect(),
                    [auto.fee_descriptor()].into(),
                ),
            )
            .unwrap();
    }
    left.stamp = left
        .stamp
        .clone()
        .merge(
            rng,
            app,
            (
                left.action_tachygrams()
                    .chain(left_auto.action_tachygrams())
                    .collect(),
                [left.fee_descriptor(), left_auto.fee_descriptor()].into(),
            ),
            (
                right.stamp.clone(),
                right
                    .action_tachygrams()
                    .chain(right_auto.action_tachygrams())
                    .collect(),
                [right.fee_descriptor(), right_auto.fee_descriptor()].into(),
            ),
        )
        .unwrap();

    pool.mine(random_block(rng, 1, 1));
    let span = build_lift_span(rng, app, &pool, pool.height()..=pool.height());
    let lifted = left
        .lift(
            rng,
            app,
            &[left_auto.as_dyn(), right.as_dyn(), right_auto.as_dyn()],
            vec![span],
        )
        .unwrap();

    let id = mock_wtxid(&lifted);
    lifted
        .verify(
            rng,
            app,
            &sighash,
            &id.into(),
            &[
                &left_auto.strip(id),
                &right.strip(id),
                &right_auto.strip(id),
            ],
        )
        .unwrap();
}

#[test]
fn zero_action_fee_seed_round_trips_and_verifies() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let bundle = wallet.autonome(rng, app, anchor, vec![], vec![]);
    let sighash = mock_sighash(bundle.commitment());
    bundle
        .verify(rng, app, &sighash, &mock_wtxid(&bundle).into(), &[])
        .unwrap();
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    let decoded = Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*bytes).unwrap();
    assert_eq!(decoded.auth_digest(), bundle.auth_digest());
    decoded
        .verify(rng, app, &sighash, &mock_wtxid(&decoded).into(), &[])
        .unwrap();
}

#[test]
fn innocent_seed_merges_and_strips() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let mut innocent = wallet.autonome(rng, app, anchor, vec![], vec![]);
    let adjunct = wallet.autonome(rng, app, anchor, vec![], vec![wallet.random_note(100)]);
    innocent.stamp = innocent
        .stamp
        .clone()
        .merge(
            rng,
            app,
            (
                innocent.action_tachygrams().collect(),
                [innocent.fee_descriptor()].into(),
            ),
            (
                adjunct.stamp.clone(),
                adjunct.action_tachygrams().collect(),
                [adjunct.fee_descriptor()].into(),
            ),
        )
        .unwrap();

    let mut parent = wallet.autonome(rng, app, anchor, vec![], vec![wallet.random_note(200)]);
    parent.stamp = parent
        .stamp
        .clone()
        .merge(
            rng,
            app,
            (
                parent.action_tachygrams().collect(),
                [parent.fee_descriptor()].into(),
            ),
            (
                innocent.stamp.clone(),
                innocent
                    .action_tachygrams()
                    .chain(adjunct.action_tachygrams())
                    .collect(),
                [innocent.fee_descriptor(), adjunct.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    let parent_id = mock_wtxid(&parent);
    parent
        .verify(
            rng,
            app,
            &mock_sighash(parent.commitment()),
            &parent_id.into(),
            &[&adjunct.strip(parent_id), &innocent.strip(parent_id)],
        )
        .unwrap();
}

#[test]
fn fee_seed_binds_its_singletons_and_header() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let other_anchor = Anchor::random(rng);
    let valid = witness::fee_seed(((), ()), wallet.random_note(0), anchor);
    let other = witness::fee_seed(((), ()), wallet.random_note(0), anchor);

    for (corrupt, expected) in [
        (
            {
                let mut corrupt = valid.clone();
                corrupt.0.value = value::Positive::try_from(1).unwrap();
                corrupt
            },
            "FeeSeed: maximum fee must be zero",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.2 = other.2.clone();
                corrupt
            },
            "FeeSeed: fee action set does not commit to the fee digest",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.3 = other.3.clone();
                corrupt
            },
            "FeeSeed: fee tachygram set does not commit to the fee change note",
        ),
    ] {
        assert_matches!(
            app.seed(rng, FeeSeed, corrupt).err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
    }

    let (seed_pcd, ()) = app.seed(rng, FeeSeed, valid.clone()).unwrap();
    let compressed = {
        let compressed = app.compress(&seed_pcd, rng).unwrap();
        let bytes = compressed.proof().to_bytes().unwrap();
        stamp::Compressed::from_bytes(&bytes).unwrap()
    };
    let proof = {
        let bytes = seed_pcd.proof().to_bytes().unwrap();
        stamp::Uncompressed::from_bytes(&bytes).unwrap()
    };
    for (header, expected) in [
        ((valid.2.commit(), valid.3.commit(), anchor), true),
        ((other.2.commit(), valid.3.commit(), anchor), false),
        ((valid.2.commit(), other.3.commit(), anchor), false),
        ((valid.2.commit(), valid.3.commit(), other_anchor), false),
    ] {
        assert_eq!(proof.verify(rng, app, header).unwrap(), expected);
        assert_eq!(compressed.verify(rng, app, header).unwrap(), expected);
    }
    let pcd = seed_pcd.proof().clone().carry::<Stamp>((
        app.bridge_hash(valid.3.commit().as_ref().to_affine())
            .unwrap()
            .into(),
        anchor,
    ));
    assert!(app.verify_differential(&pcd, rng).unwrap());
}
