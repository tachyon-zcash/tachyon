extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    string::ToString as _,
    vec,
};
use core::assert_matches;

use rand::{SeedableRng as _, rngs::StdRng};
use udon::{curve::Projective as _, field::Field as _};
use zcash_tachyon::{
    ActionDigest, Anchor, BlockHeight, Bundle, Note, Tachygram, TachygramSetPoly,
    VerificationError, VerifyCoverageError, bundle,
    constants::MAX_MONEY,
    pasta::Fp,
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
    Proved, mock_sighash, mock_wtxid,
    pool::PoolSim,
    stamp_coverage,
    wallet::{
        WalletSim, alice, bob, output_plan, outputs_with_fees, shared_sk, spend_with_fee,
        spend_with_fee_max_fee_note, zero_action,
    },
};

fn fee_less_output_bundle(
    app: &App<'_>,
    max_fee_note: Note,
) -> Bundle<ProofStamp<stamp::Uncompressed>> {
    static FEE_LESS: Proved<Bundle<ProofStamp<stamp::Uncompressed>>> =
        Proved::new("fee less output bundle");
    let anchor = PoolSim::shared().mint_anchor();
    let wallet = WalletSim::new(shared_sk());
    let note = wallet.labelled_note("fee-less output", 500);
    let key = [
        Fp::from(anchor).to_bytes(),
        Fp::from(note.commitment()).to_bytes(),
        Fp::from(max_fee_note.commitment()).to_bytes(),
    ]
    .concat();
    FEE_LESS.get(&key, |rng| {
        let (rcv, theta, output_plan) = output_plan(rng, note);
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
            tachygrams: stamp::Tachygrams {
                pairs: vec![(cm.min(pad), cm.max(pad))],
                fee_change: max_fee_note.commitment().into(),
            },
        };

        let plan = bundle::Plan::new(vec![], vec![output_plan], max_fee_note);
        plan.sign(
            rng,
            &mock_sighash(plan.commitment().unwrap()),
            &wallet.sk.derive_auth_private(),
        )
        .unwrap()
        .stamp(stamp)
        .unwrap()
    })
}

#[test]
fn fee_fuse_binds_its_sets() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_fee_note = wallet.random_note(300);
    let anchor = PoolSim::shared().mint_anchor();
    let left = fee_less_output_bundle(app, max_fee_note);

    let action_digests: BTreeSet<ActionDigest> = left
        .actions()
        .map(|action| action.digest().unwrap())
        .collect();
    let valid = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(120).unwrap(),
        &action_digests,
        &left
            .stamp
            .tachygrams
            .pairs
            .iter()
            .copied()
            .flat_map(<[Tachygram; 2]>::from)
            .collect(),
    );
    let other = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(50).unwrap(),
        &action_digests,
        &left
            .stamp
            .tachygrams
            .pairs
            .iter()
            .copied()
            .flat_map(<[Tachygram; 2]>::from)
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
    let anchor = PoolSim::shared().mint_anchor();
    let left = fee_less_output_bundle(app, wallet.random_note(300));
    let digests = left
        .actions()
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
                .stamp
                .tachygrams
                .pairs
                .iter()
                .copied()
                .flat_map(<[Tachygram; 2]>::from)
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
    let (bundle_plan, at_fixture_fee) = spend_with_fee(app);
    let anchor = at_fixture_fee.stamp.anchor;
    let max_fee_note = spend_with_fee_max_fee_note();
    let note = PoolSim::shared_note(1000);
    let spend_pcds = vec![(
        wallet.note_secret(app, note),
        wallet.spendable_init(app, PoolSim::shared(), &note, BlockHeight(1)),
        vec![],
    )];
    let commitment = at_fixture_fee.commitment();
    let sighash = mock_sighash(commitment);

    let [without_fee, maximum_fee] = [0u64, 300].map(|fee| {
        let stamp = bundle_plan
            .stamp_plan(anchor, value::Positive::try_from(fee).unwrap())
            .prove(rng, app, &wallet.pak, spend_pcds.clone())
            .unwrap();
        Bundle {
            stamp,
            ..at_fixture_fee.clone()
        }
    });
    let bundles = [without_fee, at_fixture_fee, maximum_fee];
    for bundle in &bundles {
        assert_eq!(bundle.commitment(), commitment);
        bundle
            .verify(rng, app, &sighash, &mock_wtxid(bundle).into(), &[])
            .unwrap();
    }

    let [_, once, _] = bundles;
    let digests: BTreeSet<_> = once
        .actions()
        .map(|action| action.digest().unwrap())
        .chain([once.fee_descriptor().digest().unwrap()])
        .collect();
    let repeated_witness = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(0).unwrap(),
        &digests,
        &once
            .stamp
            .tachygrams
            .pairs
            .iter()
            .copied()
            .flat_map(<[Tachygram; 2]>::from)
            .chain([once.stamp.tachygrams.fee_change])
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
        .actions()
        .map(|action| action.digest().unwrap())
        .chain([twice.fee_descriptor().digest().unwrap()])
        .collect();
    assert!(!twice.verify_proof(rng, app, &published_digests).unwrap());
}

#[test]
fn verify_rejects_a_fee_descriptor_shared_by_two_covered_bundles() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, mut aggregate) = spend_with_fee(app);
    let sighash = mock_sighash(aggregate.commitment());
    let (_, fee_bearing) = alice(app);
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
    let mut fee_less = fee_less_output_bundle(app, max_fee_note);
    let sighash = mock_sighash(fee_less.commitment());

    assert_matches!(
        fee_less.verify(rng, app, &sighash, &mock_wtxid(&fee_less).into(), &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::StampActionsMismatch
        ))
    );

    fee_less.stamp.coverage = stamp_coverage(fee_less.descriptors(), &[fee_less.fee_descriptor()]);
    fee_less.stamp.tachygram_set = fee_less
        .stamp
        .tachygrams
        .pairs
        .iter()
        .copied()
        .flat_map(<[Tachygram; 2]>::from)
        .chain([fee_less.stamp.tachygrams.fee_change])
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
    let (_, signed) = spend_with_fee(app);
    let sighash = mock_sighash(signed.commitment());

    let [(_, adjunct), _, _] = outputs_with_fees(app);
    let aggregate_stamp = signed.stamp.clone();
    let aggregate_descriptors: BTreeMap<_, _> = signed.action_tachygrams().collect();
    let aggregate_fee_descriptors = BTreeSet::from([signed.fee_descriptor()]);

    let merged_stamp = aggregate_stamp
        .merge(
            rng,
            app,
            (aggregate_descriptors, aggregate_fee_descriptors),
            (
                adjunct.stamp.clone(),
                adjunct.action_tachygrams().collect(),
                [adjunct.fee_descriptor()].into(),
            ),
        )
        .unwrap();
    let aggregate = Bundle {
        stamp: merged_stamp,
        ..signed
    };

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
    let pool = PoolSim::shared();
    let (_, mut left) = spend_with_fee(app);
    let [left_auto, mut right, right_auto] = [900, 800, 700].map(|value| {
        let (_, bundle) = wallet.bundle(
            app,
            pool.mint_anchor(),
            &[(PoolSim::shared_note(value), pool)],
            &[wallet.random_note(500)],
            wallet.random_note(100),
            value::Positive::try_from(40u64).unwrap(),
        );
        bundle
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

    let span = pool.anchor_span(app, BlockHeight(1)..=BlockHeight(2));
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
    let (_, bundle) = zero_action(app, PoolSim::shared().mint_anchor());
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
    let (_, mut innocent) = zero_action(app, PoolSim::shared().mint_anchor());
    let (_, adjunct) = alice(app);
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

    let (_, mut parent) = bob(app);
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
