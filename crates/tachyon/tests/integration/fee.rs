extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
};
use core::assert_matches;

use ragu::udon::field::Field as _;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, Anchor, BlockHeight, Bundle, Note, Tachygram, TachygramSetPoly,
    VerificationError, VerifyCoverageError, bundle,
    constants::MAX_MONEY,
    fee, note,
    pasta::Fp,
    stamp::{
        self, Stamp,
        proof::{
            App, output,
            transaction::{Actions, FeeFuse, FeeSeed, OutputAction, Transaction},
        },
    },
    value, witness,
};

use super::fixtures::application;
use crate::fixtures::{
    Proved,
    aggregator::{aggregated, aggregator, import_span, imported, verify_on},
    mock_sighash, mock_txid,
    pool::PoolSim,
    wallet::{
        WalletSim, alice, bob, compressed, output_plan, outputs_with_fees, shared_sk,
        spend_with_fee, spend_with_fee_max_fee_note, zero_action,
    },
};

fn fee_less_output_bundle(app: &App<'_>, max_fee_note: Note) -> Bundle<Stamp<stamp::Uncompressed>> {
    static FEE_LESS: Proved<Bundle<Stamp<stamp::Uncompressed>>> =
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
        let output_plan = output_plan(rng, note);
        let (bind_pcd, ()) = app
            .seed(
                rng,
                output::OutputBind,
                witness::output_bind(((), ()), output_plan.note, output_plan.rcv),
            )
            .unwrap();
        let (cm, pad, _cv) = *bind_pcd.data();
        let (pcd, ()) = app
            .fuse(
                rng,
                OutputAction,
                witness::output_action((*bind_pcd.data(), ()), output_plan.theta, anchor),
                bind_pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        let stamp = Stamp {
            anchor,
            tachygram_set: TachygramSetPoly::from_iter([cm, pad]).commit(),
            adjuncts: BTreeSet::new(),
            proof: Box::new(pcd.proof().clone()),
        };

        let plan = bundle::Plan::new(vec![], vec![output_plan], max_fee_note);
        let signatures = plan
            .sign(
                rng,
                &mock_sighash(plan.commitment().unwrap()),
                &wallet.sk.derive_auth_private(),
            )
            .unwrap();
        plan.assemble(
            signatures,
            stamp,
            BTreeMap::from([(output_plan.descriptor(), (cm.min(pad), cm.max(pad)))]),
            value::Positive::ZERO,
        )
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

    let action_digests = BTreeSet::from([left.actions[0].digest()]);
    let action_tachygrams = left
        .actions
        .iter()
        .flat_map(|action| <[Tachygram; 2]>::from(action.tachygrams))
        .collect();
    let valid = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(120).unwrap(),
        &action_digests,
        &action_tachygrams,
    );
    let other = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(50).unwrap(),
        &action_digests,
        &action_tachygrams,
    );

    for (corrupt, expected) in [
        (
            {
                let mut corrupt = valid.clone();
                corrupt.1 = value::Positive::try_from(301).unwrap();
                corrupt
            },
            "a fee above the maximum",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.2.0 = other.2.0.clone();
                corrupt
            },
            "a substituted output action set",
        ),
        (
            {
                let mut corrupt = valid;
                corrupt.2.1 = other.2.1;
                corrupt
            },
            "a substituted output tachygram set",
        ),
    ] {
        let (forged, ()) = app
            .fuse(
                rng,
                FeeFuse,
                corrupt,
                left.stamp.proof.clone().carry::<Actions>(anchor),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
            "{expected}"
        );
    }
}

#[test]
fn fee_fuse_and_fee_seed_reject_zero_rcm() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_fee_note = wallet.random_note(300);
    let anchor = PoolSim::shared().mint_anchor();
    let left = fee_less_output_bundle(app, max_fee_note);
    let action_digests = BTreeSet::from([left.actions[0].digest()]);
    let action_tachygrams = left
        .actions
        .iter()
        .flat_map(|action| <[Tachygram; 2]>::from(action.tachygrams))
        .collect();
    let zero_rcm = note::CommitmentTrapdoor::from(Fp::ZERO);

    let mut fuse_witness = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(120).unwrap(),
        &action_digests,
        &action_tachygrams,
    );
    fuse_witness.0.rcm = zero_rcm;
    let fuse = app.fuse(
        rng,
        FeeFuse,
        fuse_witness,
        left.stamp.proof.carry::<Actions>(anchor),
        app.bootstrap_proof().clone().carry::<()>(()),
    );
    let Err(ragu::Error::InvalidWitness(fuse_error)) = fuse else {
        panic!("FeeFuse: expected InvalidWitness, got {:?}", fuse.err());
    };
    assert_eq!(fuse_error.to_string(), "division by zero");

    let mut seed_witness = witness::fee_seed(((), ()), wallet.random_note(0), anchor);
    seed_witness.0.rcm = zero_rcm;
    let seed = app.seed(rng, FeeSeed, seed_witness);
    let Err(ragu::Error::InvalidWitness(seed_error)) = seed else {
        panic!("FeeSeed: expected InvalidWitness, got {:?}", seed.err());
    };
    assert_eq!(seed_error.to_string(), "division by zero");
}

#[test]
fn fee_fuse_slack_boundaries() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = PoolSim::shared().mint_anchor();
    let left = fee_less_output_bundle(app, wallet.random_note(300));
    let digests = BTreeSet::from([left.actions[0].digest()]);
    let action_tachygrams = left
        .actions
        .iter()
        .flat_map(|action| <[Tachygram; 2]>::from(action.tachygrams))
        .collect();
    let left_pcd = left.stamp.proof.carry::<Actions>(anchor);
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
            &action_tachygrams,
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
            let (forged, ()) = app
                .fuse(
                    rng,
                    FeeFuse,
                    corrupt,
                    left_pcd.clone(),
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .unwrap();
            assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
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
    let signatures = bundle::Signatures {
        actions: at_fixture_fee
            .actions
            .iter()
            .map(|action| (action.descriptor, action.signature))
            .collect(),
        binding: at_fixture_fee.binding_sig,
    };

    let [without_fee, maximum_fee] = [0u64, 300].map(|amount| {
        let fee = value::Positive::try_from(amount).unwrap();
        let (stamp, pairs) = bundle_plan
            .stamp_plan(anchor, fee)
            .prove(rng, app, &wallet.pak, spend_pcds.clone())
            .unwrap();
        bundle_plan.assemble(signatures.clone(), stamp, pairs, fee)
    });
    let bundles = [without_fee, at_fixture_fee, maximum_fee];
    for bundle in &bundles {
        assert_eq!(bundle.commitment(), commitment);
        bundle.verify(rng, app, &sighash, &[]).unwrap();
    }
    assert_eq!(bundles[0].fee.v_fee, value::Positive::ZERO);
    assert_eq!(
        bundles[2].fee.v_fee,
        value::Positive::try_from(300u64).unwrap()
    );
    assert_ne!(bundles[0].fee_auth, bundles[2].fee_auth);
    assert_ne!(
        bundles[0].clone().strip().auth_digest(),
        bundles[2].clone().strip().auth_digest()
    );

    let [_, once, _] = bundles;
    let digests: BTreeSet<_> = once.verify_covered(&[]).unwrap().0.into_iter().collect();
    let repeated_witness = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(0).unwrap(),
        &digests,
        &once
            .actions
            .iter()
            .flat_map(|action| <[Tachygram; 2]>::from(action.tachygrams))
            .chain([once.fee_auth])
            .collect(),
    );
    let (repeated, ()) = app
        .fuse(
            rng,
            FeeFuse,
            repeated_witness.clone(),
            once.stamp.proof.clone().carry::<Actions>(anchor),
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(!app.verify_uncompressed(&repeated, &mut *rng).unwrap());
    let mut twice_stamp = once.stamp.clone();
    twice_stamp.tachygram_set = repeated_witness.2.1.commit();
    let twice = Bundle {
        stamp: twice_stamp,
        ..once
    };

    assert_matches!(
        twice.verify(rng, app, &sighash, &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::WrongTachygramSet
        ))
    );

    let published_digests: Vec<ActionDigest> = digests.into_iter().collect();
    assert!(!twice.verify_proof(rng, app, &published_digests).unwrap());
}

#[test]
fn verify_rejects_a_fee_descriptor_shared_by_two_covered_bundles() {
    let wallet = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, host) = spend_with_fee(wallet);
    let (_, fee_bearing) = alice(wallet);
    let aggregate = aggregated(app, &host, &fee_bearing);

    let mut adjunct = fee_bearing.strip();
    adjunct.fee = host.fee;
    assert_matches!(
        verify_on(app, rng, &host, aggregate, &[&adjunct]),
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
        fee_less.verify(rng, app, &sighash, &[]),
        Err(VerificationError::Coverage(
            VerifyCoverageError::WrongTachygramSet
        ))
    );

    fee_less.stamp.tachygram_set = fee_less
        .actions
        .iter()
        .flat_map(|action| <[Tachygram; 2]>::from(action.tachygrams))
        .chain([fee_less.fee_auth])
        .collect::<TachygramSetPoly>()
        .commit();
    assert_matches!(
        fee_less.verify(rng, app, &sighash, &[]),
        Err(VerificationError::Disproved)
    );
}

#[test]
fn fee_applies_over_a_fee_bearing_adjunct() {
    let wallet = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, signed) = spend_with_fee(wallet);
    let [(_, adjunct), _, _] = outputs_with_fees(wallet);
    let aggregate = aggregated(app, &signed, &adjunct);
    verify_on(app, rng, &signed, aggregate, &[&adjunct.strip()]).unwrap();
}

#[test]
fn fee_bearing_aggregates_merge_and_lift() {
    let wallet_app = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let pool = PoolSim::shared();
    let (_, left) = spend_with_fee(wallet_app);
    let [left_auto, right, right_auto] = [900, 800, 700].map(|value| {
        let (_, bundle) = wallet.bundle(
            wallet_app,
            pool.mint_anchor(),
            &[(PoolSim::shared_note(value), pool)],
            &[wallet.random_note(500)],
            wallet.random_note(100),
            value::Positive::try_from(40u64).unwrap(),
        );
        bundle
    });

    let aggregate = aggregated(app, &left, &left_auto)
        .merge(
            rng,
            app,
            aggregated(app, &right, &right_auto),
            mock_txid(&right),
        )
        .unwrap();
    let adjunct_txids = BTreeSet::from([
        mock_txid(&left_auto),
        mock_txid(&right),
        mock_txid(&right_auto),
    ]);
    assert_eq!(aggregate.adjuncts(), &adjunct_txids);

    let span = import_span(rng, app, pool, BlockHeight(1), BlockHeight(2));
    let lifted = aggregate.lift(rng, app, vec![span]).unwrap();
    assert_eq!(lifted.adjuncts(), &adjunct_txids);

    verify_on(
        app,
        rng,
        &left,
        lifted,
        &[&left_auto.strip(), &right.strip(), &right_auto.strip()],
    )
    .unwrap();
}

#[test]
fn zero_action_fee_seed_round_trips_and_verifies() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, uncompressed) = zero_action(app, PoolSim::shared().mint_anchor());
    let sighash = mock_sighash(uncompressed.commitment());
    uncompressed.verify(rng, app, &sighash, &[]).unwrap();
    let bundle = compressed(app, &uncompressed);
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    let decoded = Bundle::<Stamp<stamp::Compressed>>::read(&*bytes).unwrap();
    assert_eq!(decoded.auth_digest(), bundle.auth_digest());
    decoded.verify(app, &sighash, &[]).unwrap();
}

#[test]
fn innocent_seed_merges_and_strips() {
    let wallet = &application();
    let app = &aggregator();
    let rng = &mut StdRng::seed_from_u64(0);
    // The innocent aggregate's own zero-fee stamp comes from an empty plan,
    // which the aggregator compresses and decompresses like any publication.
    let (_, innocent) = zero_action(wallet, PoolSim::shared().mint_anchor());
    let (_, adjunct) = alice(wallet);
    let seeded = aggregated(app, &innocent, &adjunct);

    let (_, parent) = bob(wallet);
    let aggregate = imported(app, &parent)
        .merge(rng, app, seeded, mock_txid(&innocent))
        .unwrap();
    assert_eq!(
        aggregate.adjuncts(),
        &BTreeSet::from([mock_txid(&adjunct), mock_txid(&innocent)])
    );
    verify_on(
        app,
        rng,
        &parent,
        aggregate,
        &[&adjunct.strip(), &innocent.strip()],
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
            "a nonzero maximum fee",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.2 = other.2.clone();
                corrupt
            },
            "a substituted fee action set",
        ),
        (
            {
                let mut corrupt = valid.clone();
                corrupt.3 = other.3.clone();
                corrupt
            },
            "a substituted fee tachygram set",
        ),
    ] {
        let (forged, ()) = app.seed(rng, FeeSeed, corrupt).unwrap();
        assert!(
            !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
            "{expected}"
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
    // The fee seed's one action digest, as `witness::fee_seed` derives it.
    let fee_digest = |note: Note| {
        let change = Tachygram::from(
            Note {
                value: value::Positive::ZERO,
                ..note
            }
            .commitment(),
        );
        fee::Descriptor {
            cv_feemax: note.cv_feemax(),
            v_fee: value::Positive::ZERO,
        }
        .digest(change)
    };
    for (digest, tachygram_set, stamp_anchor, expected) in [
        (fee_digest(valid.0), valid.3.commit(), anchor, true),
        (fee_digest(other.0), valid.3.commit(), anchor, false),
        (fee_digest(valid.0), other.3.commit(), anchor, false),
        (fee_digest(valid.0), valid.3.commit(), other_anchor, false),
    ] {
        let full = Stamp {
            anchor: stamp_anchor,
            tachygram_set,
            adjuncts: BTreeSet::new(),
            proof: Box::new(proof.clone()),
        };
        assert_eq!(full.verify_proof(rng, app, [digest]).unwrap(), expected);
        let published = Stamp {
            anchor: stamp_anchor,
            tachygram_set,
            adjuncts: BTreeSet::new(),
            proof: Box::new(compressed.clone()),
        };
        assert_eq!(published.verify_proof(app, [digest]).unwrap(), expected);
    }
    let pcd = seed_pcd.proof().clone().carry::<Transaction>((
        app.bridge_hash(valid.3.commit().into()).unwrap().into(),
        anchor,
    ));
    assert!(app.verify_differential(&pcd, rng).unwrap());
}
