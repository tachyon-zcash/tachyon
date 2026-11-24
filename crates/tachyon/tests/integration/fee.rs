extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
};
use core::assert_matches;

use ragu::udon::field::Field as _;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionSetPoly, Anchor, BlockHeight, Bundle, Note, Tachygram, TachygramSetPoly,
    VerificationError, VerifyCoverageError, bundle,
    constants::MAX_MONEY,
    fee, note,
    pasta::Fp,
    stamp::{
        self, Proof as _, ProofStamp,
        proof::{
            App, output,
            transaction::{Actions, FeeFuse, FeeSeed, OutputAction, Transaction},
        },
    },
    value, witness,
};

use super::fixtures::application;
use crate::fixtures::{
    Proved, mock_sighash, mock_txid,
    pool::PoolSim,
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
        let stamp = ProofStamp {
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
        let proof = (
            stamp,
            BTreeMap::from([(output_plan.descriptor(), (cm.min(pad), cm.max(pad)))]),
            max_fee_note.commitment().into(),
            value::Positive::ZERO,
        );
        plan.assemble(signatures, proof)
    })
}

#[test]
fn fee_fuse_binds_its_action_set() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let max_fee_note = wallet.random_note(300);
    let anchor = PoolSim::shared().mint_anchor();
    let left = fee_less_output_bundle(app, max_fee_note);

    let action_digests = BTreeSet::from([left.actions[0].digest(left.action_auth[0].1)]);
    let valid = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(120).unwrap(),
        &action_digests,
    );
    let other = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(50).unwrap(),
        &action_digests,
    );
    let foreign_change = fee::Descriptor {
        cv_feemax: max_fee_note.cv_feemax(),
        v_fee: valid.1,
    }
    .digest(Tachygram::random(rng));

    for corrupt in [
        (
            max_fee_note,
            valid.1,
            action_digests
                .iter()
                .copied()
                .chain([foreign_change])
                .collect(),
        ),
        (
            max_fee_note,
            value::Positive::try_from(301).unwrap(),
            valid.2,
        ),
        (max_fee_note, valid.1, other.2),
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
        assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
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
    let action_digests = BTreeSet::from([left.actions[0].digest(left.action_auth[0].1)]);
    let zero_rcm = note::CommitmentTrapdoor::from(Fp::ZERO);

    let mut fuse_witness = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(120).unwrap(),
        &action_digests,
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
    let digests = BTreeSet::from([left.actions[0].digest(left.action_auth[0].1)]);
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
    let signatures = (
        at_fixture_fee
            .actions
            .iter()
            .zip(&at_fixture_fee.action_auth)
            .map(|(&descriptor, &(sig, _))| (descriptor, sig))
            .collect::<BTreeMap<_, _>>(),
        at_fixture_fee.binding_sig,
    );

    let [without_fee, maximum_fee] = [0u64, 300].map(|amount| {
        let fee = value::Positive::try_from(amount).unwrap();
        let proof = bundle_plan
            .stamp_plan(anchor, fee)
            .prove(rng, app, &wallet.pak, spend_pcds.clone())
            .unwrap();
        bundle_plan.assemble(signatures.clone(), proof)
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
    assert_ne!(bundles[0].auth_digest(), bundles[2].auth_digest());

    let [_, once, _] = bundles;
    let digests: BTreeSet<_> = once.verify_covered(&[]).unwrap().0.into_iter().collect();
    let repeated_witness = witness::fee_fuse(
        (anchor, ()),
        max_fee_note,
        value::Positive::try_from(0).unwrap(),
        &digests,
    );
    let (repeated, ()) = app
        .fuse(
            rng,
            FeeFuse,
            repeated_witness,
            once.stamp.proof.carry::<Actions>(anchor),
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(!app.verify_uncompressed(&repeated, &mut *rng).unwrap());
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
                &aggregate
                    .actions
                    .iter()
                    .zip(&aggregate.action_auth)
                    .map(|(&desc, &(_, pair))| (desc, pair))
                    .collect(),
                &BTreeMap::from([(aggregate.fee, aggregate.fee_auth)]),
            ),
            (
                fee_bearing.stamp.clone(),
                mock_txid(&fee_bearing),
                &fee_bearing
                    .actions
                    .iter()
                    .zip(&fee_bearing.action_auth)
                    .map(|(&desc, &(_, pair))| (desc, pair))
                    .collect(),
                &BTreeMap::from([(fee_bearing.fee, fee_bearing.fee_auth)]),
            ),
        )
        .unwrap();

    let mut adjunct = fee_bearing.strip();
    adjunct.fee = aggregate.fee;
    assert_matches!(
        aggregate.verify(rng, app, &sighash, &[&adjunct]),
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
        .action_auth
        .iter()
        .flat_map(|&(_, pair)| <[Tachygram; 2]>::from(pair))
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
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, signed) = spend_with_fee(app);
    let sighash = mock_sighash(signed.commitment());

    let [(_, adjunct), _, _] = outputs_with_fees(app);
    let aggregate_stamp = signed.stamp.clone();

    let merged_stamp = aggregate_stamp
        .merge(
            rng,
            app,
            (
                &signed
                    .actions
                    .iter()
                    .zip(&signed.action_auth)
                    .map(|(&desc, &(_, pair))| (desc, pair))
                    .collect(),
                &BTreeMap::from([(signed.fee, signed.fee_auth)]),
            ),
            (
                adjunct.stamp.clone(),
                mock_txid(&adjunct),
                &adjunct
                    .actions
                    .iter()
                    .zip(&adjunct.action_auth)
                    .map(|(&desc, &(_, pair))| (desc, pair))
                    .collect(),
                &BTreeMap::from([(adjunct.fee, adjunct.fee_auth)]),
            ),
        )
        .unwrap();
    let aggregate = Bundle {
        stamp: merged_stamp,
        ..signed
    };

    let stripped = adjunct.strip();
    aggregate.verify(rng, app, &sighash, &[&stripped]).unwrap();
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
                    &bundle
                        .actions
                        .iter()
                        .zip(&bundle.action_auth)
                        .map(|(&desc, &(_, pair))| (desc, pair))
                        .collect(),
                    &BTreeMap::from([(bundle.fee, bundle.fee_auth)]),
                ),
                (
                    auto.stamp.clone(),
                    mock_txid(auto),
                    &auto
                        .actions
                        .iter()
                        .zip(&auto.action_auth)
                        .map(|(&desc, &(_, pair))| (desc, pair))
                        .collect(),
                    &BTreeMap::from([(auto.fee, auto.fee_auth)]),
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
                &[&left, &left_auto]
                    .into_iter()
                    .flat_map(|bundle| {
                        bundle
                            .actions
                            .iter()
                            .zip(&bundle.action_auth)
                            .map(|(&desc, &(_, pair))| (desc, pair))
                    })
                    .collect(),
                &[&left, &left_auto]
                    .into_iter()
                    .map(|bundle| (bundle.fee, bundle.fee_auth))
                    .collect(),
            ),
            (
                right.stamp.clone(),
                mock_txid(&right),
                &[&right, &right_auto]
                    .into_iter()
                    .flat_map(|bundle| {
                        bundle
                            .actions
                            .iter()
                            .zip(&bundle.action_auth)
                            .map(|(&desc, &(_, pair))| (desc, pair))
                    })
                    .collect(),
                &[&right, &right_auto]
                    .into_iter()
                    .map(|bundle| (bundle.fee, bundle.fee_auth))
                    .collect(),
            ),
        )
        .unwrap();
    let adjunct_txids = BTreeSet::from([
        mock_txid(&left_auto),
        mock_txid(&right),
        mock_txid(&right_auto),
    ]);
    assert_eq!(left.stamp.adjuncts, adjunct_txids);

    let span = pool.anchor_span(app, BlockHeight(1)..=BlockHeight(2));
    let lifted = left
        .lift(
            rng,
            app,
            &[left_auto.as_dyn(), right.as_dyn(), right_auto.as_dyn()],
            vec![span],
        )
        .unwrap();
    assert_eq!(lifted.stamp.adjuncts, adjunct_txids);

    lifted
        .verify(
            rng,
            app,
            &sighash,
            &[&left_auto.strip(), &right.strip(), &right_auto.strip()],
        )
        .unwrap();
}

#[test]
fn zero_action_fee_seed_round_trips_and_verifies() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (_, bundle) = zero_action(app, PoolSim::shared().mint_anchor());
    let sighash = mock_sighash(bundle.commitment());
    bundle.verify(rng, app, &sighash, &[]).unwrap();
    let mut bytes = Vec::new();
    bundle.write(&mut bytes).unwrap();
    let decoded = Bundle::<ProofStamp<stamp::Uncompressed>>::read(&*bytes).unwrap();
    assert_eq!(decoded.auth_digest(), bundle.auth_digest());
    decoded.verify(rng, app, &sighash, &[]).unwrap();
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
                &innocent
                    .actions
                    .iter()
                    .zip(&innocent.action_auth)
                    .map(|(&desc, &(_, pair))| (desc, pair))
                    .collect(),
                &BTreeMap::from([(innocent.fee, innocent.fee_auth)]),
            ),
            (
                adjunct.stamp.clone(),
                mock_txid(&adjunct),
                &adjunct
                    .actions
                    .iter()
                    .zip(&adjunct.action_auth)
                    .map(|(&desc, &(_, pair))| (desc, pair))
                    .collect(),
                &BTreeMap::from([(adjunct.fee, adjunct.fee_auth)]),
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
                &parent
                    .actions
                    .iter()
                    .zip(&parent.action_auth)
                    .map(|(&desc, &(_, pair))| (desc, pair))
                    .collect(),
                &BTreeMap::from([(parent.fee, parent.fee_auth)]),
            ),
            (
                innocent.stamp.clone(),
                mock_txid(&innocent),
                &[&innocent, &adjunct]
                    .into_iter()
                    .flat_map(|bundle| {
                        bundle
                            .actions
                            .iter()
                            .zip(&bundle.action_auth)
                            .map(|(&desc, &(_, pair))| (desc, pair))
                    })
                    .collect(),
                &[&innocent, &adjunct]
                    .into_iter()
                    .map(|bundle| (bundle.fee, bundle.fee_auth))
                    .collect(),
            ),
        )
        .unwrap();
    assert_eq!(
        parent.stamp.adjuncts,
        BTreeSet::from([mock_txid(&adjunct), mock_txid(&innocent)])
    );
    parent
        .verify(
            rng,
            app,
            &mock_sighash(parent.commitment()),
            &[&adjunct.strip(), &innocent.strip()],
        )
        .unwrap();
}

#[test]
fn fee_seed_binds_its_singleton_and_header() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::random(rng);
    let other_anchor = Anchor::random(rng);
    let valid = witness::fee_seed(((), ()), wallet.random_note(0), anchor);
    let other = witness::fee_seed(((), ()), wallet.random_note(0), anchor);
    let foreign_change = fee::Descriptor {
        cv_feemax: valid.0.cv_feemax(),
        v_fee: value::Positive::ZERO,
    }
    .digest(Tachygram::random(rng));

    for corrupt in [
        (
            Note {
                value: value::Positive::try_from(1).unwrap(),
                ..valid.0
            },
            anchor,
            valid.2.clone(),
        ),
        (valid.0, anchor, other.2.clone()),
        (valid.0, anchor, ActionSetPoly::from_iter([foreign_change])),
    ] {
        let (forged, ()) = app.seed(rng, FeeSeed, corrupt).unwrap();
        assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
    }

    let (seed_pcd, ()) = app.seed(rng, FeeSeed, valid.clone()).unwrap();
    assert_eq!(
        seed_pcd.commitments(),
        [
            ActionSetPoly::from_iter([]).commit().into(),
            valid.2.commit().into()
        ],
        "the fee seed leaves padding in slot zero and its fee digest in slot one"
    );
    let compressed = {
        let compressed = app.compress(&seed_pcd, rng).unwrap();
        let bytes = compressed.proof().to_bytes().unwrap();
        stamp::Compressed::from_bytes(&bytes).unwrap()
    };
    let proof = {
        let bytes = seed_pcd.proof().to_bytes().unwrap();
        stamp::Uncompressed::from_bytes(&bytes).unwrap()
    };
    let action_commit = valid.2.commit();
    let other_commit = other.2.commit();
    for (header, expected) in [
        ((action_commit, anchor), true),
        ((other_commit, anchor), false),
        ((action_commit, other_anchor), false),
    ] {
        assert_eq!(proof.verify(rng, app, header).unwrap(), expected);
        assert_eq!(compressed.verify(rng, app, header).unwrap(), expected);
    }
    let tachygram_commit = TachygramSetPoly::from_iter([valid.0.commitment().into()]).commit();
    for (accumulator, expected) in [
        (action_commit.into(), true),
        (other_commit.into(), false),
        (tachygram_commit.into(), false),
    ] {
        let header = (app.bridge_hash(accumulator).unwrap().into(), anchor);
        let carried = proof.clone().carry::<Transaction>(header);
        assert_eq!(
            app.verify_differential(&carried, &mut *rng).unwrap(),
            expected
        );
        let carried_compressed = compressed.clone().carry::<Transaction>(header);
        assert_eq!(
            app.verify_compressed(&carried_compressed).unwrap(),
            expected
        );
    }
}

#[test]
fn historical_fee_seed_verifies_under_its_original_registry() {
    use stamp::proof::historical;

    let historical = historical::new_application().unwrap();
    // Registry tags of d1f5ffb0 with test-epoch-size. Keeping the old
    // header alone is not enough: changing another registration also changes
    // which historical proofs verify.
    #[cfg(feature = "test-epoch-size")]
    {
        assert_eq!(
            historical.native_registry().tag().to_bytes(),
            [
                79, 208, 109, 73, 234, 227, 217, 0, 0, 193, 238, 153, 127, 15, 1, 3, 249, 235, 80,
                99, 142, 203, 0, 243, 157, 87, 104, 55, 73, 16, 31, 45
            ]
        );
        assert_eq!(
            historical.nested_registry().tag().to_bytes(),
            [
                202, 56, 202, 144, 142, 231, 212, 109, 243, 209, 26, 104, 178, 82, 93, 198, 252,
                97, 242, 57, 240, 60, 157, 35, 210, 152, 42, 206, 63, 121, 85, 7
            ]
        );
    }
    let current = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let note = WalletSim::new(shared_sk()).random_note(0);
    let change = Tachygram::from(note.commitment());
    let digest = fee::Descriptor {
        cv_feemax: note.cv_feemax(),
        v_fee: value::Positive::ZERO,
    }
    .digest(change);
    let actions = ActionSetPoly::from_iter([digest]);
    let tachygrams = TachygramSetPoly::from_iter([change]);
    let tachygram_set = tachygrams.commit();
    let (pcd, ()) = historical
        .seed(
            rng,
            historical::FeeSeed,
            (note, anchor, actions, tachygrams),
        )
        .unwrap();
    let proof = historical.compress(&pcd, rng).unwrap();
    let stamp = ProofStamp {
        anchor,
        tachygram_set,
        adjuncts: BTreeSet::new(),
        proof: Box::new(proof.into_parts().0),
    };
    assert!(historical::verify_proof(&historical, &stamp, [digest]).unwrap());
    assert!(!historical::verify_proof(current, &stamp, [digest]).unwrap());
    assert!(!stamp.verify_proof(rng, current, [digest]).unwrap());
}
