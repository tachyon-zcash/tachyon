extern crate alloc;

use alloc::collections::BTreeMap;
use core::assert_matches;

use ragu::pcd::pasta::baked;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionSetPoly, Anchor, Bundle, Tachygram, TachygramSetCommit, TachygramSetPoly,
    VerificationError, VerifyCoverageError,
    pasta::{EqAffine, Fp},
    stamp::{
        ProofStamp, Uncompressed,
        proof::{
            App, WalletPublicationApp,
            publication::{
                PublishedStamp, StampBindActionSet, StampBindings, StampPublish,
                StampRestoreActionSet, StampRestoreTachygramSet,
            },
            publication_builder,
            stamp::Stamp,
        },
    },
    value,
};

use super::fixtures::{
    mock_sighash, mock_txid,
    wallet::{WalletSim, shared_sk},
};

fn fee_bearing_output(
    wallet: &WalletSim,
    app: &App<'_>,
    anchor: Anchor,
) -> Bundle<ProofStamp<Uncompressed>> {
    wallet
        .bundle(
            app,
            anchor,
            &[],
            &[wallet.labelled_note("publication output", 500)],
            wallet.labelled_note("publication max fee", 100),
            value::Positive::try_from(40).unwrap(),
        )
        .1
}

#[test]
fn wallet_publication_checks_signed_coverage() {
    let rng = &mut StdRng::seed_from_u64(39);
    let bootstrap = publication_builder()
        .unwrap()
        .finalize(baked())
        .unwrap()
        .bootstrap_proof()
        .clone();
    let registry = WalletPublicationApp::new(rng, bootstrap).unwrap();
    let app = registry.application();
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::from(42));
    let (_, fee_only) = wallet.bundle(
        app,
        anchor,
        &[],
        &[],
        wallet.labelled_note("publication fee only", 0),
        value::Positive::ZERO,
    );
    let stamped = fee_bearing_output(&wallet, app, anchor);
    let empty_body = fee_only.clone().strip();
    for bundle in [&fee_only, &stamped] {
        let publication = bundle.stamp.clone().publish(rng, &registry).unwrap();
        let body = bundle.clone().strip();
        let sighash = mock_sighash(body.commitment());
        assert_eq!(
            publication
                .verify(&registry, &body, &sighash, |_| None)
                .unwrap(),
            bundle.stamp.tachygram_set
        );
        let pad = EqAffine::from(TachygramSetCommit::default());
        assert_eq!(publication.proof.online_commitments(), [pad, pad]);
        // The fee paid is authorization data. Changing only it preserves the
        // signatures and every tachygram but changes the fee digest in A.
        let mut other_fee = body;
        other_fee.fee.v_fee = value::Positive::try_from(1).unwrap();
        assert_matches!(
            publication.verify(&registry, &other_fee, &sighash, |_| None),
            Err(VerificationError::Disproved)
        );
    }

    let id = mock_txid(&fee_only);
    let rows = stamped
        .actions
        .iter()
        .zip(&stamped.action_auth)
        .map(|(&desc, &(_, pair))| (desc, pair))
        .collect();
    let merged = stamped
        .stamp
        .clone()
        .merge(
            rng,
            app,
            (&rows, &BTreeMap::from([(stamped.fee, stamped.fee_auth)])),
            (
                fee_only.stamp,
                id,
                &BTreeMap::new(),
                &BTreeMap::from([(fee_only.fee, fee_only.fee_auth)]),
            ),
        )
        .unwrap()
        .publish(rng, &registry)
        .unwrap();
    let body = stamped.strip();
    let sighash = mock_sighash(body.commitment());
    assert_eq!(
        merged
            .verify(&registry, &body, &sighash, |txid| (*txid == id)
                .then_some(&empty_body))
            .unwrap(),
        merged.tachygram_set
    );
    assert_matches!(
        merged.verify(&registry, &body, &sighash, |_| None),
        Err(VerificationError::Coverage(
            VerifyCoverageError::MissingAdjunct
        ))
    );
    assert_matches!(
        merged.verify(&registry, &body, &sighash, |_| Some(&body)),
        Err(VerificationError::Coverage(
            VerifyCoverageError::DuplicateActions
        ))
    );
}

#[test]
fn wallet_publication_binds_and_restores_both_columns() {
    let rng = &mut StdRng::seed_from_u64(42);
    let app = publication_builder().unwrap().finalize(baked()).unwrap();
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::from(42));
    let stamped = fee_bearing_output(&wallet, &app, anchor);
    let (digests, tachygrams) = stamped.verify_covered(&[]).unwrap();
    let actions = ActionSetPoly::from_iter(digests.iter().copied());
    let pairs = stamped
        .action_auth
        .iter()
        .flat_map(|&(_, pair)| <[Tachygram; 2]>::from(pair));
    let tachygram_poly = TachygramSetPoly::from_iter(pairs.chain([stamped.fee_auth]));
    let action_point = app.bridge_hash(actions.commit().into()).unwrap();
    let tachygram_point = app.bridge_hash(tachygrams.into()).unwrap();
    let working = stamped
        .stamp
        .proof
        .clone()
        .carry::<Stamp>((tachygram_point.into(), anchor));
    let unit = app.bootstrap_proof().clone().carry::<()>(());
    let (bound, ()) = app
        .fuse(rng, StampBindActionSet, (), working, unit.clone())
        .unwrap();
    let (padded, ()) = app
        .fuse(rng, StampPublish, (), bound, unit.clone())
        .unwrap();
    let published = app
        .compress(
            &app.rerandomize(padded.clone(), &mut *rng).unwrap(),
            &mut *rng,
        )
        .unwrap();
    assert!(app.verify_compressed(&published).unwrap());
    let (proof, header) = published.into_parts();
    let swapped = StampBindings {
        anchor,
        portable_tachygrams: action_point.into(),
        actions: tachygram_point.into(),
    };
    assert!(
        !app.verify_compressed(&proof.clone().carry::<PublishedStamp>(swapped))
            .unwrap()
    );
    let wrong_reference = StampBindings {
        anchor: Anchor::from(Fp::from(43)),
        ..header
    };
    assert!(
        !app.verify_compressed(&proof.carry::<PublishedStamp>(wrong_reference))
            .unwrap()
    );
    let (restored_actions, ()) = app
        .fuse(
            rng,
            StampRestoreActionSet,
            actions.clone(),
            padded.clone(),
            unit.clone(),
        )
        .unwrap();
    let (restored, ()) = app
        .fuse(
            rng,
            StampRestoreTachygramSet,
            tachygram_poly,
            restored_actions.clone(),
            unit.clone(),
        )
        .unwrap();
    assert_eq!(
        restored.commitments(),
        [EqAffine::from(actions.commit()), EqAffine::from(tachygrams)]
    );
    assert!(
        app.verify_compressed(&app.compress(&restored, &mut *rng).unwrap())
            .unwrap()
    );

    // A shared fee root in each candidate does not identify either product.
    let (wrong_actions, ()) = app
        .fuse(
            rng,
            StampRestoreActionSet,
            ActionSetPoly::from_iter([stamped.fee.digest(stamped.fee_auth)]),
            padded,
            unit.clone(),
        )
        .unwrap();
    assert!(!app.verify_uncompressed(&wrong_actions, &mut *rng).unwrap());
    let (wrong_tachygrams, ()) = app
        .fuse(
            rng,
            StampRestoreTachygramSet,
            TachygramSetPoly::from_iter([stamped.fee_auth]),
            restored_actions,
            unit,
        )
        .unwrap();
    assert!(
        !app.verify_uncompressed(&wrong_tachygrams, &mut *rng)
            .unwrap()
    );
}
