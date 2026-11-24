use ragu::{
    Cycle as _, FixedGenerators as _,
    pasta::{EpAffine, Fp, Pasta},
    pcd::{ipa::IpaCycle as _, profile::ProfiledCycle},
    udon::{curve::Affine as _, field::Field as _},
};
use ragu_pcd::pasta::{baked as baked_wallet, baked_aggregator};
use rand::{SeedableRng as _, rngs::StdRng};
use transaction::{PublicTransaction, Transaction, TransactionDehydrate, TransactionRehydrate};
use zcash_tachyon::{
    ActionSetBridge, ActionSetPoly, Anchor, EpochIndex, Note,
    keys::ProofAuthorizingKey,
    stamp::proof::{
        HEADER_SIZE, delegation, new_aggregator_application, new_application, spend, spendable,
        transaction,
    },
    value, witness,
};

use super::{
    dehydrate::funded_output,
    fixtures::wallet::{WalletSim, shared_sk},
};

fn spend_header<C: ProfiledCycle<Base = Pasta, CircuitField = Fp>, R: ragu::Rank>(
    app: &ragu::Application<'_, C, R, HEADER_SIZE, ragu::AcceleratedProver>,
    rng: &mut StdRng,
    note: Note,
    pak: ProofAuthorizingKey,
) -> ragu::Pcd<C, R, spend::SpendHeader> {
    let unit = app.bootstrap_proof().clone().carry::<()>(());
    let secret = app
        .seed(
            rng,
            delegation::NoteSeed,
            witness::note_seed(((), ()), note, pak),
        )
        .unwrap()
        .0;
    let epoch = EpochIndex::new(0);
    let window = app
        .fuse(
            rng,
            delegation::NullifierDerive,
            witness::nullifier_derive((*secret.data(), ()), epoch),
            secret.clone(),
            unit.clone(),
        )
        .unwrap()
        .0;
    let anchor = Anchor::from(Fp::from(11));
    let init = witness::spendable_init(
        (*window.data(), ()),
        anchor,
        &[note.commitment().into()],
        epoch,
    );
    let lineage = app
        .fuse(rng, spendable::SpendableInit, init, window, unit)
        .unwrap()
        .0;
    let blind = value::Trapdoor::random(rng);
    app.fuse(rng, spend::SpendBind, (blind,), lineage, secret)
        .unwrap()
        .0
}

#[test]
fn paired_app_imports_wallet_spend_headers_but_cannot_issue_them() {
    let rng = &mut StdRng::seed_from_u64(711);
    let app = new_aggregator_application(rng).unwrap();
    let wallet = new_application().unwrap();
    let owner = WalletSim::new(shared_sk());
    let note = owner.random_note(37);
    let issued = spend_header(&wallet, rng, note, owner.pak);
    let public = wallet.compress(&issued, &mut *rng).unwrap();
    let imported = app.decompress(rng, &public).unwrap();
    assert_eq!(imported.data().0, issued.data().0);
    assert_eq!(imported.data().3, issued.data().3);
    assert!(
        app.verify_compressed(&app.compress(&imported, &mut *rng).unwrap())
            .unwrap()
    );
    let foreign = spend_header(&app, rng, note, owner.pak);
    assert!(
        !app.verify_compressed(&app.compress(&foreign, &mut *rng).unwrap())
            .unwrap()
    );
}

#[test]
fn aggregator_rehydrates_only_the_finalized_wallet_action_set() {
    let rng = &mut StdRng::seed_from_u64(40);
    let params = baked_aggregator();
    let baked = baked_wallet();
    let prefix = Pasta::host_generators(baked).g();
    assert_eq!(prefix, &Pasta::host_generators(params).g()[..prefix.len()]);
    for i in [3975, 8071, 16263, 32647] {
        assert_eq!(
            Pasta::nested_generator(baked, i),
            Some(Pasta::nested_generators(params).g()[i])
        );
    }
    let step = TransactionRehydrate::new().unwrap();
    let app = new_aggregator_application(rng).unwrap();
    // Issue on the ordinary baked wallet, independently of the wallet verifier
    // constructed with the aggregator's larger parameter object above.
    let issuer = new_application().unwrap();
    let wallet = issuer.as_ref();
    let anchor = Anchor::from(Fp::from(42));
    let bundle = funded_output(wallet, &WalletSim::new(shared_sk()), anchor);
    let (digests, _) = bundle.verify_covered(&[]).unwrap();
    let actions = ActionSetPoly::from_iter(digests.iter().copied());
    let coefficients: Vec<_> = actions
        .as_ref()
        .iter_coeffs()
        .take(digests.len() + 1)
        .collect();
    let commitment = actions.commit();
    assert_eq!(app.commit(&coefficients).unwrap(), commitment.into());
    let portable = ActionSetBridge::from(wallet.bridge_hash(commitment.into()).unwrap());
    let local = ActionSetBridge::from(app.bridge_hash(commitment.into()).unwrap());
    assert_ne!(portable, local);

    // An honestly compressed working proof is valid in W, but its online
    // action slot cannot substitute for the padding required at import.
    let working = bundle
        .stamp
        .proof
        .clone()
        .carry::<Transaction>((portable, anchor));
    let ordinary = wallet.compress(&working, &mut *rng).unwrap();
    assert!(wallet.verify_compressed(&ordinary).unwrap());
    assert!(app.decompress(rng, &ordinary).is_err());
    let disguised = ordinary
        .into_parts()
        .0
        .carry::<PublicTransaction>((portable, anchor));
    assert!(app.decompress(rng, &disguised).is_err());

    let finalized = bundle.stamp.finalize(rng, wallet).unwrap();
    let fields = (portable, finalized.anchor);
    let publication = finalized.proof.clone().carry::<PublicTransaction>(fields);
    assert!(
        app.context()
            .wallet()
            .verify_compressed(&publication)
            .unwrap()
    );
    let input = app.decompress(rng, &publication).unwrap();
    assert_eq!(input.data(), &fields);
    // Import verifies the padded source header, not merely the proof bytes.
    let other_anchor = Anchor::from(Fp::from(43));
    let (x, y) = EpAffine::from(portable).coordinates().unwrap();
    let other_bridge = ActionSetBridge::from(EpAffine::from_xy(x, -y).unwrap());
    for other in [(portable, other_anchor), (other_bridge, anchor)] {
        assert!(
            app.decompress(
                rng,
                &finalized.proof.clone().carry::<PublicTransaction>(other)
            )
            .is_err()
        );
    }
    assert!(
        app.decompress(rng, &finalized.proof.carry::<Transaction>(fields))
            .is_err()
    );

    let unit = app.bootstrap_proof().clone().carry::<()>(());
    let (restored, ()) = app
        .fuse(
            rng,
            step.clone(),
            (actions.clone(), commitment),
            input.clone(),
            unit.clone(),
        )
        .unwrap();
    assert_eq!(restored.polynomials(), [vec![Fp::ONE], coefficients]);
    assert_eq!(restored.commitments()[1], commitment.into());
    assert_eq!(restored.data(), &(local, anchor));
    let candidate = app.compress(&restored, &mut *rng).unwrap().into_parts().0;
    let claimed = |data| candidate.clone().carry::<Transaction>(data);
    assert!(app.verify_compressed(&claimed((local, anchor))).unwrap());
    assert!(
        !app.verify_compressed(&claimed((local, other_anchor)))
            .unwrap()
    );
    assert!(!app.verify_compressed(&claimed((portable, anchor))).unwrap());

    // Step 39's wallet padding check also excludes local aggregator issuance.
    let (reissued, ()) = app
        .fuse(rng, TransactionDehydrate, (), restored, unit.clone())
        .unwrap();
    assert!(
        !app.verify_compressed(&app.compress(&reissued, &mut *rng).unwrap())
            .unwrap()
    );

    // Keep the roots but repeat one: root membership cannot detect this change.
    let replacement = ActionSetPoly::from_iter(digests.iter().copied().chain([digests[0]]));
    let other = replacement.commit();
    assert_ne!(other, commitment);
    for witness in [
        (replacement.clone(), commitment),
        (replacement, other),
        (actions, other),
    ] {
        let (wrong, ()) = app
            .fuse(rng, step.clone(), witness, input.clone(), unit.clone())
            .unwrap();
        let compressed = app.compress(&wrong, &mut *rng).unwrap();
        assert!(!app.verify_compressed(&compressed).unwrap());
    }
}
