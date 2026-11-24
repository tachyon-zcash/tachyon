use ragu::{
    header::{Header, Suffix},
    udon::{curve::Affine as _, field::Field as _},
};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionSetBridge, ActionSetCommit, ActionSetPoly, Anchor, Bundle,
    pasta::{EpAffine, EqAffine, Fp},
    stamp::{
        Compressed, Proof as _, ProofStamp, Uncompressed,
        proof::{
            self, App,
            transaction::{PublicTransaction, Transaction, TransactionDehydrate},
        },
    },
    value,
};

use super::fixtures::{
    mock_sighash,
    wallet::{WalletSim, shared_sk},
};

fn funded_output(
    app: &App<'_>,
    wallet: &WalletSim,
    anchor: Anchor,
) -> Bundle<ProofStamp<Uncompressed>> {
    wallet
        .bundle(
            app,
            anchor,
            &[],
            &[wallet.labelled_note("finalized output", 500)],
            wallet.labelled_note("finalized max fee", 100),
            value::Positive::try_from(40).unwrap(),
        )
        .1
}

#[test]
fn dehydrate_copies_the_certified_action_binding() {
    assert_eq!(<PublicTransaction as Header<Fp>>::SUFFIX, Suffix::new(17));
    let app = proof::new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(40);
    let anchor = Anchor::from(Fp::from(42));
    let wallet = WalletSim::new(shared_sk());
    let bundle = funded_output(&app, &wallet, anchor);
    let (digests, tachygrams) = bundle.verify_covered(&[]).unwrap();
    let actions = ActionSetPoly::from_iter(digests);
    let commitment = EqAffine::from(actions.commit());
    let bridge = ActionSetBridge::from(app.bridge_hash(commitment).unwrap());
    let wrong_bridge = ActionSetBridge::from(app.bridge_hash(tachygrams.into()).unwrap());
    let working = bundle.stamp.proof.carry::<Transaction>((bridge, anchor));
    let unit = app.bootstrap_proof().clone().carry::<()>(());
    let pad = app.commit(&[Fp::ONE]).unwrap();

    // Dehydration must use the certified working field, even when the prover
    // attaches a different, well-formed bridge to the same working proof.
    let (working_proof, _) = working.clone().into_parts();
    let substituted = working_proof.carry::<Transaction>((wrong_bridge, anchor));
    let (false_public, ()) = app
        .fuse(rng, TransactionDehydrate, (), substituted, unit.clone())
        .unwrap();
    assert!(!app.verify_uncompressed(&false_public, &mut *rng).unwrap());

    let (public, ()) = app
        .fuse(rng, TransactionDehydrate, (), working, unit)
        .unwrap();
    assert_eq!(public.commitments(), [pad, pad]);
    let refreshed = app.rerandomize(public, &mut *rng).unwrap();
    let published = app.compress(&refreshed, &mut *rng).unwrap();
    assert!(app.verify_compressed(&published).unwrap());
    let (compressed, (portable, reference)) = published.into_parts();
    assert_eq!(portable, bridge);
    assert_eq!(reference, anchor);
    let (x, y) = EpAffine::from(bridge).coordinates().unwrap();
    for other in [
        (wrong_bridge, anchor),
        (EpAffine::from_xy(x * Fp::ZETA, y).unwrap().into(), anchor),
        (EpAffine::from_xy(x, -y).unwrap().into(), anchor),
        (portable, Anchor::from(Fp::from(43))),
    ] {
        assert!(
            !app.verify_compressed(&compressed.clone().carry::<PublicTransaction>(other))
                .unwrap()
        );
    }
    assert!(
        !app.verify_compressed(&compressed.carry::<Transaction>((bridge, anchor)))
            .unwrap()
    );
}

#[test]
fn finalize_rerandomizes_between_dehydration_and_compression() {
    let app = proof::new_application().unwrap();
    let anchor = Anchor::from(Fp::from(42));
    let bundle = funded_output(&app, &WalletSim::new(shared_sk()), anchor);
    let (digests, _) = bundle.verify_covered(&[]).unwrap();
    let actions = ActionSetPoly::from_iter(digests).commit();
    let bridge = ActionSetBridge::from(app.bridge_hash(actions.into()).unwrap());
    let [mut reference_rng, mut wallet_rng] = [41; 2].map(StdRng::seed_from_u64);

    let working = bundle
        .stamp
        .proof
        .clone()
        .carry::<Transaction>((bridge, anchor));
    let unit = app.bootstrap_proof().clone().carry::<()>(());
    let (public, ()) = app
        .fuse(&mut reference_rng, TransactionDehydrate, (), working, unit)
        .unwrap();
    let refreshed = app.rerandomize(public, &mut reference_rng).unwrap();
    let expected = app.compress(&refreshed, &mut reference_rng).unwrap();

    // Verification alone accepts both the refreshed and unrefreshed statement.
    // Compare the proof bytes with the same input proof, bootstrap and initial RNG.
    let actual = bundle.stamp.finalize(&mut wallet_rng, &app).unwrap();
    assert_eq!(
        actual.proof.to_bytes().unwrap(),
        expected.proof().to_bytes().unwrap()
    );
}

#[test]
fn wallet_finalizes_the_working_statement_independently_of_the_trailer() {
    let app = &proof::new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(39);
    let bootstrap = app.bootstrap_proof().clone().carry::<()>(());
    assert!(
        app.verify_compressed(&app.compress(&bootstrap, &mut *rng).unwrap())
            .unwrap()
    );
    let wallet = WalletSim::new(shared_sk());
    let anchor = Anchor::from(Fp::from(42));
    let stamped = funded_output(app, &wallet, anchor);
    let (_, fee_only) = wallet.bundle(
        app,
        anchor,
        &[],
        &[],
        wallet.labelled_note("finalized fee only", 0),
        value::Positive::ZERO,
    );
    // Even inadmissible trailer metadata is not a witness to dehydration.
    let mut unusual = fee_only.stamp.clone();
    unusual.tachygram_set = EqAffine::identity().into();
    unusual.adjuncts.insert([17; 32]);
    let copied = unusual.finalize(rng, app).unwrap();
    assert_eq!(EqAffine::from(copied.tachygram_set), EqAffine::identity());
    assert!(copied.adjuncts.iter().eq([&[17; 32]]));
    for signed in [stamped, fee_only] {
        let (digests, _) = signed.verify_covered(&[]).unwrap();
        let commitment = ActionSetPoly::from_iter(digests.iter().copied()).commit();
        let sighash = mock_sighash(signed.commitment());
        signed.verify_signatures(&sighash).unwrap();
        let mut wrong_sighash = sighash;
        wrong_sighash[0] ^= 1;
        signed.verify_signatures(&wrong_sighash).unwrap_err();

        let padding = [app.commit(&[Fp::ONE]).unwrap(); 2];
        assert!(signed.verify_proof(rng, app, &digests).unwrap());
        let bridge = ActionSetBridge::from(app.bridge_hash(commitment.into()).unwrap());
        let working = signed
            .stamp
            .proof
            .clone()
            .carry::<Transaction>((bridge, anchor));
        // Raw Ragu compression in the current registry preserves Transaction;
        // it verifies under that header, but not as a finalized wallet proof.
        let ordinary = app.compress(&working, &mut *rng).unwrap();
        assert!(app.verify_compressed(&ordinary).unwrap());
        assert!(
            !ordinary
                .proof()
                .verify(rng, app, (commitment, anchor))
                .unwrap()
        );
        assert_ne!(ordinary.proof().online_commitments(), padding);

        let finalized = signed.stamp.clone().finalize(rng, app).unwrap();
        assert_eq!(finalized.anchor, signed.stamp.anchor);
        assert_eq!(finalized.tachygram_set, signed.stamp.tachygram_set);
        assert_eq!(finalized.adjuncts, signed.stamp.adjuncts);
        let published = Bundle {
            actions: signed.actions,
            action_auth: signed.action_auth,
            fee: signed.fee,
            fee_auth: signed.fee_auth,
            value_balance: signed.value_balance,
            binding_sig: signed.binding_sig,
            memo: signed.memo,
            stamp: finalized,
        };
        let mut bytes = Vec::new();
        published.write(&mut bytes).unwrap();
        let mut bundle = Bundle::<ProofStamp<Compressed>>::read(bytes.as_slice()).unwrap();
        assert_eq!(bundle, published);
        bundle.verify_signatures(&sighash).unwrap();
        let (covered, tachygrams) = bundle.verify_covered(&[]).unwrap();
        assert_eq!(bundle.stamp.proof.online_commitments(), padding);
        assert!(bundle.verify_proof(rng, app, &covered).unwrap());
        assert_eq!(bundle.verify(rng, app, &sighash, &[]).unwrap(), tachygrams);
        bundle
            .stamp
            .proof
            .verify(
                rng,
                app,
                (ActionSetCommit::from(EqAffine::identity()), anchor),
            )
            .unwrap_err();

        // A different fee leaves C_T unchanged, but changes the expected C_A.
        let original_fee = bundle.fee;
        bundle.fee.v_fee = value::Positive::try_from(1).unwrap();
        let (other_digests, _) = bundle.verify_covered(&[]).unwrap();
        assert!(!bundle.verify_proof(rng, app, &other_digests).unwrap());
        bundle.fee = original_fee;
        bundle.stamp.tachygram_set = EqAffine::identity().into();
        assert!(bundle.verify_proof(rng, app, &covered).unwrap());
        bundle.verify_covered(&[]).unwrap_err();
    }
}
