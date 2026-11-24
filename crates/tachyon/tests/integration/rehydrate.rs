use ragu::{
    Cycle as _, FixedGenerators as _, WalletRank,
    circuits::polynomials,
    pasta::{EpAffine, Fp, Pasta},
    pcd::{
        ipa::IpaCycle as _,
        profile::{Aggregator, Decompression, Profiled},
    },
    udon::{curve::Affine as _, field::Field as _},
};
use ragu_pcd::pasta::{baked as baked_wallet, baked_aggregator};
use rand::{SeedableRng as _, rngs::StdRng};
use transaction::{PublicTransaction, Transaction, TransactionDehydrate, TransactionRehydrate};
use zcash_tachyon::{
    ActionSetBridge, ActionSetPoly, Anchor,
    stamp::proof::{
        HEADER_SIZE, delegation, evidence, new_application, output, pool, qr, spend, spendable,
        summary, transaction,
    },
};

use super::{
    dehydrate::funded_output,
    fixtures::wallet::{WalletSim, shared_sk},
};

// Use the production list without publishing a new builder API.
#[path = "../../src/stamp/proof/registry.rs"]
mod registry;

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
    let source = registry::shared_builder::<Pasta, WalletRank>(step.clone())
        .unwrap()
        .finalize(params)
        .unwrap();
    let app = registry::shared_builder::<
        Profiled<Pasta, Aggregator<HEADER_SIZE>>,
        polynomials::AggregatorRank,
    >(step.clone())
    .unwrap()
    .finalize_with(params, Decompression::new(source, rng).unwrap())
    .unwrap();
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
