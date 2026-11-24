use ragu::{circuits::polynomials, pcd::profile, udon::field::Field as _};

mod registered_cost;

use super::{
    registry::{dehydration_registry, shared_builder},
    *,
};

#[test]
fn mixed_verifier_checks_the_registry_even_with_the_right_wallet_statement() {
    use alloc::collections::BTreeSet;

    use rand::{SeedableRng as _, rngs::StdRng};

    use crate::{
        Anchor, Note, ProofStamp, Tachygram, TachygramSetPoly, fee,
        pasta::Fp,
        stamp::{PublicationProof, Uncompressed},
        value, witness,
    };

    let rng = &mut StdRng::seed_from_u64(91);
    let other = dehydration_registry::<Pasta, WalletRank>()
        .unwrap()
        .finalize(pasta::baked())
        .unwrap();
    let current = new_aggregator_application(rng).unwrap();
    let anchor = Anchor::from(Fp::from(3));
    let note = Note {
        pk: Fp::from(5).into(),
        value: value::Positive::ZERO,
        psi: Fp::from(7).into(),
        rcm: Fp::from(9).into(),
    };
    let change = Tachygram::from(note.commitment());
    let digest = fee::Descriptor {
        cv_feemax: note.cv_feemax(),
        v_fee: value::Positive::ZERO,
    }
    .digest(change);
    let pcd = other
        .seed(
            rng,
            transaction::FeeSeed,
            witness::fee_seed(((), ()), note, anchor),
        )
        .unwrap()
        .0;
    let working = ProofStamp::<Uncompressed> {
        anchor,
        tachygram_set: TachygramSetPoly::from_iter([change]).commit(),
        adjuncts: BTreeSet::new(),
        proof: Box::new(pcd.into_parts().0),
    };
    let published = working.finalize(rng, &other).unwrap();
    assert!(published.verify_proof(rng, &other, [digest]).unwrap());
    let mixed = ProofStamp {
        anchor,
        tachygram_set: published.tachygram_set,
        adjuncts: published.adjuncts,
        proof: Box::new(PublicationProof::Wallet(*published.proof)),
    };
    assert!(!mixed.verify_proof(&current, &[digest]).unwrap());
}

#[test]
fn shared_registry_preserves_the_dehydration_prefix_and_fits_the_wallet() {
    let prefix = dehydration_registry::<Pasta, WalletRank>()
        .unwrap()
        .finalize(pasta::baked())
        .unwrap();
    // Pin the width-nine test-epoch registry through TransactionDehydrate,
    // including the wallet-locked spend and end-factor span writers.
    assert_eq!(
        prefix.native_registry().tag().to_bytes(),
        [
            52, 90, 131, 40, 47, 46, 162, 35, 170, 179, 109, 45, 182, 78, 172, 191, 75, 10, 150,
            220, 204, 71, 245, 110, 167, 44, 235, 154, 240, 171, 56, 30
        ]
    );
    assert_eq!(
        prefix.nested_registry().tag().to_bytes(),
        [
            202, 56, 202, 144, 142, 231, 212, 109, 243, 209, 26, 104, 178, 82, 93, 198, 252, 97,
            242, 57, 240, 60, 157, 35, 210, 152, 42, 206, 63, 121, 85, 7
        ]
    );

    let step = transaction::TransactionRehydrate::new().unwrap();
    let wallet = shared_builder::<Pasta, WalletRank>(step.clone())
        .unwrap()
        .finalize(pasta::baked())
        .unwrap();
    let registry = wallet.native_registry();
    let before = prefix.native_registry().num_circuits();
    assert_eq!(
        registered_cost::cost(registry, before - 40 + 8),
        (1644, 3311)
    );
    assert_eq!(registry.num_circuits(), before + 3);
    // The adapter wires its final gate to an oracle evaluation. Inspect the
    // highest occupied gate in each actual step's wiring, including SYSTEM,
    // the application's reserved stage and the adapter's default openings.
    let costs = [
        before - 9,
        before - 8,
        before - 1,
        before,
        before + 1,
        before + 2,
    ]
    .map(|index| registered_cost::cost(registry, index));
    assert_eq!(
        costs,
        [
            (330, 675),
            (23, 50),
            (16, 47),
            (1405, 2828),
            (17, 47),
            (1407, 2830)
        ]
    );

    // The integration suite exercises the finalized aggregator application.
    shared_builder::<profile::Profiled<Pasta, profile::Standard>, polynomials::AggregatorRank>(
        step,
    )
    .unwrap();
}
