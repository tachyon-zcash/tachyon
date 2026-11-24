use ragu::{
    Rank as _,
    circuits::{polynomials, registry},
    pasta::Fp,
    pcd::profile,
    udon::field::Field as _,
};

use super::{
    registry::{dehydration_registry, shared_builder},
    *,
};

#[test]
fn shared_registry_preserves_the_dehydration_prefix_and_fits_the_wallet() {
    let prefix = dehydration_registry::<Pasta, WalletRank>()
        .unwrap()
        .finalize(pasta::baked())
        .unwrap();
    // Pin the width-nine test-epoch registry through TransactionDehydrate
    // (ea6524aa). Appending step 40 changes the complete registry.
    assert_eq!(
        prefix.native_registry().tag().to_bytes(),
        [
            243, 103, 84, 114, 64, 129, 124, 174, 185, 44, 187, 199, 96, 0, 86, 141, 52, 93, 236,
            181, 100, 168, 32, 71, 239, 186, 209, 199, 203, 12, 190, 11
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
    assert_eq!(registry.num_circuits(), before + 1);
    // The adapter wires its final gate to an oracle evaluation. Inspect the
    // highest occupied gate in each actual step's wiring, including SYSTEM,
    // the application's reserved stage and the adapter's default openings.
    let costs = [before - 1, before].map(|index| {
        let circuit = registry::CircuitIndex::new(index);
        let wiring = registry.circuit_y(circuit, Fp::from(7));
        let width = WalletRank::n();
        let gates = wiring
            .iter_stored_coeffs()
            .filter(|&(_, coefficient)| *coefficient != Fp::ZERO)
            .map(|(degree, _)| {
                let offset = degree & (width - 1);
                if degree & width == 0 {
                    offset + 1
                } else {
                    width - offset
                }
            })
            .max()
            .unwrap();
        // Both circuits have one contiguous root segment. Its first constraint
        // (the K_W x equality or alloc_square's a=b for O.x) occupies the highest
        // Y degree and has nonzero wiring at X=7. Count zero padding rows too;
        // omit only the registry-wide tag at degree 4n−1.
        let rows = registry.wx(circuit.omega_j(), Fp::from(7));
        let constraints = rows
            .iter_stored_coeffs()
            .filter(|&(degree, coefficient)| {
                degree < WalletRank::num_coeffs() - 1 && *coefficient != Fp::ZERO
            })
            .map(|(degree, _)| degree + 1)
            .max()
            .unwrap();
        (gates, constraints)
    });
    assert_eq!(costs, [(16, 47), (1405, 2828)]);

    // The integration suite exercises the finalized aggregator application.
    shared_builder::<profile::Profiled<Pasta, profile::Standard>, polynomials::AggregatorRank>(
        step,
    )
    .unwrap();
}
