//! Measure the occupied gates and linear constraints in the registered adapter.

use ragu::{
    Rank,
    circuits::registry::{CircuitIndex, Registry},
    pasta::Fp,
    udon::field::Field as _,
};

pub(super) fn cost<R: Rank>(registry: &Registry<'_, Fp, R>, index: usize) -> (usize, usize) {
    let circuit = CircuitIndex::new(index);
    let probe = Fp::from(7);
    let wiring = registry.circuit_y(circuit, probe);
    let width = R::n();
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
    // Include zero padding rows. Omit only the registry tag at degree 4n−1.
    let rows = registry.wx(circuit.omega_j(), probe);
    let constraints = rows
        .iter_stored_coeffs()
        .filter(|&(degree, coefficient)| degree < R::num_coeffs() - 1 && *coefficient != Fp::ZERO)
        .map(|(degree, _)| degree + 1)
        .max()
        .unwrap();
    (gates, constraints)
}
