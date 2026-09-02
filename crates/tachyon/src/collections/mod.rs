extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::Fp;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};

pub(crate) mod indexed_multiset;
pub(crate) mod multiset;

fn trim(coeffs: &mut Vec<Fp>) {
    if let Some(last_nonzero_idx) = coeffs.iter().rposition(|co| co != &Fp::ZERO) {
        coeffs.truncate(last_nonzero_idx + 1);
    }
}

pub(super) fn poly_mul(
    input_a: &Polynomial<Fp, ProductionRank>,
    input_b: &Polynomial<Fp, ProductionRank>,
) -> Polynomial<Fp, ProductionRank> {
    use ragu_arithmetic as arithmetic;

    let mut a_coeffs = Vec::from_iter(input_a.iter_coeffs());
    let mut b_coeffs = Vec::from_iter(input_b.iter_coeffs());

    trim(&mut a_coeffs);
    trim(&mut b_coeffs);

    let mut out_coeffs = Vec::new();

    arithmetic::poly_mul(&a_coeffs, &b_coeffs, &mut out_coeffs);

    trim(&mut out_coeffs);

    Polynomial::from_coeffs(out_coeffs)
}
