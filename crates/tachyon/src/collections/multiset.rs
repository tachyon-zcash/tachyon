extern crate alloc;

use alloc::vec::Vec;

use pasta_curves::Fp;
use ragu_arithmetic::poly_with_roots;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};

/// Encode the provided members as roots.
pub(crate) fn encode(members: impl IntoIterator<Item = Fp>) -> Polynomial<Fp, ProductionRank> {
    let roots: Vec<Fp> = members.into_iter().collect();
    Polynomial::from_coeffs(poly_with_roots(&roots))
}
