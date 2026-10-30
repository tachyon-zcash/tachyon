extern crate alloc;

use alloc::vec::Vec;

use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::pasta::Fp;

use super::arithmetic::poly_with_roots;

/// Encode the provided members as roots.
pub(crate) fn encode(members: impl IntoIterator<Item = Fp>) -> Polynomial<Fp, ProductionRank> {
    let roots: Vec<Fp> = members.into_iter().collect();
    Polynomial::from_coeffs(poly_with_roots(&roots))
}
