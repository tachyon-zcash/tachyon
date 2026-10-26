extern crate alloc;

use alloc::vec::Vec;

use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::pasta;
use udon::field::{Fp, Reduced};

use super::arithmetic::poly_with_roots;

/// Encode the provided members as roots.
pub(crate) fn encode(
    members: impl IntoIterator<Item = Fp<Reduced>>,
) -> Polynomial<pasta::Fp, ProductionRank> {
    let roots: Vec<Fp> = members.into_iter().map(Fp::into_loose).collect();
    Polynomial::from_coeffs(
        poly_with_roots(&roots)
            .into_iter()
            .map(pasta::Fp::new)
            .collect(),
    )
}
