extern crate alloc;

use alloc::{vec, vec::Vec};

use ragu::{Polynomial, ProductionRank};
use udon::{field::Field as _, polynomial::vanishing_polynomial};

use crate::pasta::Fp;

/// Encode the provided members as roots.
#[expect(
    clippy::expect_used,
    reason = "the buffer fits the roots and leading one"
)]
pub(crate) fn encode(members: impl IntoIterator<Item = Fp>) -> Polynomial<Fp, ProductionRank> {
    let roots: Vec<Fp> = members.into_iter().collect();
    let mut coeffs = vec![Fp::ZERO; roots.len() + 1];
    vanishing_polynomial(Fp::as_slice(&roots), Fp::as_slice_mut(&mut coeffs))
        .expect("the buffer fits the roots and leading one");
    Polynomial::from_coeffs(coeffs)
}
