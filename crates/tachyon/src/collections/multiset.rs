extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use ragu::udon::field::Field as _;
use ragu::udon::polynomial::vanishing_polynomial;
use ragu::{Polynomial, ProductionRank};

use crate::pasta::Fp;

/// Encode the provided members as roots.
///
/// # Panics
///
/// Panics if more than 8191 roots are supplied, counting duplicates, or if
/// construction exceeds the supported FFT domain.
#[expect(
    clippy::expect_used,
    reason = "the buffer fits the roots and leading one"
)]
pub(crate) fn encode(members: impl IntoIterator<Item = Fp>) -> Polynomial<Fp, ProductionRank> {
    let roots: Vec<Fp> = members.into_iter().collect();
    #[expect(
        clippy::arithmetic_side_effects,
        reason = "the roots vector length is bounded by isize::MAX"
    )]
    let mut coeffs = vec![Fp::ZERO; roots.len() + 1];
    vanishing_polynomial(Fp::as_slice(&roots), Fp::as_slice_mut(&mut coeffs))
        .expect("the buffer fits the roots and leading one");
    Polynomial::from_coeffs(coeffs)
}
