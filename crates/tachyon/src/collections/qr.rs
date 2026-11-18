//! # Quadratic-residue classification
//!
//! A value $x$ takes the residue side at a discriminant $R$ iff $x + R$ is a
//! square or zero, and the non-residue side otherwise. A root $y$ attests
//! either side: $y^2 = x + R$ on the residue side, $y^2 = n \cdot (x + R)$ for
//! a fixed non-residue $n$ on the other.
//!
//! ## Class decomposition
//!
//! With $q$ one side's values as roots and $u$ interpolating their roots
//! $y_i$, at that side's class multiplier $c$,
//!
//! $$
//!   u(X)^2 - c \cdot (X + R) = q(X) \cdot h(X),
//! $$
//!
//! so every root of $q$ takes that side. The exceptional value $-R$ has root
//! $0$ under either class; $q_\mathsf{non}(-R) \neq 0$ files it residue-side.
//!
//! The identity also reads over one value against many discriminants: with
//! the $R_j$ as the roots of $q$ and $x$ as the shift, $u(R_j)^2 = c(x +
//! R_j)$ at each.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ragu::{Polynomial, ProductionRank, fft, ifft};
use udon::{
    field::Field as _,
    polynomial::{
        InterpolationError, InterpolationPlan, divide_monic_in_place, vanishing_polynomial,
    },
};

use crate::pasta::Fp;

/// The least quadratic non-residue of the Pallas base field. Distinct from
/// the cubic non-residue the sequence encoding uses.
pub(crate) const QUADRATIC_NON_RESIDUE: Fp = Fp::new(udon::fp_hex!(
    "0x0000000000000000000000000000000000000000000000000000000000000005"
));

/// The class multiplier $c$ of a side: $1$ on the residue side, the quadratic
/// non-residue otherwise.
pub(crate) const fn class_multiplier(side: bool) -> Fp {
    if side { Fp::ONE } else { QUADRATIC_NON_RESIDUE }
}

/// Classify $v$ at the discriminant $R$: the residue-side bit, set iff $v +
/// R$ is a square or zero, and a root with $\mathsf{root}^2 = c \cdot (v + R)$
/// at that side's [`class_multiplier`].
///
/// # Panics
///
/// Panics if neither character branch has a root. The character is
/// multiplicative and the multiplier is a non-residue, so exactly one branch
/// always does, and this is unreachable.
#[must_use]
pub fn classify(value: Fp, discriminant: Fp) -> (bool, Fp) {
    let shifted = value + discriminant;
    if let Some(root) = shifted.sqrt() {
        return (true, root);
    }
    // The character is multiplicative and n is a non-residue, so exactly
    // one of the two character branches has a root.
    let root = (QUADRATIC_NON_RESIDUE * shifted).sqrt();
    #[expect(
        clippy::expect_used,
        reason = "one of the two character branches always has a root"
    )]
    (false, root.expect("non-residue branch has a root"))
}

/// One side's points $(x_i, y_i)$, each $y_i$ the root of $x_i$ on that side.
pub(crate) type ClassificationPoints = Vec<(Fp, Fp)>;

/// Split values by side at `discriminant`, returning the residue-side then
/// the non-residue-side points.
#[must_use]
pub(crate) fn split(
    values: impl IntoIterator<Item = Fp>,
    discriminant: Fp,
) -> (ClassificationPoints, ClassificationPoints) {
    let mut residue = Vec::new();
    let mut non_residue = Vec::new();
    for value in values {
        let (bit, root) = classify(value, discriminant);
        if bit {
            residue.push((value, root));
        } else {
            non_residue.push((value, root));
        }
    }
    (residue, non_residue)
}

/// Class decomposition $(u, h)$ of `points` at class multiplier $c$ and shift
/// $s$:
///
/// $$
///   u(X)^2 - c \cdot (X + s) = q(X) \cdot h(X),
/// $$
///
/// with $q$ the abscissas as roots and $u$ interpolating the points. An empty
/// side takes $u = 1$ and an all-zero side takes $u = q$, so neither
/// polynomial is zero.
///
/// Returns `None` when two abscissas coincide or a point lies off the side.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "the buffers and FFT domain fit each operation and udon writes a monic divisor"
)]
pub(crate) fn decomposition(
    points: &[(Fp, Fp)],
    class: Fp,
    shift: Fp,
) -> Option<(
    Polynomial<Fp, ProductionRank>,
    Polynomial<Fp, ProductionRank>,
)> {
    let (abscissas, values): (Vec<_>, Vec<_>) = points.iter().copied().unzip();
    let len = points.len();
    let mut interpolant_coeffs = if len == 0 {
        vec![Fp::ONE]
    } else {
        let mut weights = vec![Fp::ZERO; len];
        let mut scratch = vec![Fp::ZERO; len];
        let mut coeffs = vec![Fp::ZERO; len];
        let plan = match InterpolationPlan::prepare(
            Fp::as_slice(&abscissas),
            Fp::as_slice_mut(&mut weights),
            Fp::as_slice_mut(&mut scratch),
        ) {
            Ok(plan) => plan,
            Err(InterpolationError::DuplicatePoints { .. }) => return None,
            Err(err) => unreachable!("interpolation buffers match the point count: {err}"),
        };
        plan.interpolate(
            Fp::as_slice(&values),
            Fp::as_slice_mut(&mut coeffs),
            Fp::as_slice_mut(&mut scratch),
        )
        .expect("interpolation values and buffers match the point count");
        coeffs
    };
    let mut vanishing = vec![Fp::ZERO; len + 1];
    vanishing_polynomial(Fp::as_slice(&abscissas), Fp::as_slice_mut(&mut vanishing))
        .expect("the buffer fits the abscissas and leading one");
    if interpolant_coeffs.iter().all(|coeff| coeff == &Fp::ZERO) {
        interpolant_coeffs.clone_from(&vanishing);
    }

    let translate = [class * shift, class];
    let dividend_len = (2 * interpolant_coeffs.len() - 1).max(translate.len());
    let domain = Fp::domain(dividend_len.next_power_of_two().trailing_zeros())
        .expect("the square fits the FFT domain");
    let mut dividend = interpolant_coeffs.clone();
    dividend.resize(domain.size(), Fp::ZERO);
    fft(domain, &mut dividend);
    for evaluation in &mut dividend {
        *evaluation = evaluation.square();
    }
    ifft(domain, &mut dividend);
    dividend.truncate(dividend_len);
    for (coeff, &translate_coeff) in dividend.iter_mut().zip(&translate) {
        *coeff -= translate_coeff;
    }
    let remainder_len =
        divide_monic_in_place(Fp::as_slice_mut(&mut dividend), Fp::as_slice(&vanishing))
            .expect("the vanishing polynomial is monic");
    let h_coeffs = dividend.split_off(remainder_len);
    if dividend.iter().any(|coeff| coeff != &Fp::ZERO) {
        return None;
    }

    Some((
        Polynomial::from_coeffs(interpolant_coeffs),
        Polynomial::from_coeffs(h_coeffs),
    ))
}

#[cfg(test)]
mod tests;
