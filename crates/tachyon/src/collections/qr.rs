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

use alloc::vec::Vec;

use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use udon::field::Field as _;

use crate::{arithmetic, pasta::Fp};

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
pub(crate) fn decomposition(
    points: &[(Fp, Fp)],
    class: Fp,
    shift: Fp,
) -> Option<(
    Polynomial<Fp, ProductionRank>,
    Polynomial<Fp, ProductionRank>,
)> {
    let mut interpolant_coeffs = if points.is_empty() {
        [Fp::ONE].to_vec()
    } else {
        arithmetic::interpolate(points)?
    };
    if interpolant_coeffs.iter().all(|coeff| coeff == &Fp::ZERO) {
        let abscissas: Vec<Fp> = points.iter().map(|&(abscissa, _)| abscissa).collect();
        interpolant_coeffs = arithmetic::poly_with_roots(&abscissas);
    }

    let translate = [class * shift, class];
    let mut h_coeffs = arithmetic::poly_mul(&interpolant_coeffs, &interpolant_coeffs);
    if h_coeffs.len() < translate.len() {
        h_coeffs.resize(translate.len(), Fp::ZERO);
    }
    for (coeff, &translate_coeff) in h_coeffs.iter_mut().zip(&translate) {
        *coeff -= translate_coeff;
    }
    for &(abscissa, _) in points {
        h_coeffs = arithmetic::divide_by_root(&h_coeffs, abscissa)?;
    }

    Some((
        Polynomial::from_coeffs(interpolant_coeffs),
        Polynomial::from_coeffs(h_coeffs),
    ))
}

#[cfg(test)]
mod tests;
