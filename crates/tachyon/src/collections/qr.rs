//! # Quadratic-residue classification
//!
//! A value $x$ takes the residue side at a discriminant $R$ iff $x + R$ is a
//! square or zero, and the non-residue side otherwise. A class root $r$
//! attests its class by $r^2 = m \cdot (x + R)$, with multiplier $m = 1$ on
//! the residue side and $m = c$ on the other, for a fixed non-residue $c$.
//!
//! ## Class decomposition
//!
//! Let $q_0$ and $q_1$ be the non-residue and residue set polynomials.
//! For one side's set polynomial $q$, the interpolant satisfies
//! $u(x_i) = r_i$ with $r_i^2 = m \cdot (x_i + R)$. The decomposition satisfies
//!
//! $$
//!   u(X)^2 - m \cdot (X + R) = q(X) \cdot h(X).
//! $$
//!
//! The exceptional value $-R$ satisfies the identity with root $0$ under
//! either multiplier. The condition $q_0(-R) \neq 0$ keeps it on the residue
//! side.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ragu::{
    Polynomial, WalletRank, fft, ifft,
    udon::{
        field::Field as _,
        polynomial::{
            InterpolationError, InterpolationPlan, divide_monic_in_place, vanishing_polynomial,
        },
    },
};

use crate::pasta::Fp;

/// The least quadratic non-residue of the Pallas base field. Distinct from
/// the cubic non-residue the sequence encoding uses.
pub(crate) const QUADRATIC_NON_RESIDUE: Fp = Fp::new(ragu::udon::fp_hex!(
    "0x0000000000000000000000000000000000000000000000000000000000000005"
));

/// Class decomposition $(u, h)$ of `points` at class multiplier $m$ and
/// discriminant $R$:
///
/// $$
///   u(X)^2 - m \cdot (X + R) = q(X) \cdot h(X),
/// $$
///
/// with $q$ the abscissas as roots and $u$ interpolating the points. An empty
/// side takes $u = 1$ and an all-zero side takes $u = q$, so neither
/// polynomial is zero.
///
/// Returns `None` when two abscissas coincide or a point $(x, r)$ satisfies
/// $r^2 \neq m \cdot (x + R)$.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "the buffers and FFT domain fit each operation and udon writes a monic divisor"
)]
pub(crate) fn decomposition(
    points: impl IntoIterator<Item = (Fp, Fp)>,
    multiplier: Fp,
    discriminant: Fp,
) -> Option<(Polynomial<Fp, WalletRank>, Polynomial<Fp, WalletRank>)> {
    let (abscissas, values): (Vec<_>, Vec<_>) = points.into_iter().unzip();
    let len = abscissas.len();
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

    let translate = [multiplier * discriminant, multiplier];
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
