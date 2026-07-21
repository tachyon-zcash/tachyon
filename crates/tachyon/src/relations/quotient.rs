//! Generic coset arithmetic for off-circuit witness-quotient preparation.

extern crate alloc;

use alloc::vec::Vec;
use core::{array, iter};

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use ragu::{Domain, Polynomial};

/// The polynomial $p(X^{\mathsf{stride}})$: coefficient $m$ placed at degree
/// $m \cdot \mathsf{stride}$, over the full domain.
pub(crate) fn spread_argument(poly: &Polynomial, stride: u32) -> Polynomial {
    let spread: Vec<Fp> = poly
        .iter_coeffs()
        .flat_map(|coeff| {
            iter::once(coeff).chain(
                #[expect(clippy::as_conversions, reason = "stride fits usize")]
                iter::repeat_n(Fp::ZERO, (stride - 1) as usize),
            )
        })
        .take(1 << Polynomial::R)
        .collect();
    Polynomial::from_coeffs(spread)
}

/// The interpolant of `values`, a polynomial in evaluation form over the
/// `DOMAIN`-point coset $\mathsf{shift} \cdot \langle \omega \rangle$ ($\omega$
/// the order-`DOMAIN` root, a power of two), converted to coefficient form:
/// inverse FFT over $\langle \omega \rangle$, then unscale the shift off the
/// argument. `DOMAIN` is the coset size, at most `POLY_LEN_MAX`.
pub(crate) fn coset_interpolate<const R: u32>(values: &Polynomial, shift: Fp) -> Polynomial {
    let mut coeffs: Vec<Fp> = values.iter_coeffs().take(1 << R).collect();
    Domain::new(R).ifft(&mut coeffs);
    let mut interpolant = Polynomial::from_coeffs(coeffs);
    interpolant.dilate(shift.invert().expect("coset shift is nonzero"));
    interpolant
}

/// Evaluations of `poly` over the coset $\mathsf{shift} \cdot H$ of the full
/// domain $H$ (the inverse of [`coset_interpolate`]).
fn coset_evaluations(poly: &Polynomial, shift: Fp) -> Vec<Fp> {
    let mut shifted = poly.clone();
    shifted.dilate(shift);
    let mut values: Vec<Fp> = shifted.iter_coeffs().collect();
    Domain::new(Polynomial::R).fft(&mut values);
    values
}

/// Quotient by the full-domain vanisher $Z_D = X^{|D|} - 1$ ($|D|$ =
/// `POLY_LEN_MAX`) of the numerator formed by combining `operands`
/// pointwise with `combine`.
///
/// $Z_D$ is the constant $g^{|D|} - 1$ on the coset $g \cdot H$ ($g$ the
/// multiplicative generator), so the quotient's evaluations there are the
/// numerator's scaled by that constant's inverse; interpolating them yields
/// the quotient in coefficient form. Exact division is assumed: the caller
/// establishes divisibility and the circuit enforces it by opening the
/// quotient against the identity.
pub(crate) fn coset_quotient<const N: usize>(
    operands: [&Polynomial; N],
    combine: impl Fn([Fp; N]) -> Fp,
) -> Polynomial {
    let shift = Fp::MULTIPLICATIVE_GENERATOR;
    let tables = operands.map(|operand| coset_evaluations(operand, shift));
    let vanisher_inv = (shift.pow_vartime([1 << Polynomial::R]) - Fp::ONE)
        .invert()
        .expect("the coset avoids the domain");
    #[expect(clippy::indexing_slicing, reason = "coset tables are full-length")]
    let quotient_evals: Vec<Fp> = (0..(1 << Polynomial::R))
        .map(|point| combine(array::from_fn(|i| tables[i][point])) * vanisher_inv)
        .collect();
    coset_interpolate::<{ Polynomial::R }>(&Polynomial::from_coeffs(quotient_evals), shift)
}
