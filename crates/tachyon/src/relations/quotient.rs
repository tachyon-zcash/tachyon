//! Generic coset arithmetic for off-circuit witness-quotient preparation.

extern crate alloc;

use alloc::vec::Vec;
use core::{array, iter};

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use ragu::{Domain, Polynomial};

/// The polynomial $p(X^{\mathsf{stride}})$: coefficient $m$ placed at degree
/// $m \cdot \mathsf{stride}$, over the full domain.
pub(crate) fn spread_argument(poly: &Polynomial, stride: usize) -> Polynomial {
    let spread: Vec<Fp> = poly
        .iter_coeffs()
        .flat_map(|coeff| iter::once(coeff).chain(iter::repeat_n(Fp::ZERO, stride - 1)))
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
    #[expect(clippy::expect_used, reason = "a coset shift generates the coset")]
    let shift_inv = shift
        .invert()
        .into_option()
        .expect("coset shift is nonzero");
    interpolant.dilate(shift_inv);
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

/// The polynomial whose coefficient $j$ is
/// $c_j \, \mathsf{shift}^j \, (1 - \chi\, \mathsf{step}^{\,j \bmod
/// \mathsf{PERIOD}})^{-1}$, with $c_j$ `poly`'s coefficients and $\chi$ =
/// `challenge`: `poly` dilated by `shift`, then scaled coefficient-wise by
/// the `PERIOD`-cyclic sequence of inverse fold denominators.
///
/// It satisfies $A(X) - \chi A(\mathsf{step}\,X) = p(\mathsf{shift}\,X)$
/// wherever the cycle closes, so opening $A$ at two points folds any
/// contiguous run of $p$'s dilated evaluations with Horner weights.
pub(crate) fn cyclic_fold<const PERIOD: usize>(
    poly: &Polynomial,
    shift: Fp,
    step: Fp,
    challenge: Fp,
) -> Polynomial {
    let mut step_power = Fp::ONE;
    #[expect(
        clippy::expect_used,
        reason = "a derived challenge hits a root of the cycle with negligible probability"
    )]
    let denominator_invs: [Fp; PERIOD] = array::from_fn(|_| {
        let denominator = Fp::ONE - challenge * step_power;
        step_power *= step;
        denominator
            .invert()
            .into_option()
            .expect("challenge is not a root of the cycle")
    });

    let mut dilated = poly.clone();
    dilated.dilate(shift);
    let coeffs = dilated
        .iter_coeffs()
        .zip(denominator_invs.iter().cycle())
        .map(|(coeff, &inv)| coeff * inv)
        .collect();
    Polynomial::from_coeffs(coeffs)
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
    #[expect(
        clippy::expect_used,
        reason = "the multiplicative generator is not a domain element"
    )]
    let vanisher_inv = (shift.pow_vartime([1 << Polynomial::R]) - Fp::ONE)
        .invert()
        .into_option()
        .expect("the coset avoids the domain");
    #[expect(clippy::indexing_slicing, reason = "coset tables are full-length")]
    let quotient_evals: Vec<Fp> = (0..(1 << Polynomial::R))
        .map(|point| combine(array::from_fn(|i| tables[i][point])) * vanisher_inv)
        .collect();
    coset_interpolate::<{ Polynomial::R }>(&Polynomial::from_coeffs(quotient_evals), shift)
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    /// The recurrence [`cyclic_fold`] exists to satisfy, at random points:
    /// $A(X) - \chi A(\mathsf{step}\,X) = p(\mathsf{shift}\,X)$ wherever the
    /// period divides the argument's orbit, which holds coefficient-wise for
    /// a `PERIOD` dividing the polynomial length.
    #[test]
    fn cyclic_fold_satisfies_its_recurrence() {
        const PERIOD: usize = 4;

        let rng = &mut StdRng::seed_from_u64(0);
        let coeffs: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
            .take(PERIOD)
            .collect();
        let poly = Polynomial::from_coeffs(coeffs);
        let shift = Fp::from(7);
        let step = Fp::from(3);
        let challenge = Fp::from(11);

        let folded = cyclic_fold::<PERIOD>(&poly, shift, step, challenge);

        for x in [Fp::from(2), Fp::from(1000), Fp::random(rng)] {
            let mut shifted = poly.clone();
            shifted.dilate(shift);
            assert_eq!(
                folded.eval(x) - challenge * folded.eval(step * x),
                shifted.eval(x),
                "the fold accumulator must satisfy its recurrence"
            );
        }
    }
}
