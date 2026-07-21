//! Each relation here is a convenience tool over the two framework hooks a step
//! body reaches for -- [`StepCtx::enforce_poly_query`] and
//! [`StepCtx::derive_challenge`]. They share one shape: the result is
//! prover-supplied (built off-circuit) rather than computed by the relation,
//! the relation computes each operand's commitment internally, derives a
//! Fiat-Shamir challenge `z` from those commitments, checks the defining
//! algebraic identity at `z`, and emits one opening claim per operand at
//! `(commitment, z, eval(z))`. These functions only *record* the openings;
//! actually verifying them is the proof system's job, not done here.
//!
//! Soundness rests on Schwartz-Zippel: every operand commitment is absorbed
//! into `z`, so the operands are fixed *before* `z` exists and the identity at
//! a random `z` pins the corresponding polynomial identity (error `~deg/|F|`).
//! An input that is **not** a committed operand (a raw scalar, say) is not
//! absorbed into `z` and is not pinned this way; a relation that takes such an
//! input states its own precondition.
//!
//! # Caller obligation: binding
//!
//! These relations prove the identity among the polynomials passed; pinning
//! *which* polynomials those are is the caller's job. Every operand the
//! surrounding statement relies on must have its commitment grounded in a
//! statement-fixed value -- a public input, a prior-step output, a
//! transcript/header-absorbed value, or a consensus/output-checked commitment
//! -- and the binding holds only once that chain actually terminates in such a
//! value (a fresh witness, or a commitment merely threaded onward, is not
//! itself enough). The binding target is the commitment *point*
//! (`= operand.commit()`); trailing-zero coefficients collapse under
//! [`Polynomial::commit`], so this is commitment-identity, not the literal
//! coefficient vector.
//!
//! This principle is common to all of these relations; each states which
//! operands it covers and any relation-specific nuance.
//!
//! Implementation invariant: the eval fed to each identity check is the same
//! eval emitted in that operand's opening claim (one `operand.eval(z)` call per
//! operand). A refactor that recomputed or separately witnessed the evals could
//! let the checked value diverge from the opened one and break soundness.

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Error, Result, ctx::StepCtx, polynomial::Polynomial};

/// Faithful polynomial product: confirm `product = multiplicand · multiplier`
/// among three committed polynomials by opening all three at a Fiat-Shamir
/// challenge.
///
/// `product` is prover-supplied and the relation works only from the three
/// commitments and their openings at `z` -- it does not multiply the inputs.
/// The point-wise identity `product(z) = multiplicand(z)·multiplier(z)` at a
/// random `z` confirms the relation: with every operand committed and absorbed
/// into `z`, the difference `product − multiplicand·multiplier` is a fixed
/// polynomial pinned to zero by Schwartz-Zippel.
///
/// # Caller obligation (soundness)
///
/// Every operand is committed and absorbed into `z`, so the module-level
/// binding obligation -- here applying symmetrically to `multiplicand`,
/// `multiplier`, and `product` -- is the only precondition.
pub(crate) fn enforce_poly_product(
    ctx: &mut StepCtx<'_>,
    multiplicand: &Polynomial,
    multiplier: &Polynomial,
    product: &Polynomial,
) -> Result<()> {
    let multiplicand_com = multiplicand.commit();
    let multiplier_com = multiplier.commit();
    let product_com = product.commit();
    let z = ctx.derive_challenge(&[multiplicand_com, multiplier_com, product_com])?;

    if product.eval(z) != multiplicand.eval(z) * multiplier.eval(z) {
        return Err(Error::InvalidWitness(
            "poly product: product identity fails at challenge".into(),
        ));
    }

    ctx.enforce_poly_query(multiplicand_com, z, multiplicand.eval(z))?;
    ctx.enforce_poly_query(multiplier_com, z, multiplier.eval(z))?;
    ctx.enforce_poly_query(product_com, z, product.eval(z))?;

    Ok(())
}

/// `X^exponent` evaluated at `point`.
#[expect(clippy::as_conversions, reason = "must be in range")]
fn monomial_at(point: Fp, exponent: usize) -> Fp {
    point.pow_vartime([exponent as u64])
}

/// Shifted linear combination of committed polynomials and monomials: confirm
/// `result(X) = Σ_i X^{k_i}·p_i(X) + Σ_j c_j·X^{m_j}` by opening each `p_i`
/// and `result` at a Fiat-Shamir challenge.
///
/// `result` is prover-supplied (built off-circuit). Each `shifted_polys` entry
/// pairs a committed operand `p_i` with its shift exponent `k_i`; each
/// `monomials` entry pairs a raw scalar coefficient `c_j` with its degree
/// `m_j`. The point-wise identity at a random `z` confirms the combination:
/// every polynomial operand is committed and absorbed into `z`, so the
/// difference of the two sides is a fixed polynomial pinned to zero by
/// Schwartz-Zippel.
///
/// # Caller obligations (soundness)
///
/// 1. **Binding.** Subject to the module-level binding obligation for every
///    `shifted_polys` entry and `result`. One nuance: `commit(X^k·p)` lands on
///    shifted generators, so it is not homomorphically recoverable from
///    `commit(p)`; a `result` consumed downstream must have its commitment
///    threaded independently.
/// 2. **Monomial coefficients fixed before the challenge.** The scalars `c_j`
///    are not absorbed into `z`, and the identity is *linear* in each: a prover
///    free to choose one after seeing `z` solves it and passes for any
///    committed `result`. Pin each coefficient independently of `z` -- a
///    public/statement input, a prior-step output, or a value absorbed into the
///    transcript before `z`.
/// 3. **Exponents.** The integer exponents `k_i` and `m_j` may be left free:
///    `z` is fixed by the commitments before any exponent is chosen, an
///    adaptive search over wrong exponents succeeds with probability `<=
///    tries/|F|`, and recovering an exponent from a `z` power is
///    discrete-log-hard. Whether a *specific* exponent is the one the
///    surrounding statement needs (an operand's span, say) is that statement's
///    obligation, as is any structural well-formedness of the operands (a
///    shifted sum proves the sum, not that the addends avoid overlapping).
///
/// The exponent parameters and the `z^k` point-wise factors stand in for
/// positional shifts the commitment scheme does not express directly; a
/// first-class committed `X^k·p` (or a built-in shifted sum) would carry the
/// shift itself and collapse this to a direct check.
pub(crate) fn enforce_shifted_combination<const SHIFTED_POLYS: usize, const MONOMIALS: usize>(
    ctx: &mut StepCtx<'_>,
    shifted_polys: [(&Polynomial, usize); SHIFTED_POLYS],
    monomials: [(Fp, usize); MONOMIALS],
    result: &Polynomial,
) -> Result<()> {
    let poly_coms = shifted_polys.map(|(poly, _)| poly.commit());
    let result_com = result.commit();
    let z = ctx.derive_challenge(&[poly_coms.as_slice(), [result_com].as_slice()].concat())?;

    let combination = shifted_polys
        .iter()
        .map(|&(poly, shift)| monomial_at(z, shift) * poly.eval(z))
        .chain(
            monomials
                .iter()
                .map(|&(coeff, degree)| coeff * monomial_at(z, degree)),
        )
        .sum::<Fp>();
    if result.eval(z) != combination {
        return Err(Error::InvalidWitness(
            "shifted combination: identity fails at challenge".into(),
        ));
    }

    for (&(poly, _), com) in shifted_polys.iter().zip(poly_coms) {
        ctx.enforce_poly_query(com, z, poly.eval(z))?;
    }
    ctx.enforce_poly_query(result_com, z, result.eval(z))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    //! Native checks of the shifted-combination identity on tiny cases.
    //!
    //! Pure algebra over explicit coefficient vectors: each case builds the
    //! operands with [`Polynomial::from_coeffs`], the true combination by
    //! coefficient arithmetic (an independent computation in the coefficient
    //! basis), and confirms the relation's defining identity point-wise (an
    //! exact polynomial identity holds at every point), plus one mismatch per
    //! operand kind.

    extern crate alloc;

    use alloc::vec;
    use core::iter;

    use super::*;

    /// Sample evaluation points (arbitrary, fixed).
    const POINTS: [u64; 3] = [0, 2, 927];

    fn poly(coeffs: &[u64]) -> Polynomial {
        Polynomial::from_coeffs(coeffs.iter().copied().map(Fp::from).collect())
    }

    /// `x^exponent` by repeated multiplication (exponents here are tiny).
    fn power(x: Fp, exponent: usize) -> Fp {
        (0..exponent).fold(Fp::ONE, |acc, _| acc * x)
    }

    /// The true combination, built in the coefficient basis.
    fn combine(shifted_polys: &[(&Polynomial, usize)], monomials: &[(Fp, usize)]) -> Polynomial {
        let mut result = Polynomial::new();
        for &(poly, shift) in shifted_polys {
            result += &Polynomial::from_coeffs(
                iter::repeat_n(Fp::ZERO, shift)
                    .chain(poly.iter_coeffs())
                    .take(1usize << Polynomial::R)
                    .collect(),
            );
        }
        for &(coeff, degree) in monomials {
            let mut monomial = vec![Fp::ZERO; degree + 1];
            monomial[degree] = coeff;
            result += &Polynomial::from_coeffs(monomial);
        }
        result
    }

    /// The relation's point-wise check, at every sample point.
    fn identity_holds(
        shifted_polys: &[(&Polynomial, usize)],
        monomials: &[(Fp, usize)],
        result: &Polynomial,
    ) -> bool {
        POINTS.iter().all(|&point| {
            let x = Fp::from(point);
            let combination = shifted_polys
                .iter()
                .map(|&(poly, shift)| power(x, shift) * poly.eval(x))
                .chain(
                    monomials
                        .iter()
                        .map(|&(coeff, degree)| coeff * power(x, degree)),
                )
                .sum::<Fp>();
            result.eval(x) == combination
        })
    }

    #[test]
    fn identity_on_single_unshifted_polynomial() {
        let operand = poly(&[3, 5, 7]);
        let result = combine(&[(&operand, 0)], &[]);
        assert!(result.iter_coeffs().eq(operand.iter_coeffs()));
        assert!(identity_holds(&[(&operand, 0)], &[], &result));
    }

    #[test]
    fn identity_on_overlapping_shifted_polynomials() {
        let low = poly(&[3, 5, 7]);
        let high = poly(&[11, 13]);
        let terms = [(&low, 0), (&high, 1)];
        let result = combine(&terms, &[]);
        assert!(result.iter_coeffs().eq(poly(&[3, 16, 20]).iter_coeffs()));
        assert!(identity_holds(&terms, &[], &result));
    }

    #[test]
    fn identity_on_monomials_alone() {
        let monomials = [(Fp::from(5), 0), (Fp::from(9), 3)];
        let result = combine(&[], &monomials);
        assert!(result.iter_coeffs().eq(poly(&[5, 0, 0, 9]).iter_coeffs()));
        assert!(identity_holds(&[], &monomials, &result));
    }

    #[test]
    fn identity_on_cancelling_monomial() {
        // A negative monomial cancels a known coefficient: `low`'s top
        // coefficient `1` at degree 2 is overwritten by `high`'s first.
        let low = poly(&[3, 5, 1]);
        let high = poly(&[7, 11]);
        let terms = [(&low, 0), (&high, 2)];
        let monomials = [(-Fp::ONE, 2)];
        let result = combine(&terms, &monomials);
        assert!(result.iter_coeffs().eq(poly(&[3, 5, 7, 11]).iter_coeffs()));
        assert!(identity_holds(&terms, &monomials, &result));
    }

    #[test]
    fn identity_rejects_wrong_result() {
        let low = poly(&[3, 5]);
        let high = poly(&[7]);
        let wrong = poly(&[3, 5, 8]);
        assert!(!identity_holds(&[(&low, 0), (&high, 2)], &[], &wrong));
    }

    #[test]
    fn identity_rejects_wrong_monomial_coefficient() {
        let operand = poly(&[3, 5]);
        let result = combine(&[(&operand, 0)], &[(Fp::from(9), 2)]);
        assert!(!identity_holds(
            &[(&operand, 0)],
            &[(Fp::from(8), 2)],
            &result
        ));
    }

    #[test]
    fn identity_rejects_wrong_shift() {
        let low = poly(&[3, 5]);
        let high = poly(&[7]);
        let result = combine(&[(&low, 0), (&high, 2)], &[]);
        assert!(!identity_holds(&[(&low, 0), (&high, 3)], &[], &result));
    }
}
