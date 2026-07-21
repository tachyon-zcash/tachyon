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
    shifted_polys: [(&Polynomial, u64); SHIFTED_POLYS],
    monomials: [(Fp, u64); MONOMIALS],
    result: &Polynomial,
) -> Result<()> {
    let poly_coms = shifted_polys.map(|(poly, _)| poly.commit());
    let result_com = result.commit();
    let z = ctx.derive_challenge(&[poly_coms.as_slice(), [result_com].as_slice()].concat())?;

    let combination = shifted_polys
        .iter()
        .map(|&(poly, shift)| z.pow_vartime([shift]) * poly.eval(z))
        .chain(
            monomials
                .iter()
                .map(|&(coeff, degree)| coeff * z.pow_vartime([degree])),
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
