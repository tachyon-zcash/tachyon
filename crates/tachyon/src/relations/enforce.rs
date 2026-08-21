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
    err: &'static str,
) -> Result<()> {
    let multiplicand_com = multiplicand.commit();
    let multiplier_com = multiplier.commit();
    let product_com = product.commit();
    let z = ctx.derive_challenge(&[multiplicand_com, multiplier_com, product_com])?;

    if product.eval(z) != multiplicand.eval(z) * multiplier.eval(z) {
        return Err(Error::InvalidWitness(err.into()));
    }

    ctx.enforce_poly_query(multiplicand_com, z, multiplicand.eval(z))?;
    ctx.enforce_poly_query(multiplier_com, z, multiplier.eval(z))?;
    ctx.enforce_poly_query(product_com, z, product.eval(z))?;

    Ok(())
}
