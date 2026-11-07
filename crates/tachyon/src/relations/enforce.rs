//! The framework commits the prover-supplied polynomials before deriving the
//! Fiat-Shamir challenge $z$. Each relation checks its algebraic identity at
//! $z$ through [`Oracles::query`]. The proof system verifies the openings.
//!
//! Soundness rests on Schwartz-Zippel: every operand commitment is absorbed
//! into `z`, so the operands are fixed *before* `z` exists and the identity at
//! a random `z` pins the corresponding polynomial identity (error `~deg/|F|`).
//! An input that is **not** a committed operand (a raw scalar, say) is not
//! pinned this way; a relation that takes such an input states its own
//! precondition.
//!
//! # Caller obligation: binding
//!
//! These relations prove the identity among the polynomials in the slots;
//! pinning *which* polynomials those are is the caller's job. Every operand the
//! surrounding statement relies on must have its commitment grounded in a
//! statement-fixed value -- a public input, a prior-step output, a
//! transcript/header-absorbed value, or a consensus/output-checked commitment
//! -- and the binding holds only once that chain actually terminates in such a
//! value (a fresh witness, or a commitment merely threaded onward, is not
//! itself enough). The binding target is the commitment *point*;
//! trailing-zero coefficients collapse under commitment, so this is
//! commitment-identity, not the literal coefficient vector.
//!
//! This principle is common to all of these relations; each states which
//! operands it covers and any relation-specific nuance.
//!
//! Implementation invariant: the eval fed to each identity check is the same
//! eval emitted in that operand's opening claim (one `query` call per
//! operand). A refactor that recomputed or separately witnessed the evals could
//! let the checked value diverge from the opened one and break soundness.

use ragu::step::{Oracles, Slot};
use ragu_core::{Error, Result, drivers::Driver};
use ragu_primitives::{Element, GadgetExt as _};
use udon::field::Field as _;

use crate::pasta::Fp;

pub(crate) fn enforce_poly_equal<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    oracles: &mut Oracles<'_, 'dr, D>,
    left: Slot,
    right: Slot,
) -> Result<()> {
    let z = oracles.zeta().clone();
    let left_value = oracles.query(dr, left, &z)?;
    let right_value = oracles.query(dr, right, &z)?;
    left_value.enforce_equal(dr, &right_value)
}

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
pub(crate) fn enforce_poly_product<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    oracles: &mut Oracles<'_, 'dr, D>,
    multiplicand: &Slot,
    multiplier: &Slot,
    product: &Slot,
    err: &'static str,
) -> Result<()> {
    let z = oracles.zeta().clone();
    let multiplicand_value = oracles.query(dr, *multiplicand, &z)?;
    let multiplier_value = oracles.query(dr, *multiplier, &z)?;
    let product_value = oracles.query(dr, *product, &z)?;
    let expected = multiplicand_value.mul(dr, &multiplier_value)?;
    product_value
        .enforce_equal(dr, &expected)
        .map_err(|_err| Error::InvalidWitness(err.into()))
}

/// Faithful root accumulator: confirm `accumulator = ∏ᵢ (X − rootᵢ)` over the
/// given roots by opening the accumulator at a Fiat-Shamir challenge and
/// comparing against the product of the root factors, computed in cheap field
/// operations.
///
/// `accumulator` is prover-supplied and the relation works only from its
/// commitment and opening at `z` -- it does not interpolate the roots. The
/// point-wise identity `accumulator(z) = ∏ᵢ (z − rootᵢ)` at a random `z`
/// confirms the relation: with the accumulator committed and absorbed into
/// `z`, the difference `accumulator − ∏ᵢ (X − rootᵢ)` is a fixed polynomial
/// pinned to zero by Schwartz-Zippel.
///
/// # Caller obligation (soundness)
///
/// The module-level binding obligation applies to the accumulator. Each root
/// must be fixed before $z$ by an input header, derivation from fixed values,
/// or staging. The call site states each root's binding.
///
/// `N` fixes the root count at compile time.
pub(crate) fn enforce_poly_roots<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    oracles: &mut Oracles<'_, 'dr, D>,
    accumulator: &Slot,
    roots: &[Element<'dr, D>; N],
    err: &'static str,
) -> Result<()> {
    let z = oracles.zeta().clone();
    let accumulator_value = oracles.query(dr, *accumulator, &z)?;
    let mut expected = Element::constant(dr, Fp::ONE);
    for root in roots {
        let factor = z.sub(dr, root);
        expected = expected.mul(dr, &factor)?;
    }
    accumulator_value
        .enforce_equal(dr, &expected)
        .map_err(|_err| Error::InvalidWitness(err.into()))
}
