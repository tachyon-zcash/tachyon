//! The framework commits the prover-supplied polynomials before deriving the
//! Fiat-Shamir challenge $z$. Each relation checks its algebraic identity over
//! openings at $z$ that its caller makes through
//! [`Oracle::open`](ragu::step::Oracle::open). The proof system verifies
//! the openings.
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
//! These relations prove the identity among the opened polynomials; pinning
//! *which* polynomials those are is the caller's job. Every operand the
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
//! Caller invariant: each operand value passed to a relation is the value
//! [`Oracle::open`](ragu::step::Oracle::open) returned for that operand
//! at `z`. A caller that recomputed or separately witnessed a value could let
//! the checked value diverge from the opened one and break soundness.

use ragu::{
    Result,
    drivers::Driver,
    primitives::{Element, GadgetExt as _},
};
use udon::field::Field as _;

use crate::pasta::Fp;

/// Faithful polynomial product: confirm `product = multiplicand · multiplier`
/// among three committed polynomials from their openings at a Fiat-Shamir
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
    multiplicand: &Element<'dr, D>,
    multiplier: &Element<'dr, D>,
    product: &Element<'dr, D>,
) -> Result<()> {
    let expected = multiplicand.mul(dr, multiplier)?;
    product.enforce_equal(dr, &expected)
}

/// Faithful root accumulator: confirm `accumulator = ∏ᵢ (X − rootᵢ)` over the
/// given roots from the accumulator's opening at a Fiat-Shamir challenge,
/// compared against the product of the root factors, computed in cheap field
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
    z: &Element<'dr, D>,
    accumulator: &Element<'dr, D>,
    roots: &[Element<'dr, D>; N],
) -> Result<()> {
    let mut expected = Element::constant(dr, Fp::ONE);
    for root in roots {
        let factor = z.sub(dr, root);
        expected = expected.mul(dr, &factor)?;
    }
    accumulator.enforce_equal(dr, &expected)
}
