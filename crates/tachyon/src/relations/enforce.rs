//! Each relation here is a convenience tool over the framework hooks a step
//! body reaches for -- [`StepCtx::witness_polynomial`],
//! [`StepCtx::evaluate`], [`StepCtx::enforce_poly_query`] and
//! [`StepCtx::derive_challenge`]. A caller witnesses each polynomial once;
//! the relation absorbs its handle into a Fiat–Shamir challenge, evaluates it,
//! checks the algebraic identity on the caller's driver, and submits the same
//! evaluation as an opening. The mock also validates those openings against the
//! witnessed coefficients when the step completes.
//!
//! The relation emits its identity constraints on `ctx.dr`. Its mock opening
//! checks are additional native checks and are not a claim about real recursive
//! proof soundness. The transcript uses each handle's fixed two compressed
//! commitment limbs. Any operand not included in that ordered transcript must
//! already be pinned by another input or check.
//!
//! # Caller obligation: binding
//!
//! These relations prove the identity among the handles passed; pinning which
//! commitments those handles name is the caller's job. When an operand is
//! intended to match a header commitment, [`bind_poly_handle`] binds the
//! handle's compressed limbs to that target. The statement must ultimately pin
//! each such target through its header lineage or an external consensus check.
//!
//! This principle is common to all of these relations; each states which
//! operands it covers and any relation-specific nuance.
//!
//! Implementation invariant: each evaluation is allocated once and used by
//! both its identity check and opening query. The challenge element's wire is
//! promoted for repeated queries, preserving one circuit value across every
//! opening.

use alloc::vec::Vec;

use ragu::{
    PolyHandle, StepCtx,
    pasta::{Fp, Pasta},
};
use ragu_core::{Error, Result, drivers::Driver, maybe::Maybe as _};
use ragu_primitives::{Element, GadgetExt as _};
use udon::field::Field as _;

/// Compute one indexed-multiset factor `(member + index * z)^3 - 2` on the
/// caller's driver. `member` and `index` must already be pinned by the caller.
pub(crate) fn indexed_member_factor<'dr, D>(
    dr: &mut D,
    member: &Element<'dr, D>,
    index: &Element<'dr, D>,
    z: &Element<'dr, D>,
) -> Result<Element<'dr, D>>
where
    D: Driver<'dr, F = Fp>,
{
    let index_times_z = index.mul(dr, z)?;
    let shifted = member.add(dr, &index_times_z);
    let square = shifted.square(dr)?;
    let cube = square.mul(dr, &shifted)?;
    let two = Element::constant(dr, Fp::from(2));
    Ok(cube.sub(dr, &two))
}

/// Enforce `product(z) = multiplicand(z) * multiplier(z)` for three witnessed
/// polynomial handles at their joint Fiat–Shamir challenge.
///
/// `product` is prover-supplied off circuit. The relation uses the three
/// openings at `z` and emits the multiplication constraint on `ctx.dr`; it
/// does not construct a product polynomial inside the step.
///
/// # Caller obligation (soundness)
///
/// The caller must pin every operand commitment used by the statement. The
/// challenge absorbs multiplicand, multiplier, and product handles in that
/// order.
pub(crate) fn enforce_poly_product<'dr, D>(
    ctx: &mut StepCtx<'_, 'dr, D>,
    multiplicand: &PolyHandle<'dr, D, Pasta>,
    multiplier: &PolyHandle<'dr, D, Pasta>,
    product: &PolyHandle<'dr, D, Pasta>,
    err: &'static str,
) -> Result<()>
where
    D: Driver<'dr, F = Fp>,
{
    let [multiplicand_lo, multiplicand_hi] = poly_handle_limbs(ctx.dr, multiplicand)?;
    let [multiplier_lo, multiplier_hi] = poly_handle_limbs(ctx.dr, multiplier)?;
    let [product_lo, product_hi] = poly_handle_limbs(ctx.dr, product)?;
    let z = ctx.derive_challenge(&[
        multiplicand_lo,
        multiplicand_hi,
        multiplier_lo,
        multiplier_hi,
        product_lo,
        product_hi,
    ])?;
    let multiplicand_assignment =
        ctx.evaluate(multiplicand, z.value().map(|challenge| *challenge))?;
    let multiplier_assignment = ctx.evaluate(multiplier, z.value().map(|challenge| *challenge))?;
    let product_assignment = ctx.evaluate(product, z.value().map(|challenge| *challenge))?;
    let multiplicand_at_z = Element::alloc(ctx.dr, &mut (), multiplicand_assignment)?;
    let multiplier_at_z = Element::alloc(ctx.dr, &mut (), multiplier_assignment)?;
    let product_at_z = Element::alloc(ctx.dr, &mut (), product_assignment)?;
    let expected_product = multiplicand_at_z.mul(ctx.dr, &multiplier_at_z)?;
    product_at_z
        .enforce_equal(ctx.dr, &expected_product)
        .map_err(|_err| Error::InvalidWitness(err.into()))?;

    ctx.enforce_poly_query(
        multiplicand,
        Element::promote(z.wire().clone(), z.value().map(|challenge| *challenge)),
        multiplicand_at_z,
    )?;
    ctx.enforce_poly_query(
        multiplier,
        Element::promote(z.wire().clone(), z.value().map(|challenge| *challenge)),
        multiplier_at_z,
    )?;
    ctx.enforce_poly_query(product, z, product_at_z)?;

    Ok(())
}

/// Binds a witnessed polynomial handle to the same fixed commitment used by
/// the surrounding header or witness statement.
pub(crate) fn bind_poly_handle<'dr, D>(
    ctx: &mut StepCtx<'_, 'dr, D>,
    handle: &PolyHandle<'dr, D, Pasta>,
    commitment: &[Element<'dr, D>; 2],
    err: &'static str,
) -> Result<()>
where
    D: Driver<'dr, F = Fp>,
{
    let [handle_lo, handle_hi] = poly_handle_limbs(ctx.dr, handle)?;
    let expected_lo = &commitment[0];
    let expected_hi = &commitment[1];
    handle_lo
        .enforce_equal(ctx.dr, expected_lo)
        .map_err(|_err| Error::InvalidWitness(err.into()))?;
    handle_hi
        .enforce_equal(ctx.dr, expected_hi)
        .map_err(|_err| Error::InvalidWitness(err.into()))?;
    Ok(())
}

pub(crate) fn poly_handle_limbs<'dr, D>(
    dr: &mut D,
    handle: &PolyHandle<'dr, D, Pasta>,
) -> Result<[Element<'dr, D>; 2]>
where
    D: Driver<'dr, F = Fp>,
{
    let mut serialized = Vec::new();
    handle.write(dr, &mut serialized)?;
    serialized.try_into().map_err(|_elements| {
        Error::InvalidWitness("polynomial commitment handle did not write two limbs".into())
    })
}

/// Pin a shim handle to the constant polynomial represented by `scalar`.
/// Absorbing both the commitment and scalar prevents choosing the scalar after
/// the validation challenge. The caller reuses this handle's compressed limbs
/// in its original protocol transcript.
pub(crate) fn enforce_constant_polynomial<'dr, D: Driver<'dr, F = Fp>>(
    ctx: &mut StepCtx<'_, 'dr, D>,
    handle: &PolyHandle<'dr, D, Pasta>,
    scalar: &Element<'dr, D>,
    message: &'static str,
) -> Result<()> {
    let limbs = poly_handle_limbs(ctx.dr, handle)?;
    let challenge = ctx.derive_challenge(&(limbs, scalar.clone()))?;
    ctx.enforce_poly_query(handle, challenge, scalar.clone())
        .map_err(|_err| Error::InvalidWitness(message.into()))
}

/// Enforce `accumulator(z) = ∏ᵢ (z - rootᵢ)` for a witnessed handle at its
/// Fiat–Shamir challenge.
///
/// `accumulator` is prover-supplied and the relation does not interpolate the
/// roots. Its evaluation is constrained using the already allocated root
/// elements and submitted as the same opening to the mock.
///
/// # Caller obligation (soundness)
///
/// Only the accumulator handle is absorbed into `z`. The caller must pin each
/// root element through its statement or another constrained relation.
///
/// `N` fixes the root count at compile time.
pub(crate) fn enforce_poly_roots<'dr, D, const N: usize>(
    ctx: &mut StepCtx<'_, 'dr, D>,
    accumulator: &PolyHandle<'dr, D, Pasta>,
    roots: &[Element<'dr, D>; N],
    err: &'static str,
) -> Result<()>
where
    D: Driver<'dr, F = Fp>,
{
    let accumulator_limbs = poly_handle_limbs(ctx.dr, accumulator)?;
    let z = ctx.derive_challenge(&accumulator_limbs)?;
    let accumulator_assignment =
        ctx.evaluate(accumulator, z.value().map(|challenge| *challenge))?;
    let accumulator_at_z = Element::alloc(ctx.dr, &mut (), accumulator_assignment)?;
    let mut factors_at_z = Element::constant(ctx.dr, Fp::ONE);
    for root in roots {
        let factor = z.sub(ctx.dr, root);
        factors_at_z = factors_at_z.mul(ctx.dr, &factor)?;
    }
    accumulator_at_z
        .enforce_equal(ctx.dr, &factors_at_z)
        .map_err(|_err| Error::InvalidWitness(err.into()))?;

    ctx.enforce_poly_query(accumulator, z, accumulator_at_z)?;

    Ok(())
}

/// Enforce componentwise equality of fixed-size field tuples.
pub(crate) fn enforce_equal_fields<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    left: &[Element<'dr, D>; N],
    right: &[Element<'dr, D>; N],
    errors: [&'static str; N],
) -> Result<()> {
    for ((left_field, right_field), message) in left.iter().zip(right.iter()).zip(errors) {
        left_field
            .enforce_equal(dr, right_field)
            .map_err(|_err| Error::InvalidWitness(message.into()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ragu::{
        pasta::Fp,
        primitives::{Element, Simulator},
    };
    use ragu_primitives::GadgetExt as _;
    use udon::field::Field as _;

    use super::indexed_member_factor;

    #[test]
    fn indexed_member_factor_emits_and_checks_driver_arithmetic() {
        let member_value = Fp::from(19);
        let index_value = Fp::from(7);
        let challenge_value = Fp::from(13);
        let expected_value =
            (member_value + index_value * challenge_value).pow_u64(3) - Fp::from(2);

        let driver = Simulator::<Fp>::simulate((), |dr, _| {
            let member_element = Element::constant(dr, member_value);
            let index_element = Element::constant(dr, index_value);
            let challenge_element = Element::constant(dr, challenge_value);
            let factor =
                indexed_member_factor(dr, &member_element, &index_element, &challenge_element)?;
            let expected_element = Element::constant(dr, expected_value);
            factor.enforce_equal(dr, &expected_element)
        })
        .expect("the indexed factor satisfies its fixed polynomial identity");
        assert!(driver.num_gates() >= 3);

        let mismatch = Simulator::<Fp>::simulate((), |dr, _| {
            let member_element = Element::constant(dr, member_value);
            let index_element = Element::constant(dr, index_value);
            let challenge_element = Element::constant(dr, challenge_value);
            let factor =
                indexed_member_factor(dr, &member_element, &index_element, &challenge_element)?;
            let wrong = Element::constant(dr, expected_value + Fp::ONE);
            factor.enforce_equal(dr, &wrong)
        });
        assert!(
            mismatch.is_err(),
            "a different factor must violate equality"
        );
    }
}
