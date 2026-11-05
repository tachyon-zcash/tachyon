//! Polynomial identities over slots fixed before the framework's challenge.
//!
//! Child slots are bound by PCD; output slots are supplied by
//! `Step::polynomials`. Callers preserve the correspondence between slots and
//! semantic header fields.

use ragu::{Oracles, Slot};
use ragu_core::{Error, Result, drivers::Driver};
use ragu_primitives::{Element, GadgetExt as _};
use udon::field::Field as _;

use crate::pasta::Fp;

/// Preserve a carried polynomial when a step copies a slot.
pub(crate) fn enforce_poly_equal<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    oracles: &mut Oracles<'_, 'dr, D>,
    left: Slot,
    right: Slot,
) -> Result<()> {
    let left_value = oracles.query_at_zeta(dr, left)?;
    let right_value = oracles.query_at_zeta(dr, right)?;
    left_value.enforce_equal(dr, &right_value)
}

/// Enforce `product(ζ) = multiplicand(ζ) * multiplier(ζ)`.
pub(crate) fn enforce_poly_product<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    oracles: &mut Oracles<'_, 'dr, D>,
    multiplicand: &Slot,
    multiplier: &Slot,
    product: &Slot,
    err: &'static str,
) -> Result<()> {
    let multiplicand_value = oracles.query_at_zeta(dr, *multiplicand)?;
    let multiplier_value = oracles.query_at_zeta(dr, *multiplier)?;
    let product_value = oracles.query_at_zeta(dr, *product)?;
    let expected = multiplicand_value.mul(dr, &multiplier_value)?;
    product_value
        .enforce_equal(dr, &expected)
        .map_err(|_err| Error::InvalidWitness(err.into()))
}

/// Enforce `accumulator(ζ) = ∏ᵢ (ζ - rootᵢ)` for a fixed root count.
pub(crate) fn enforce_poly_roots<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    oracles: &mut Oracles<'_, 'dr, D>,
    accumulator: &Slot,
    roots: &[Element<'dr, D>; N],
    err: &'static str,
) -> Result<()> {
    let z = oracles.zeta().clone();
    let accumulator_value = oracles.query_at_zeta(dr, *accumulator)?;
    let mut expected = Element::constant(dr, Fp::ONE);
    for root in roots {
        let factor = z.sub(dr, root);
        expected = expected.mul(dr, &factor)?;
    }
    accumulator_value
        .enforce_equal(dr, &expected)
        .map_err(|_err| Error::InvalidWitness(err.into()))
}
