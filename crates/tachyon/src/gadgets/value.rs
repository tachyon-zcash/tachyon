//! Note amounts inside a circuit.

use core::ops::Deref;

use ragu::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe as _,
    primitives::{
        Element, allocator::Allocator, comparison::GadgetEquals, decompose_n, enforce_le_bits,
        io::Write,
    },
};

use super::uint::Uint;
use crate::{constants::MAX_MONEY, pasta::Fp, value};

/// A [`value::Positive`] inside a circuit: an amount in `0..=MAX_MONEY`.
///
/// # Injectivity
///
/// The element stands for an integer in `0..=MAX_MONEY`. `MAX_MONEY` is below
/// $2^{51}$, so the element is that integer and no other. The field is
/// private and every constructor below forces the range, so each `Positive`
/// of a satisfied circuit holds an amount.
#[derive(Gadget, Write, GadgetEquals)]
#[expect(
    missing_debug_implementations,
    reason = "a gadget holds driver wires, like the header gadgets it sits in"
)]
pub struct Positive<'dr, D: Driver<'dr>> {
    element: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> Deref for Positive<'dr, D> {
    type Target = Element<'dr, D>;

    fn deref(&self) -> &Element<'dr, D> {
        &self.element
    }
}

impl<'dr, D: Driver<'dr, F = Fp>> Positive<'dr, D> {
    /// Allocates `value` and bounds it to `0..=MAX_MONEY`.
    ///
    /// The check decomposes the element into 51 bits and compares their
    /// integer with `MAX_MONEY`.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub(crate) fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        value: DriverValue<D, value::Positive>,
    ) -> Result<Self> {
        let element = Element::alloc(dr, allocator, value.map(u64::from).map(Fp::from))?;
        element.enforce_le::<{ MAX_MONEY.bit_width() as usize }>(
            dr,
            &mut (),
            Fp::from(MAX_MONEY),
        )?;
        Ok(Self { element })
    }

    /// The amount `bits` encodes, bounded by `MAX_MONEY`.
    ///
    /// The bound is on the integer of the bits and the element is their
    /// packing, so `bits` is the amount's only 51-bit decomposition. A fixed
    /// base multiplied by `bits` is multiplied by the amount.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub(crate) fn from_bits(
        dr: &mut D,
        bits: &Uint<'dr, D, { MAX_MONEY.bit_width() as usize }>,
    ) -> Result<Self> {
        enforce_le_bits(dr, bits.bits(), Fp::from(MAX_MONEY))?;
        Ok(Self {
            element: bits.pack(dr)?,
        })
    }

    /// The amount `MAX_MONEY - slack`, with `slack` bounded by `MAX_MONEY`.
    ///
    /// `slack` is at most `MAX_MONEY` as an integer, so the difference does
    /// not wrap. The amount and `slack` determine each other.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub(crate) fn from_slack(
        dr: &mut D,
        slack: &Uint<'dr, D, { MAX_MONEY.bit_width() as usize }>,
    ) -> Result<Self> {
        let maximum = Fp::from(MAX_MONEY);
        enforce_le_bits(dr, slack.bits(), maximum)?;
        let packed_slack = slack.pack(dr)?;
        Ok(Self {
            element: Element::constant(dr, maximum).sub(dr, &packed_slack),
        })
    }

    /// The zero amount, holding `element` to zero.
    pub(crate) fn from_zero(dr: &mut D, element: Element<'dr, D>) -> Result<Self> {
        element.enforce_zero(dr)?;
        Ok(Self { element })
    }

    /// `(part, self - part)`.
    ///
    /// `part` is the packing of 51 bits with no other constraint, and
    /// `self - part` is held to 51 bits. Two integers below $2^{51}$ sum to
    /// less than the modulus, so their sum is `self` over the integers. Both
    /// are then in `0..=self`, and both are amounts.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub(crate) fn split(&self, dr: &mut D, part: DriverValue<D, Fp>) -> Result<(Self, Self)> {
        let packed = Uint::<_, { MAX_MONEY.bit_width() as usize }>::alloc(dr, part)?.pack(dr)?;
        let rest = self.element.sub(dr, &packed);
        decompose_n::<_, { MAX_MONEY.bit_width() as usize }>(dr, &mut (), &rest)?;
        Ok((Self { element: packed }, Self { element: rest }))
    }

    /// The amount's bits, its only 51-bit decomposition.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub(crate) fn to_bits(
        &self,
        dr: &mut D,
    ) -> Result<Uint<'dr, D, { MAX_MONEY.bit_width() as usize }>> {
        Uint::from_element(dr, &self.element)
    }
}

#[cfg(test)]
mod tests;
