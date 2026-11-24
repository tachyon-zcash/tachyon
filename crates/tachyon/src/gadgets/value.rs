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

/// An in-circuit [`value::Positive`]. Every constructor bounds the element to
/// `0..=MAX_MONEY`, below both $2^{51}$ and the modulus.
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
    /// Allocates `value` and bounds its 51-bit decomposition by `MAX_MONEY`.
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

    /// Bounds `bits` by `MAX_MONEY` and packs them into the amount. These same
    /// 51 bits uniquely encode the amount for fixed-base multiplication.
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

    /// Bounding `slack` by `MAX_MONEY` makes `MAX_MONEY - slack` an unwrapped
    /// amount that uniquely determines `slack`.
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
    /// Packs `part` from 51 freely chosen Boolean wires and decomposes `self -
    /// part` into 51 bits. Two integers below $2^{51}$ sum to less than the
    /// modulus, so they sum to `self` over the integers and both lie in
    /// `0..=self` as amounts.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub(crate) fn split(&self, dr: &mut D, part: DriverValue<D, Fp>) -> Result<(Self, Self)> {
        let packed = Uint::<_, { MAX_MONEY.bit_width() as usize }>::alloc(dr, part)?.pack(dr)?;
        let rest = self.element.sub(dr, &packed);
        decompose_n::<_, { MAX_MONEY.bit_width() as usize }>(dr, &mut (), &rest)?;
        Ok((Self { element: packed }, Self { element: rest }))
    }

    /// The amount's unique 51-bit decomposition.
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
