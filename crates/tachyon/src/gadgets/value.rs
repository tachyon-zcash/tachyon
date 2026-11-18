//! Note amounts inside a circuit.

use core::ops::Deref;

use ragu::Result;
use ragu::drivers::{Driver, DriverValue};
use ragu::gadgets::Gadget;
use ragu::maybe::Maybe as _;
use ragu::primitives::Element;
use ragu::primitives::allocator::Allocator;
use ragu::primitives::comparison::GadgetEquals;
use ragu::primitives::io::Write;

use super::uint::Uint;
use crate::constants::MAX_MONEY;
use crate::pasta::Fp;
use crate::value;

#[expect(
    clippy::as_conversions,
    reason = "a monetary amount has at most 64 bits"
)]
const MONEY_BITS: usize = MAX_MONEY.bit_width() as usize;

/// A [`value::Positive`] inside a circuit: an amount in `0..=MAX_MONEY`.
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
    pub(crate) fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        value: DriverValue<D, value::Positive>,
    ) -> Result<Self> {
        let element = Element::alloc(dr, allocator, value.map(u64::from).map(Fp::from))?;
        Uint::<_, MONEY_BITS>::from_element(dr, &element)?.enforce_max(dr, MAX_MONEY)?;
        Ok(Self { element })
    }

    /// The amount `bits` encodes, bounded by `MAX_MONEY`.
    pub(crate) fn from_bits(dr: &mut D, bits: &Uint<'dr, D, MONEY_BITS>) -> Result<Self> {
        bits.enforce_max(dr, MAX_MONEY)?;
        Ok(Self {
            element: bits.pack(dr)?,
        })
    }

    /// The amount `MAX_MONEY - slack`, with `slack` bounded by `MAX_MONEY`.
    pub(crate) fn from_slack(dr: &mut D, slack: &Uint<'dr, D, MONEY_BITS>) -> Result<Self> {
        Ok(Self {
            element: slack.enforce_max(dr, MAX_MONEY)?.pack(dr)?,
        })
    }

    /// The zero amount, holding `element` to zero.
    pub(crate) fn from_zero(dr: &mut D, element: Element<'dr, D>) -> Result<Self> {
        element.enforce_zero(dr)?;
        Ok(Self { element })
    }

    /// `(part, self - part)`. Both fit the width of `MAX_MONEY` and sum to
    /// `self`, so neither wraps and both are amounts.
    pub(crate) fn split(&self, dr: &mut D, part: DriverValue<D, Fp>) -> Result<(Self, Self)> {
        let packed = Uint::<_, MONEY_BITS>::alloc(dr, part)?.pack(dr)?;
        let rest = self.element.sub(dr, &packed);
        Uint::<_, MONEY_BITS>::from_element(dr, &rest)?;
        Ok((Self { element: packed }, Self { element: rest }))
    }

    /// The amount's bits.
    pub(crate) fn to_bits(&self, dr: &mut D) -> Result<Uint<'dr, D, MONEY_BITS>> {
        Uint::from_element(dr, &self.element)
    }
}

#[cfg(test)]
mod tests;
