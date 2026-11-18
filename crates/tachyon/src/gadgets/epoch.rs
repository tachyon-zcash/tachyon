//! Epoch indices inside a circuit.

use core::ops::Deref;

use ragu::drivers::{Driver, DriverValue};
use ragu::gadgets::Gadget;
use ragu::maybe::Maybe as _;
use ragu::pasta::PoseidonFp;
use ragu::primitives::allocator::Allocator;
use ragu::primitives::comparison::GadgetEquals;
use ragu::primitives::io::Write;
use ragu::primitives::{Boolean, Element};
use ragu::{PoseidonPermutation as _, Result};
use udon::field::Field as _;

use super::uint::Uint;
use crate::constants::EPOCH_MAX;
use crate::pasta::Fp;
use crate::primitives;

#[expect(clippy::as_conversions, reason = "an epoch has at most 32 bits")]
const EPOCH_BITS: usize = (EPOCH_MAX + 1).ilog2() as usize;

/// A [`primitives::EpochIndex`] inside a circuit: an index in
/// `0..=EPOCH_MAX`. `EPOCH_MAX + 1` is a power of two, so the bits of the
/// epoch width bound it exactly.
#[derive(Gadget, Write, GadgetEquals)]
#[expect(
    missing_debug_implementations,
    reason = "a gadget holds driver wires, like the header gadgets it sits in"
)]
pub struct EpochIndex<'dr, D: Driver<'dr>> {
    element: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> Deref for EpochIndex<'dr, D> {
    type Target = Element<'dr, D>;

    fn deref(&self) -> &Element<'dr, D> {
        &self.element
    }
}

impl<'dr, D: Driver<'dr, F = Fp>> EpochIndex<'dr, D> {
    /// Allocates `epoch` and range-checks it.
    pub(crate) fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        epoch: DriverValue<D, primitives::EpochIndex>,
    ) -> Result<Self> {
        let element = Element::alloc(dr, allocator, epoch.map(Fp::from))?;
        Uint::<_, EPOCH_BITS>::from_element(dr, &element)?;
        Ok(Self { element })
    }

    /// The epoch `bits` encodes.
    pub(crate) fn from_bits(dr: &mut D, bits: &Uint<'dr, D, EPOCH_BITS>) -> Result<Self> {
        Ok(Self {
            element: bits.pack(dr)?,
        })
    }

    /// The epoch `bits` encodes, with its low `log2(RATE)` bits held to zero:
    /// the first epoch of a nullifier group.
    pub(crate) fn from_group_start(dr: &mut D, bits: &Uint<'dr, D, EPOCH_BITS>) -> Result<Self> {
        for (bit, _) in bits.bits().iter().zip(0..PoseidonFp::RATE.ilog2()) {
            bit.element().enforce_zero(dr)?;
        }
        Self::from_bits(dr, bits)
    }

    /// The index after this one. Range-checks both this index and the
    /// result; unsatisfiable at `EPOCH_MAX`.
    pub(crate) fn next(&self, dr: &mut D) -> Result<Self> {
        Uint::<_, EPOCH_BITS>::from_element(dr, &self.element)?;
        let one = Element::constant(dr, Fp::ONE);
        let element = self.element.add(dr, &one);
        Uint::<_, EPOCH_BITS>::from_element(dr, &element)?;
        Ok(Self { element })
    }

    /// Splits this index into the first epoch of its nullifier group and the
    /// two low bits that select within the group.
    pub(crate) fn group(&self, dr: &mut D) -> Result<(Element<'dr, D>, [Boolean<'dr, D>; 2])> {
        let bits = Uint::<_, EPOCH_BITS>::from_element(dr, &self.element)?;
        let mut low_bits = bits.bits().iter().cloned();
        #[expect(
            clippy::expect_used,
            reason = "the fixed epoch width includes two low bits"
        )]
        let [low, high] = [(); 2].map(|()| low_bits.next().expect("an epoch has two low bits"));
        let twice_high = high.element().double(dr);
        let group_start = self.element.sub(dr, &low.element()).sub(dr, &twice_high);
        Ok((group_start, [low, high]))
    }
}

#[cfg(test)]
mod tests;
