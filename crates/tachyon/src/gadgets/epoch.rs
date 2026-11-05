//! Circuit gadgets for epoch values.

scalar_gadget!(EpochIndexGadget, "EpochIndexGadget(..)");

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe as _,
};
use ragu_primitives::Element;
use udon::field::Field as _;

use super::arithmetic::bounded;
use crate::{constants::EPOCH_MAX, pasta::Fp, primitives::EpochIndex};
impl<'dr, D: Driver<'dr, F = Fp>> EpochIndexGadget<'dr, D> {
    /// A bounded successor, with no field wrap and no final-epoch overflow.
    pub(crate) fn next(&self, dr: &mut D) -> Result<Self> {
        let epoch = &self.element;
        bounded::<D, 32>(dr, epoch, u64::from(EPOCH_MAX))?;
        let one = Element::constant(dr, Fp::ONE);
        let next = epoch.add(dr, &one);
        bounded::<D, 32>(dr, &next, u64::from(EPOCH_MAX))?;
        Ok(next.into())
    }

    /// Read a bounded circuit result into the prover-side Data carrier.
    pub(crate) fn value(&self) -> DriverValue<D, EpochIndex> {
        self.element.value().map(|candidate| {
            let [first, second, third, fourth, ..] = candidate.to_bytes();
            EpochIndex::new(u32::from_le_bytes([first, second, third, fourth]))
        })
    }
}

#[cfg(test)]
mod tests;
