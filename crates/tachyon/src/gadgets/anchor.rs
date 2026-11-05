//! Circuit gadgets for anchor values.

scalar_gadget!(AnchorGadget, "AnchorGadget(..)");

use ragu::{Cycle as _, FixedGenerators as _, pasta::Pasta};
use ragu_core::{Error, Result, drivers::Driver};
use ragu_primitives::Element;

use super::arithmetic::bounded;
use crate::{constants::EPOCH_MAX, digest::poseidon, pasta, pasta::Fp};
impl<'dr, D: Driver<'dr, F = Fp>> AnchorGadget<'dr, D> {
    /// Enforce the stamp-fold domain and derive its anchor on the caller
    /// driver.
    pub(crate) fn next_stamp(
        &self,
        dr: &mut D,
        epoch: &Element<'dr, D>,
        limbs: [Element<'dr, D>; 2],
    ) -> Result<Self> {
        let generator = *Pasta::host_generators(pasta::baked())
            .g()
            .first()
            .ok_or_else(|| Error::InvalidWitness("fixed generator table is empty".into()))?;
        let [stamp_low, stamp_high] = limbs;
        let (low, high) = poseidon::commitment_digest(generator);
        {
            let low_element = Element::constant(dr, low);
            let high_element = Element::constant(dr, high);
            let equal_low = stamp_low.is_equal(dr, &mut (), &low_element)?;
            let equal_high = stamp_high.is_equal(dr, &mut (), &high_element)?;
            equal_low
                .and(dr, &equal_high)?
                .element()
                .enforce_zero(dr)
                .map_err(|_err| Error::InvalidWitness("invalid anchor step".into()))?;
        }
        bounded::<D, 32>(dr, epoch, u64::from(EPOCH_MAX))?;
        poseidon::anchor_next_stamp_gadget(dr, &self.element, epoch, &[stamp_low, stamp_high])
            .map(Into::into)
    }
}
