//! Circuit gadgets for anchor values.

scalar_gadget!(AnchorGadget, "AnchorGadget(..)");

use ragu::{
    Cycle as _, FixedGenerators as _,
    pasta::{EqAffine, Fp, Pasta},
};
use ragu_core::{Error, Result, drivers::Driver};
use ragu_pcd::pasta::baked;
use ragu_primitives::Element;
use udon::{curve::Affine as _, field::Field as _};

use super::arithmetic::bounded;
use crate::{constants::EPOCH_MAX, digest::poseidon};
impl<'dr, D: Driver<'dr, F = Fp>> AnchorGadget<'dr, D> {
    /// Enforce the stamp-fold domain and derive its anchor on the caller
    /// driver.
    pub(crate) fn next_stamp(
        &self,
        dr: &mut D,
        epoch: Element<'dr, D>,
        limbs: [Element<'dr, D>; 2],
    ) -> Result<Self> {
        let generator = *Pasta::host_generators(baked())
            .g()
            .first()
            .ok_or_else(|| Error::InvalidWitness("fixed generator table is empty".into()))?;
        let [stamp_low, stamp_high] = limbs;
        for excluded in [EqAffine::identity(), generator] {
            let bytes = excluded.to_bytes();
            let (low, high) = bytes.split_at(16);
            let low_element = Element::constant(
                dr,
                Fp::from_u128(u128::from_le_bytes(low.try_into().map_err(|_err| {
                    Error::InvalidWitness("invalid fixed limb width".into())
                })?)),
            );
            let high_element = Element::constant(
                dr,
                Fp::from_u128(u128::from_le_bytes(high.try_into().map_err(|_err| {
                    Error::InvalidWitness("invalid fixed limb width".into())
                })?)),
            );
            let equal_low = stamp_low.is_equal(dr, &mut (), &low_element)?;
            let equal_high = stamp_high.is_equal(dr, &mut (), &high_element)?;
            equal_low
                .and(dr, &equal_high)?
                .element()
                .enforce_zero(dr)
                .map_err(|_err| Error::InvalidWitness("invalid anchor step".into()))?;
        }
        bounded::<D, 32>(dr, &epoch, u64::from(EPOCH_MAX))?;
        poseidon::anchor_next_stamp_circuit(
            dr,
            &[self.element.clone(), epoch, stamp_low, stamp_high],
        )
        .map(Into::into)
    }
}
