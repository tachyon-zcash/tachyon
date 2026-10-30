//! Circuit gadgets for keys values.

scalar_gadget!(PaymentKeyGadget, "PaymentKeyGadget(..)");
scalar_gadget!(NoteMasterKeyGadget, "NoteMasterKeyGadget(..)");

use ragu::pasta::Fp;
use ragu_core::drivers::Driver;
use ragu_primitives::Element;

use crate::digest::poseidon;

impl<'dr, D: Driver<'dr, F = Fp>> NoteMasterKeyGadget<'dr, D> {
    /// Derive one group and select its epoch lane using constrained low bits.
    #[expect(
        clippy::indexing_slicing,
        clippy::missing_asserts_for_indexing,
        reason = "the epoch decomposition has exactly 32 bits"
    )]
    pub(crate) fn derive_nullifier(
        &self,
        dr: &mut D,
        epoch: &Element<'dr, D>,
    ) -> ragu_core::Result<super::nullifier::NullifierGadget<'dr, D>> {
        let bits = super::arithmetic::bits::<D, 32>(dr, epoch)?;
        let low = &bits[0];
        let high = &bits[1];
        let twice_high = high.element().double(dr);
        let group = epoch.sub(dr, &low.element()).sub(dr, &twice_high);
        let [first, second, third, fourth] =
            poseidon::nullifier_group_circuit(dr, &self.element, &group)?;
        let lower = low.conditional_select(dr, &first, &second)?;
        let upper = low.conditional_select(dr, &third, &fourth)?;
        high.conditional_select(dr, &lower, &upper).map(Into::into)
    }
}
