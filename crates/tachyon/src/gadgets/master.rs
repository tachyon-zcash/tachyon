//! Note master keys inside a circuit.

use ragu::Result;
use ragu::drivers::Driver;
use ragu::gadgets::Gadget;
use ragu::primitives::Element;
use ragu::primitives::io::Write;

use super::epoch::EpochIndex;
use crate::digest::poseidon;
use crate::pasta::Fp;

/// A [`NoteMasterKey`](crate::keys::NoteMasterKey) inside a circuit.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "a gadget holds driver wires, like the header gadgets it sits in"
)]
pub struct NoteMasterKey<'dr, D: Driver<'dr>> {
    pub element: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr, F = Fp>> NoteMasterKey<'dr, D> {
    /// The nullifier for `epoch`: entry $b_{0} + 2 b_{1}$ of the
    /// `PoseidonFp::RATE`-element group starting at `epoch` with its two low
    /// bits $b_{0}, b_{1}$ cleared.
    ///
    /// # Errors
    ///
    /// Returns an error if epoch decomposition, sponge evaluation, or
    /// conditional selection fails.
    pub(crate) fn derive_nullifier(
        &self,
        dr: &mut D,
        epoch: &EpochIndex<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let (group_start, [low, high]) = epoch.group(dr)?;
        let [first, second, third, fourth] =
            poseidon::circuit::nullifier_group(dr, &self.element, &group_start)?;
        let lower = low.conditional_select(dr, &first, &second)?;
        let upper = low.conditional_select(dr, &third, &fourth)?;
        high.conditional_select(dr, &lower, &upper)
    }
}
