//! Note master keys inside a circuit.

use ragu_core::{Result, drivers::Driver, gadgets::Gadget};
use ragu_primitives::{Element, io::Write};

use super::epoch::EpochIndex;
use crate::{digest::poseidon, pasta::Fp};

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
    /// The nullifier for `epoch`: entry $b_0 + 2 b_1$ of the
    /// `PoseidonFp::RATE`-element group starting at `epoch` with its two low
    /// bits $b_0, b_1$ cleared.
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
