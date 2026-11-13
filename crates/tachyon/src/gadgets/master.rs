//! Note master keys inside a circuit.

use ragu_core::{Result, drivers::Driver, gadgets::Gadget, maybe::Maybe as _};
use ragu_primitives::{Boolean, Element, io::Write};
use udon::field::Field as _;

use super::epoch;
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
    /// `PoseidonFp::RATE`-element group starting at $4g$, for
    /// $\mathsf{epoch} = 4g + b_0 + 2 b_1$ with Boolean $b_0, b_1$ and
    /// $g < 2^{30}$.
    ///
    /// The decomposition is unique and proves $\mathsf{epoch} < 2^{32}$.
    #[expect(
        clippy::indexing_slicing,
        reason = "bits 0 and 1 of a canonical field encoding"
    )]
    pub(crate) fn derive_nullifier(
        &self,
        dr: &mut D,
        epoch: &Element<'dr, D>,
    ) -> Result<Element<'dr, D>> {
        let [low_bit, high_bit] = [0, 1].map(|index| {
            epoch
                .value()
                .map(|candidate| candidate.to_le_bits().as_ref()[index])
        });
        let low = Boolean::alloc(dr, &mut (), low_bit)?;
        let high = Boolean::alloc(dr, &mut (), high_bit)?;
        let twice_high = high.element().double(dr);
        let group_start = epoch.sub(dr, &low.element()).sub(dr, &twice_high);
        epoch::enforce_group_start(dr, &group_start)?;
        let [first, second, third, fourth] =
            poseidon::circuit::nullifier_group(dr, &self.element, &group_start)?;
        let lower = low.conditional_select(dr, &first, &second)?;
        let upper = low.conditional_select(dr, &third, &fourth)?;
        high.conditional_select(dr, &lower, &upper)
    }
}

#[cfg(test)]
mod tests;
