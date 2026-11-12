//! Note master keys inside a circuit.

use ragu_core::{
    PoseidonPermutation as _, Result,
    drivers::{Coeff, Driver},
    gadgets::Gadget,
    maybe::Maybe as _,
    pasta::PoseidonFp,
};
use ragu_primitives::{Boolean, Element, io::Write};
use udon::field::Field as _;

use super::range;
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

const _: () = assert!(
    PoseidonFp::RATE == 1 << (u32::BITS - 30),
    "derive_nullifier writes an epoch as four times a 30-bit group plus two position bits"
);

impl<'dr, D: Driver<'dr, F = Fp>> NoteMasterKey<'dr, D> {
    /// The nullifier for `epoch`: entry $b_0 + 2 b_1$ of the
    /// `PoseidonFp::RATE`-element group starting at $4g$, for
    /// $\mathsf{epoch} = 4g + b_0 + 2 b_1$ with Boolean $b_0, b_1$ and
    /// $g < 2^{30}$.
    ///
    /// The decomposition is unique and proves $\mathsf{epoch} < 2^{32}$; the
    /// caller bounds the epoch by `EPOCH_MAX`.
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
        #[expect(clippy::expect_used, reason = "four is invertible in Fp")]
        let quarter = Fp::from(4).invert().expect("four is invertible");
        let group = group_start.scale(dr, Coeff::Arbitrary(quarter));
        range::enforce_width::<D, 30>(dr, &group)?;
        let [first, second, third, fourth] =
            poseidon::circuit::nullifier_group(dr, &self.element, &group_start)?;
        let lower = low.conditional_select(dr, &first, &second)?;
        let upper = low.conditional_select(dr, &third, &fourth)?;
        high.conditional_select(dr, &lower, &upper)
    }
}

#[cfg(test)]
mod tests;
