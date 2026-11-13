//! Epoch gadgets for proof steps.

use ragu_core::{
    PoseidonPermutation as _, Result,
    drivers::{Coeff, Driver},
    pasta::PoseidonFp,
};
use ragu_primitives::Element;
use udon::field::Field as _;

use super::range;
use crate::{constants::EPOCH_MAX, nullifier, pasta::Fp, primitives};

/// Constrains `group_start` to `PoseidonFp::RATE` times a group index within
/// [`GROUP_BITS`](nullifier::GROUP_BITS), so it is the first epoch of a
/// nullifier group and cannot wrap.
pub(crate) fn enforce_group_start<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    group_start: &Element<'dr, D>,
) -> Result<()> {
    #[expect(
        clippy::expect_used,
        reason = "the sponge rate is a small nonzero constant"
    )]
    let inverse_rate = Fp::from(1u64 << PoseidonFp::RATE.ilog2())
        .invert()
        .expect("the sponge rate is invertible");
    let group_index = group_start.scale(dr, Coeff::Arbitrary(inverse_rate));
    range::enforce_width::<D, { nullifier::GROUP_BITS }>(dr, &group_index)
}

/// A range-checked epoch index inside a circuit.
pub(crate) struct EpochIndex<'dr, D: Driver<'dr>> {
    element: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr, F = Fp>> EpochIndex<'dr, D> {
    /// Both the index and `EPOCH_MAX - index` must fit the epoch width,
    /// preventing field wraparound.
    pub(crate) fn new(dr: &mut D, epoch: &Element<'dr, D>) -> Result<Self> {
        range::enforce_width::<D, { primitives::EpochIndex::BITS }>(dr, epoch)?;
        let maximum = Element::constant(dr, Fp::from(u64::from(EPOCH_MAX)));
        let slack = maximum.sub(dr, epoch);
        range::enforce_width::<D, { primitives::EpochIndex::BITS }>(dr, &slack)?;
        Ok(Self {
            element: epoch.clone(),
        })
    }

    /// The range-checked index after `epoch`, which this does not check.
    pub(crate) fn successor(dr: &mut D, epoch: &Element<'dr, D>) -> Result<Self> {
        let one = Element::constant(dr, Fp::ONE);
        let successor = epoch.add(dr, &one);
        Self::new(dr, &successor)
    }

    pub(crate) fn into_element(self) -> Element<'dr, D> {
        self.element
    }
}

#[cfg(test)]
mod tests;
