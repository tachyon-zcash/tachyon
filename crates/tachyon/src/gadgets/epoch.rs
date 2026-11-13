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

/// Constrains `epoch` to an epoch index: both `epoch` and `EPOCH_MAX - epoch`
/// must fit the epoch width, preventing field wraparound.
pub(crate) fn enforce_epoch<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    epoch: &Element<'dr, D>,
) -> Result<()> {
    range::enforce_width::<D, { primitives::EpochIndex::BITS }>(dr, epoch)?;
    let maximum = Element::constant(dr, Fp::from(u64::from(EPOCH_MAX)));
    let slack = maximum.sub(dr, epoch);
    range::enforce_width::<D, { primitives::EpochIndex::BITS }>(dr, &slack)
}

/// The index after `epoch`, constrained by [`enforce_epoch`]; `epoch` itself
/// is not checked.
pub(crate) fn successor<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    epoch: &Element<'dr, D>,
) -> Result<Element<'dr, D>> {
    let one = Element::constant(dr, Fp::ONE);
    let successor = epoch.add(dr, &one);
    enforce_epoch(dr, &successor)?;
    Ok(successor)
}

#[cfg(test)]
mod tests;
