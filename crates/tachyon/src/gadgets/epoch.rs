//! Epoch gadgets for proof steps.

use ragu_core::{
    PoseidonPermutation as _, Result,
    drivers::{Coeff, Driver},
    pasta::PoseidonFp,
};
use ragu_primitives::Element;
use udon::field::Field as _;

use super::range;
use crate::{constants::EPOCH_MAX, pasta::Fp};

/// Constrains `group_start` to `PoseidonFp::RATE` times a group index within
/// the epoch width less `log2(RATE)` bits, so it is the first epoch of a
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
    range::enforce_width::<D, { u32::BITS - PoseidonFp::RATE.ilog2() }>(dr, &group_index)
}

/// Constrains `epoch` to an epoch index, `0..=EPOCH_MAX`: `EPOCH_MAX + 1` is a
/// power of two, so one width check bounds it exactly.
pub(crate) fn enforce_epoch<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    epoch: &Element<'dr, D>,
) -> Result<()> {
    range::enforce_width::<D, { (EPOCH_MAX + 1).ilog2() }>(dr, epoch)
}

/// The index after `epoch`, with both `epoch` and the result constrained by
/// [`enforce_epoch`].
pub(crate) fn successor<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    epoch: &Element<'dr, D>,
) -> Result<Element<'dr, D>> {
    enforce_epoch(dr, epoch)?;
    let one = Element::constant(dr, Fp::ONE);
    let successor = epoch.add(dr, &one);
    enforce_epoch(dr, &successor)?;
    Ok(successor)
}

#[cfg(test)]
mod tests;
