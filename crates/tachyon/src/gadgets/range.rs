//! Range checks for proof steps.

use alloc::vec::Vec;

use ragu_core::{Result, drivers::Driver, maybe::Maybe as _};
use ragu_primitives::{Boolean, Element, GadgetExt as _, multipack};
use udon::field::Field as _;

use crate::{
    constants::{MAX_MONEY, MAX_MONEY_BITS},
    pasta::Fp,
};

/// Constrains `value` below $2^{BITS}$ by decomposing it into `BITS` Boolean
/// bits that pack back to it.
#[expect(
    clippy::indexing_slicing,
    reason = "multipack packs at most 64 bits into one chunk"
)]
pub(crate) fn enforce_width<'dr, D: Driver<'dr, F = Fp>, const BITS: u32>(
    dr: &mut D,
    value: &Element<'dr, D>,
) -> Result<()> {
    const {
        assert!(
            BITS > 0 && BITS <= u64::BITS,
            "a range check covers at most 64 bits"
        );
    }
    let bits = (0..BITS)
        .map(|position| {
            Boolean::alloc(
                dr,
                &mut (),
                value.value().map(|candidate| {
                    candidate
                        .to_le_bits()
                        .as_ref()
                        .iter()
                        .zip(0..BITS)
                        .any(|(bit, index)| index == position && *bit)
                }),
            )
        })
        .collect::<Result<Vec<_>>>()?;
    multipack(dr, &bits)?[0].enforce_equal(dr, value)
}

/// Constrains `value` to `0..=MAX_MONEY`, the range of a valid amount.
///
/// `value` and `MAX_MONEY - value` each fit [`MAX_MONEY_BITS`] bits. Their sum
/// is `MAX_MONEY`, far below the field modulus, so neither wraps.
pub(crate) fn enforce_money<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    value: &Element<'dr, D>,
) -> Result<()> {
    enforce_width::<D, MAX_MONEY_BITS>(dr, value)?;
    let slack = Element::constant(dr, Fp::from(MAX_MONEY)).sub(dr, value);
    enforce_width::<D, MAX_MONEY_BITS>(dr, &slack)
}
