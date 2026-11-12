//! Range checks for proof steps.

use ragu_core::{Result, drivers::Driver, maybe::Maybe as _};
use ragu_primitives::{
    Boolean, Element, GadgetExt as _, multipack,
    vec::{ConstLen, FixedVec},
};
use udon::field::Field as _;

use crate::pasta::Fp;

/// Constrains `value` below $2^N$ by decomposing it into `N` Boolean bits that
/// pack back to it.
#[expect(
    clippy::indexing_slicing,
    reason = "multipack packs at most 64 bits into one chunk"
)]
pub(crate) fn enforce_width<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    value: &Element<'dr, D>,
) -> Result<()> {
    const {
        assert!(N > 0 && N <= 64, "a range check covers at most 64 bits");
    }
    let bits = FixedVec::<_, ConstLen<N>>::try_from_fn(|index| {
        Boolean::alloc(
            dr,
            &mut (),
            value
                .value()
                .map(|candidate| candidate.to_le_bits().as_ref()[index]),
        )
    })?;
    multipack(dr, &bits)?[0].enforce_equal(dr, value)
}
