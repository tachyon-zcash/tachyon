//! Generic fixed-width circuit arithmetic.

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe as _,
};
use ragu_primitives::{
    Boolean, Element, GadgetExt as _, multipack,
    vec::{ConstLen, FixedVec},
};
use udon::field::Field as _;

use crate::pasta::{Fp, Fq};
/// Unique little-endian decomposition. The canonical comparison matters at
/// 255 bits, where a modular recomposition alone would allow aliases.
#[expect(clippy::indexing_slicing, reason = "fixed field and bit widths")]
pub(crate) fn bits<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    value: &Element<'dr, D>,
) -> Result<FixedVec<Boolean<'dr, D>, ConstLen<N>>> {
    const {
        assert!(N > 0 && N <= 255, "decomposition width must fit the field");
    }
    let bits = FixedVec::try_from_fn(|i| {
        Boolean::alloc(
            dr,
            &mut (),
            value
                .value()
                .map(|candidate| candidate.to_le_bits().as_ref()[i]),
        )
    })?;
    let packed = multipack(dr, &bits)?;
    let recomposed = if N == 255 {
        let high_weight = Element::constant(dr, Fp::from(2).pow_u64(254));
        let high = packed[1].mul(dr, &high_weight)?;
        packed[0].add(dr, &high)
    } else {
        packed[0].clone()
    };
    recomposed.enforce_equal(dr, value)?;
    if N == 255 {
        let maximum = (-Fp::ONE).to_le_bits();
        let mut equal = Element::constant(dr, Fp::ONE);
        for i in (0..255).rev() {
            if maximum.as_ref()[i] {
                equal = equal.mul(dr, &bits[i].element())?;
            } else {
                equal.mul(dr, &bits[i].element())?.enforce_zero(dr)?;
            }
        }
    }
    Ok(bits)
}

/// Bounded unsigned integer: both the value and its slack have N bits.
/// The caller supplies a public maximum below 2^N; N is at most 64, so
/// neither side of the slack equation can wrap in the circuit field.
pub(crate) fn bounded<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    value: &Element<'dr, D>,
    maximum: u64,
) -> Result<()> {
    const {
        assert!(
            N > 0 && N <= 64,
            "bounded integer width must be at most 64 bits"
        );
    }
    bits::<D, N>(dr, value)?;
    let maximum_element = Element::constant(dr, Fp::from(maximum));
    let slack = maximum_element.sub(dr, value);
    bits::<D, N>(dr, &slack)?;
    Ok(())
}

/// A free scalar's canonical bits. It is used only as a blinding witness;
/// no arithmetic-field embedding of Fq into Fp is assumed.
#[expect(clippy::indexing_slicing, reason = "fixed 255-bit scalar width")]
pub(crate) fn scalar_bits<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    scalar: &DriverValue<D, Fq>,
) -> Result<FixedVec<Boolean<'dr, D>, ConstLen<255>>> {
    let bits = FixedVec::try_from_fn(|i| {
        Boolean::alloc(
            dr,
            &mut (),
            scalar
                .as_ref()
                .map(|candidate| candidate.to_le_bits().as_ref()[i]),
        )
    })?;
    let maximum = (-Fq::ONE).to_le_bits();
    let mut equal = Element::constant(dr, Fp::ONE);
    for i in (0..255).rev() {
        if maximum.as_ref()[i] {
            equal = equal.mul(dr, &bits[i].element())?;
        } else {
            equal.mul(dr, &bits[i].element())?.enforce_zero(dr)?;
        }
    }
    Ok(bits)
}

#[cfg(test)]
mod tests;
