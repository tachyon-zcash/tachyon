//! Unsigned integers held as their bits inside a circuit.

use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe as _,
};
use ragu_primitives::{
    Boolean, Element, GadgetExt as _, multipack,
    vec::{ConstLen, FixedVec},
};
use udon::field::Field as _;

use crate::pasta::Fp;

/// A value held as `BITS` little-endian Boolean bits, so it is below
/// $2^{BITS}$.
#[derive(Gadget)]
pub(crate) struct Uint<'dr, D: Driver<'dr>, const BITS: usize> {
    #[ragu(gadget)]
    bits: FixedVec<Boolean<'dr, D>, ConstLen<BITS>>,
}

impl<'dr, D: Driver<'dr, F = Fp>, const BITS: usize> Uint<'dr, D, BITS> {
    /// Allocates the bits of `value`, which must fit `BITS` bits.
    pub(crate) fn alloc(dr: &mut D, value: DriverValue<D, Fp>) -> Result<Self> {
        let bits = D::try_just(|| {
            let bits = value.take().to_le_bits();
            if bits.as_ref().iter().skip(BITS).any(|bit| *bit) {
                return Err(Error::InvalidWitness("value exceeds its bit width".into()));
            }
            Ok(bits)
        })?;
        Ok(Self {
            bits: FixedVec::try_from_fn(|index| {
                Boolean::alloc(
                    dr,
                    &mut (),
                    bits.as_ref()
                        .map(|candidate| candidate.as_ref().get(index).is_some_and(|bit| *bit)),
                )
            })?,
        })
    }

    /// Decomposes `element` into `BITS` bits that pack back to it.
    pub(crate) fn from_element(dr: &mut D, element: &Element<'dr, D>) -> Result<Self> {
        let uint = Self::alloc(dr, element.value().map(Clone::clone))?;
        uint.pack(dr)?.enforce_equal(dr, element)?;
        Ok(uint)
    }

    /// The value the bits encode.
    pub(crate) fn pack(&self, dr: &mut D) -> Result<Element<'dr, D>> {
        let Ok([packed]) = <[Element<'dr, D>; 1]>::try_from(multipack(dr, &self.bits)?) else {
            return Err(Error::InvalidWitness(
                "the bits pack into one element".into(),
            ));
        };
        Ok(packed)
    }

    pub(crate) const fn bits(&self) -> &FixedVec<Boolean<'dr, D>, ConstLen<BITS>> {
        &self.bits
    }

    /// Bounds the value to `0..=maximum` and returns `maximum - value`, which
    /// fits the same width: the two sum to `maximum`, so neither wraps.
    pub(crate) fn enforce_max(&self, dr: &mut D, maximum: u64) -> Result<Self> {
        let packed = self.pack(dr)?;
        let slack = Element::constant(dr, Fp::from(maximum)).sub(dr, &packed);
        Self::from_element(dr, &slack)
    }
}

#[cfg(test)]
mod tests;
