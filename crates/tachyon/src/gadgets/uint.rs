//! Unsigned integers held as their bits inside a circuit.

use alloc::vec::Vec;

use ragu::Result;
use ragu::drivers::{Driver, DriverValue};
use ragu::gadgets::Gadget;
use ragu::maybe::Maybe as _;
use ragu::primitives::vec::{ConstLen, FixedVec};
use ragu::primitives::{Boolean, Element, GadgetExt as _};
use ragu::udon::field::Field;

use crate::pasta::Fp;

/// A value held as `BITS` little-endian Boolean bits, so it is below
/// $2^{BITS}$.
#[derive(Gadget)]
pub(crate) struct Uint<'dr, D: Driver<'dr>, const BITS: usize> {
    #[ragu(gadget)]
    bits: FixedVec<Boolean<'dr, D>, ConstLen<BITS>>,
}

impl<'dr, D: Driver<'dr, F = Fp>, const BITS: usize> Uint<'dr, D, BITS> {
    /// Allocates the low `BITS` bits of `value`, an element of either Pasta
    /// field. The bits are free: a caller whose value may be wider binds them
    /// to it, as [`from_element`](Self::from_element) does.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver cannot allocate the Boolean bits.
    pub(crate) fn alloc<V: Field>(dr: &mut D, value: DriverValue<D, V>) -> Result<Self> {
        let bits = value.map(|element| element.to_le_bits());
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
    ///
    /// # Errors
    ///
    /// Returns an error if bit allocation or packing fails, or if the bits do
    /// not recompose to `element`.
    pub(crate) fn from_element(dr: &mut D, element: &Element<'dr, D>) -> Result<Self> {
        let uint = Self::alloc(dr, element.value().map(Clone::clone))?;
        uint.pack(dr)?.enforce_equal(dr, element)?;
        Ok(uint)
    }

    /// The value the bits encode.
    ///
    /// # Errors
    ///
    /// Returns an error if the driver cannot pack the bits.
    ///
    /// # Panics
    ///
    /// Panics if `BITS` does not pack into exactly one field element.
    pub(crate) fn pack(&self, dr: &mut D) -> Result<Element<'dr, D>> {
        let packed = ragu::primitives::multipack(dr, &self.bits)?;
        Ok(single_packed_element(packed))
    }

    pub(crate) const fn bits(&self) -> &FixedVec<Boolean<'dr, D>, ConstLen<BITS>> {
        &self.bits
    }

    /// Bounds the value to `0..=maximum` and returns `maximum - value`, which
    /// fits the same width: the two sum to `maximum`, so neither wraps.
    ///
    /// # Errors
    ///
    /// Returns an error if packing or bit allocation fails, or if the
    /// difference from `maximum` does not fit in `BITS` bits.
    pub(crate) fn enforce_max(&self, dr: &mut D, maximum: u64) -> Result<Self> {
        let packed = self.pack(dr)?;
        let slack = Element::constant(dr, Fp::from(maximum)).sub(dr, &packed);
        Self::from_element(dr, &slack)
    }
}

/// Checks the fixed-width invariant separately from fallible driver packing.
///
/// # Panics
///
/// Panics if `packed` does not contain exactly one element.
#[expect(
    clippy::expect_used,
    reason = "every Uint packing width fits one field element"
)]
fn single_packed_element<'dr, D: Driver<'dr>>(packed: Vec<Element<'dr, D>>) -> Element<'dr, D> {
    let [element] = <[_; 1]>::try_from(packed)
        .map_err(|_elements| ())
        .expect("the bits pack into one element");
    element
}

#[cfg(test)]
mod tests;
