//! Unsigned integers held as their bits inside a circuit.

use alloc::vec::Vec;

use ragu::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe as _,
    primitives::{
        Boolean, Element, decompose_n, multipack,
        vec::{ConstLen, FixedVec},
    },
    udon::field::Field,
};

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
    pub(crate) fn from_element(dr: &mut D, element: &Element<'dr, D>) -> Result<Self> {
        Ok(Self {
            bits: decompose_n(dr, &mut (), element)?,
        })
    }

    /// The value the bits encode.
    pub(crate) fn pack(&self, dr: &mut D) -> Result<Element<'dr, D>> {
        Ok(single_packed_element(multipack(dr, &self.bits)?))
    }

    pub(crate) const fn bits(&self) -> &FixedVec<Boolean<'dr, D>, ConstLen<BITS>> {
        &self.bits
    }
}

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
