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

/// An integer held as `BITS` little-endian Boolean wires $b_i$.
///
/// # Injectivity
///
/// Every width here is at most 254. Since $n=\sum_i2^i b_i$ lies below both
/// Pasta moduli, distinct bit strings give distinct [`pack`](Self::pack)
/// outputs in $\mathbb{F}_p$ and [fixed-base](super::fixed_base) scalars in
/// $\mathbb{F}_q$.
#[derive(Gadget)]
pub(crate) struct Uint<'dr, D: Driver<'dr>, const BITS: usize> {
    #[ragu(gadget)]
    bits: FixedVec<Boolean<'dr, D>, ConstLen<BITS>>,
}

impl<'dr, D: Driver<'dr, F = Fp>, const BITS: usize> Uint<'dr, D, BITS> {
    /// Allocates `BITS` Boolean wires assigned to the low bits of `value`, an
    /// element of either Pasta field.
    ///
    /// No constraint ties the bits to `value` or any other wire. Callers
    /// needing a specific integer constrain [`pack`](Self::pack)'s output or
    /// call [`from_element`](Self::from_element).
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

    /// The unique `BITS`-bit decomposition that packs back to `element`.
    /// Packing never wraps at these widths, so elements at or above
    /// $2^{\mathsf{BITS}}$ have no assignment.
    pub(crate) fn from_element(dr: &mut D, element: &Element<'dr, D>) -> Result<Self> {
        Ok(Self {
            bits: decompose_n(dr, &mut (), element)?,
        })
    }

    /// The element $\sum_i 2^i b_i$, a linear combination of the bit wires.
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
