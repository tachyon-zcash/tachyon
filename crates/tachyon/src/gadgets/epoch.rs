//! Epoch indices inside a circuit.

use core::ops::Deref;

use ragu_core::{
    PoseidonPermutation as _, Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe as _,
    pasta::PoseidonFp,
};
use ragu_primitives::{Element, allocator::Allocator, comparison::GadgetEquals, io::Write};

use super::uint::Uint;
use crate::{constants::EPOCH_MAX, pasta::Fp, primitives};

/// A [`primitives::EpochIndex`] inside a circuit: an index in
/// `0..=EPOCH_MAX`. `EPOCH_MAX + 1` is a power of two, so the bits of the
/// epoch width bound it exactly.
#[derive(Gadget, Write, GadgetEquals)]
#[expect(
    missing_debug_implementations,
    reason = "a gadget holds driver wires, like the header gadgets it sits in"
)]
pub struct EpochIndex<'dr, D: Driver<'dr>> {
    element: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr>> Deref for EpochIndex<'dr, D> {
    type Target = Element<'dr, D>;

    fn deref(&self) -> &Element<'dr, D> {
        &self.element
    }
}

impl<'dr, D: Driver<'dr, F = Fp>> EpochIndex<'dr, D> {
    /// Allocates `epoch` and range-checks it.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub(crate) fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        epoch: DriverValue<D, primitives::EpochIndex>,
    ) -> Result<Self> {
        let element = Element::alloc(dr, allocator, epoch.map(Fp::from))?;
        Uint::<_, { (EPOCH_MAX + 1).ilog2() as usize }>::from_element(dr, &element)?;
        Ok(Self { element })
    }

    /// The epoch `bits` encodes, with its low `log2(RATE)` bits held to zero:
    /// the first epoch of a nullifier group.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub(crate) fn from_group_start(
        dr: &mut D,
        bits: &Uint<'dr, D, { (EPOCH_MAX + 1).ilog2() as usize }>,
    ) -> Result<Self> {
        for (bit, _) in bits.bits().iter().zip(0..PoseidonFp::RATE.ilog2()) {
            bit.element().enforce_zero(dr)?;
        }
        Ok(Self {
            element: bits.pack(dr)?,
        })
    }
}
