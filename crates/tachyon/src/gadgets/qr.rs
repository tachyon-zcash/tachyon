//! QR profiles inside a circuit.

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe as _,
};
use ragu_primitives::{Boolean, Element, allocator::Allocator, io::Write};
use udon::field::Field as _;

use super::uint::Uint;
use crate::{pasta::Fp, primitives};

/// A [`QrProfile`](primitives::QrProfile) inside a circuit: the number of
/// sides taken and those sides as bits.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "a gadget holds driver wires, like the header gadgets it sits in"
)]
pub struct QrProfile<'dr, D: Driver<'dr>> {
    pub depth: Element<'dr, D>,
    pub bits: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr, F = Fp>> QrProfile<'dr, D> {
    /// Allocates a header's profile.
    pub(crate) fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        profile: DriverValue<D, primitives::QrProfile>,
    ) -> Result<Self> {
        Ok(Self {
            depth: Element::alloc(
                dr,
                allocator,
                profile
                    .as_ref()
                    .map(|value| Fp::from(u64::from(value.depth))),
            )?,
            bits: Element::alloc(
                dr,
                allocator,
                profile.map(|value| Fp::from(u64::from(value.bits))),
            )?,
        })
    }

    /// The depth-zero profile, as constants.
    pub(crate) fn root(dr: &mut D) -> Self {
        Self {
            depth: Element::constant(dr, Fp::from(u64::from(primitives::QrProfile::ROOT.depth))),
            bits: Element::constant(dr, Fp::from(u64::from(primitives::QrProfile::ROOT.bits))),
        }
    }

    /// The child profile on side `bit`. The parent's depth is checked below
    /// [`MAX_DEPTH`](primitives::QrProfile::MAX_DEPTH), leaving a position for
    /// the new side.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub(crate) fn descend(&self, dr: &mut D, bit: &Boolean<'dr, D>) -> Result<Self> {
        Uint::<_, { primitives::QrProfile::MAX_DEPTH.ilog2() as usize }>::from_element(
            dr,
            &self.depth,
        )?;
        let one = Element::constant(dr, Fp::ONE);
        Ok(Self {
            depth: self.depth.add(dr, &one),
            bits: self.bits.double(dr).add(dr, &bit.element()),
        })
    }
}
