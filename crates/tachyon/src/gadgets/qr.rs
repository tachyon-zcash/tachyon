//! QR profiles inside a circuit.

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe as _,
};
use ragu_primitives::{Boolean, Element, GadgetExt as _, allocator::Allocator, io::Write};
use udon::field::Field as _;

use crate::{
    collections::qr::QUADRATIC_NON_RESIDUE,
    pasta::Fp,
    primitives::{self, QrClassRoot},
};

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

    /// Proves that `value`'s first `depth` QR sides are this profile's bits.
    ///
    /// At each discriminant $d_i$ of the progression from `discriminant`, the
    /// witnessed root squares to $s$ or $c \cdot s$ for $s = v + d_i$ and the
    /// fixed non-residue $c$, which fixes the side; a zero $s$ cannot claim the
    /// non-residue side. The depth mask must be a prefix of `depth` ones, and
    /// the selected sides must pack to `bits`.
    #[expect(clippy::indexing_slicing, reason = "fixed 32-position profile arrays")]
    pub(crate) fn enforce_sides_of(
        &self,
        dr: &mut D,
        value: &Element<'dr, D>,
        discriminant: &Element<'dr, D>,
        classes: DriverValue<D, [QrClassRoot; primitives::QrProfile::MAX_DEPTH]>,
        mask: DriverValue<D, [bool; primitives::QrProfile::MAX_DEPTH]>,
    ) -> Result<()> {
        let mut shifted = value.add(dr, discriminant);
        let mut depth_acc = Element::constant(dr, Fp::ZERO);
        let mut index_acc = Element::constant(dr, Fp::ZERO);
        let mut bits_acc = Element::constant(dr, Fp::ZERO);
        let one = Element::constant(dr, Fp::ONE);
        let non_residue = Element::constant(dr, QUADRATIC_NON_RESIDUE);
        let mut position_element = Element::constant(dr, Fp::ZERO);
        for position in 0..primitives::QrProfile::MAX_DEPTH {
            let side = Boolean::alloc(
                dr,
                &mut (),
                classes.as_ref().map(|values| values[position].0),
            )?;
            let root = Element::alloc(
                dr,
                &mut (),
                classes.as_ref().map(|values| values[position].1),
            )?;
            let selected =
                Boolean::alloc(dr, &mut (), mask.as_ref().map(|values| values[position]))?;
            let multiplier = side.conditional_select(dr, &non_residue, &one)?;
            let expected_square = multiplier.mul(dr, &shifted)?;
            root.square(dr)?
                .enforce_equal(dr, &expected_square)
                .map_err(|_err| {
                    ragu_core::Error::InvalidWitness(
                        "QR profile: root does not square to the claimed class".into(),
                    )
                })?;
            side.conditional_select(dr, &shifted, &one)?
                .enforce_nonzero(dr)
                .map_err(|_err| {
                    ragu_core::Error::InvalidWitness(
                        "QR profile: exceptional discriminant claimed the non-residue class".into(),
                    )
                })?;
            depth_acc = depth_acc.add(dr, &selected.element());
            let index_term = selected.element().mul(dr, &position_element)?;
            index_acc = index_acc.add(dr, &index_term);
            let extended_bits = bits_acc.add(dr, &side.element());
            let bits_term = selected.element().mul(dr, &extended_bits)?;
            bits_acc = bits_acc.add(dr, &bits_term);
            shifted = shifted.add(dr, &one);
            position_element = position_element.add(dr, &one);
        }
        depth_acc.enforce_equal(dr, &self.depth).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QR profile: depth mask does not match the bucket's depth".into(),
            )
        })?;
        let depth_minus_one = depth_acc.sub(dr, &one);
        let expected_index_sum = depth_acc.mul(dr, &depth_minus_one)?;
        index_acc
            .double(dr)
            .enforce_equal(dr, &expected_index_sum)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("QR profile: depth mask is not a prefix".into())
            })?;
        bits_acc.enforce_equal(dr, &self.bits).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QR profile: value does not take the bucket's profile".into(),
            )
        })?;
        Ok(())
    }
}
