//! Circuit mirror of [`Note`](crate::note::Note) derivations.

use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe as _,
};
use ragu_primitives::{Element, Point, allocator::Allocator, io::Write};

use crate::{
    constants::MAX_MONEY,
    digest::poseidon,
    gadgets::fixed_base,
    note,
    pasta::{EpAffine, Fp},
};

/// The fields of a native [`Note`](crate::note::Note) inside a circuit, in
/// note commitment order.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "a gadget holds driver wires, like the header gadgets it sits in"
)]
pub struct Note<'dr, D: Driver<'dr>> {
    /// Commitment trapdoor.
    pub rcm: Element<'dr, D>,
    /// Recipient payment key.
    pub pk: Element<'dr, D>,
    /// Note amount.
    pub value: Element<'dr, D>,
    /// Nullifier trapdoor.
    pub psi: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr, F = Fp>> Note<'dr, D> {
    /// Allocates the fields of a native note.
    pub(crate) fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        note: DriverValue<D, note::Note>,
    ) -> Result<Self> {
        Ok(Self {
            rcm: Element::alloc(
                dr,
                allocator,
                note.as_ref().map(|fields| Fp::from(fields.rcm)),
            )?,
            pk: Element::alloc(
                dr,
                allocator,
                note.as_ref().map(|fields| Fp::from(fields.pk)),
            )?,
            value: Element::alloc(
                dr,
                allocator,
                note.as_ref()
                    .map(|fields| Fp::from(u64::from(fields.value))),
            )?,
            psi: Element::alloc(dr, allocator, note.map(|fields| Fp::from(fields.psi)))?,
        })
    }

    /// The canonical Fp digest representing the native maximum-fee blind.
    ///
    /// Fixed-base digest multiplication embeds this scalar into Fq canonically,
    /// as the native derivation does.
    pub(crate) fn derive_feemax_blind(&self, dr: &mut D) -> Result<Element<'dr, D>> {
        poseidon::circuit::feemax_blind(dr, &self.pk, &self.psi, &self.rcm)
    }

    /// The max fee commitment, `cv_feemax`.
    ///
    /// The 51-bit decomposition of `MAX_MONEY - value` bounds `value` by
    /// `MAX_MONEY`.
    pub(crate) fn cv_feemax(&self, dr: &mut D) -> Result<Point<'dr, D, EpAffine>> {
        let blind = self.derive_feemax_blind(dr)?;
        let blind_point = fixed_base::R_BASE.mul_digest(dr, &blind, None)?;
        let bound = Element::constant(dr, Fp::from(MAX_MONEY));
        let slack = bound.sub(dr, &self.value);
        fixed_base::FEE_V_BASE.mul_amount(dr, &slack, &blind_point)
    }

    /// The max fee commitment of a zero-value note: the blind term alone,
    /// with no value term.
    ///
    /// Valid only when `value` is proven zero; nothing here constrains it.
    pub(crate) fn cv_feemax_zero(&self, dr: &mut D) -> Result<Point<'dr, D, EpAffine>> {
        let blind = self.derive_feemax_blind(dr)?;
        fixed_base::R_BASE.mul_digest(dr, &blind, None)
    }

    /// Derives the note commitment from the supplied fields.
    ///
    /// Neither bounds `value` nor checks `rcm` nonzero; callers do.
    pub(crate) fn commitment(&self, dr: &mut D) -> Result<Element<'dr, D>> {
        poseidon::circuit::note_commitment(dr, &self.rcm, &self.pk, &self.value, &self.psi)
    }

    /// Derives the output's padding tachygram from the fields
    /// [`commitment`](Self::commitment) commits to.
    pub(crate) fn pad_tachygram(&self, dr: &mut D) -> Result<Element<'dr, D>> {
        poseidon::circuit::pad_tachygram(dr, &self.rcm, &self.pk, &self.value, &self.psi)
    }
}
