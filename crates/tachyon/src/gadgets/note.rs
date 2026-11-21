//! Circuit mirror of [`Note`](crate::note::Note) derivations.

use ragu::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::Gadget,
    maybe::Maybe as _,
    primitives::{Element, GadgetExt as _, Point, allocator::Allocator, decompose_n, io::Write},
};

use crate::{
    constants::MAX_MONEY,
    digest::poseidon,
    gadgets::{fixed_base, uint::Uint, value::Positive},
    note,
    pasta::{EpAffine, Fp},
};

/// The fields of a native [`Note`](crate::note::Note) inside a circuit, in
/// note commitment order.
///
/// `value` is an [amount](Positive). `rcm`, `pk` and `psi` are elements with
/// no constraint of their own.
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
    #[ragu(gadget)]
    pub value: Positive<'dr, D>,
    /// Nullifier trapdoor.
    pub psi: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr, F = Fp>> Note<'dr, D> {
    /// Allocates the fields of a native note, range-checking its value.
    pub(crate) fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        note: DriverValue<D, note::Note>,
    ) -> Result<Self> {
        Ok(Self {
            rcm: Element::alloc(
                dr,
                allocator,
                note.as_ref().map(|&note::Note { rcm, .. }| Fp::from(rcm)),
            )?,
            pk: Element::alloc(
                dr,
                allocator,
                note.as_ref().map(|&note::Note { pk, .. }| Fp::from(pk)),
            )?,
            value: Positive::alloc(
                dr,
                allocator,
                note.as_ref().map(|&note::Note { value, .. }| value),
            )?,
            psi: Element::alloc(
                dr,
                allocator,
                note.map(|note::Note { psi, .. }| Fp::from(psi)),
            )?,
        })
    }

    /// The Fp digest representing the native maximum-fee blind, which the
    /// native derivation embeds in Fq as the scalar $r$.
    pub(crate) fn derive_feemax_blind(&self, dr: &mut D) -> Result<Element<'dr, D>> {
        poseidon::circuit::feemax_blind(dr, &self.pk, &self.psi, &self.rcm)
    }

    /// The max fee commitment $\mathsf{cv}_\mathsf{feemax} =
    /// \[-v\]\mathcal{V} + \[r\]\mathcal{R}$, for this note's value $v$ and
    /// its [feemax blind](Self::derive_feemax_blind) $r$.
    ///
    /// # Injectivity
    ///
    /// The circuit holds `slack + value` equal to `MAX_MONEY`. Both are
    /// integers below $2^{51}$, so the equation holds over the integers and
    /// `slack` is the only bit string for `MAX_MONEY - value`.
    /// [`FEE_V_BASE`](struct@fixed_base::FEE_V_BASE) multiplied by it gives
    /// $\[-v\]\mathcal{V}$.
    ///
    /// The blind digest is decomposed into 254 bits, which are its only
    /// decomposition. A digest that is zero or at least $2^{254}$ has no
    /// assignment. The scalar is the digest's integer, as in the native
    /// derivation.
    ///
    /// The result is a function of the note's four fields, and it determines
    /// them. It is a [value commitment](fixed_base#value-commitments), so it
    /// determines $v$ and $r$. Blinds below $2^{254}$ that are equal as
    /// scalars are equal as elements, and the blind digest determines `pk`,
    /// `psi` and `rcm`.
    pub(crate) fn cv_feemax(
        &self,
        dr: &mut D,
        slack: &Uint<'dr, D, 51>,
    ) -> Result<Point<'dr, D, EpAffine>> {
        let total = slack.pack(dr)?.add(dr, &self.value);
        Element::constant(dr, Fp::from(MAX_MONEY)).enforce_equal(dr, &total)?;
        let blind = self.derive_feemax_blind(dr)?;
        // The blind's 254 bits recompose to it, so they are its canonical
        // bits; a blind at or above 2^254 has no proof.
        let blind_bits = decompose_n::<_, 254>(dr, &mut (), &blind)?;
        let blind_point = fixed_base::R_BASE.mul(dr, &blind_bits)?;
        fixed_base::FEE_V_BASE.mul_and_add(dr, slack.bits(), &blind_point)
    }

    /// Enforces a zero `value` and returns the max fee commitment for it: the
    /// blind term alone, with no value term.
    ///
    /// # Injectivity
    ///
    /// The result is [`R_BASE`](struct@fixed_base::R_BASE) multiplied by the
    /// 254-bit decomposition of the blind digest, with nothing added. It is
    /// the max fee commitment $\[-v\]\mathcal{V} + \[r\]\mathcal{R}$ at
    /// $v = 0$. A digest that is zero or at least $2^{254}$ has no
    /// assignment, and there is no other case without one.
    ///
    /// The point is a [value commitment](fixed_base#value-commitments) with
    /// value zero, so it determines $r$. The blind digest determines `pk`,
    /// `psi` and `rcm`, as in [`cv_feemax`](Self::cv_feemax), so the point
    /// determines the note.
    pub(crate) fn cv_feemax_zero(&self, dr: &mut D) -> Result<Point<'dr, D, EpAffine>> {
        self.value.enforce_zero(dr)?;
        let blind = self.derive_feemax_blind(dr)?;
        // The blind's 254 bits recompose to it, so they are its canonical
        // bits; a blind at or above 2^254 has no proof.
        let blind_bits = decompose_n::<_, 254>(dr, &mut (), &blind)?;
        fixed_base::R_BASE.mul(dr, &blind_bits)
    }

    /// Derives the note commitment from the supplied fields.
    ///
    /// Does not bound `value` or check `rcm` nonzero.
    pub(crate) fn commitment(&self, dr: &mut D) -> Result<Element<'dr, D>> {
        poseidon::circuit::note_commitment(dr, &self.rcm, &self.pk, &self.value, &self.psi)
    }

    /// Derives the output's padding tachygram from the fields
    /// [`commitment`](Self::commitment) commits to.
    pub(crate) fn pad_tachygram(&self, dr: &mut D) -> Result<Element<'dr, D>> {
        poseidon::circuit::pad_tachygram(dr, &self.rcm, &self.pk, &self.value, &self.psi)
    }
}

#[cfg(test)]
mod tests;
