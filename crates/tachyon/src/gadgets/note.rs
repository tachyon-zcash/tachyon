//! Circuit gadgets for note values.

scalar_gadget!(NoteCommitmentGadget, "NoteCommitmentGadget(..)");
scalar_gadget!(CommitmentTrapdoorGadget, "CommitmentTrapdoorGadget(..)");

use super::{keys::PaymentKeyGadget, nullifier::NullifierTrapdoorGadget, value::ValueGadget};

/// A note opening represented by its semantic fields.
#[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write, derive_more::Debug)]
#[debug("NoteGadget(..)")]
pub struct NoteGadget<'dr, D: ragu_core::drivers::Driver<'dr>> {
    pub(crate) rcm: CommitmentTrapdoorGadget<'dr, D>,
    pub(crate) pk: PaymentKeyGadget<'dr, D>,
    pub(crate) value: ValueGadget<'dr, D>,
    pub(crate) psi: NullifierTrapdoorGadget<'dr, D>,
}
