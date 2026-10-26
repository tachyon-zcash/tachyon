//! Semantic headers for delegation steps.
use ragu::{
    Header, Suffix,
    pasta::{Eq, Fp},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe as _,
};
use ragu_primitives::{Element, allocator::Allocator};
use udon::curve::Projective as _;

use crate::{
    gadgets::{
        commitment::HostCommitment,
        epoch::EpochIndexGadget,
        keys::NoteMasterKeyGadget,
        note::{NoteCommitmentGadget, NoteGadget},
        sets::NfSeqCommitGadget,
    },
    keys, note,
    primitives::{EpochIndex, NfSeqCommit},
};
/// A note's certified record: its commitment, its opening, and its master key
/// (wallet-only).
///
/// `mk` is derived natively from the note's secrets and certified here, so
/// every consuming [`NullifierDerive`] threads a genuine master key without
/// re-witnessing the note. `note` is the opening `cm` commits to.
/// [`SpendBind`](crate::stamp::proof::spend::SpendBind) reads it.
#[derive(Clone, Debug)]
pub struct NoteSecret;

output_gadget!(NoteSecretOutput, "NoteSecretOutput(..)", {
    cm: NoteCommitmentGadget,
    note: NoteGadget,
    mk: NoteMasterKeyGadget,
});

impl Header for NoteSecret {
    type Data = (note::Commitment, note::Note, keys::NoteMasterKey);
    type Output = Kind![Fp; NoteSecretOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        data: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteSecretOutput {
            cm: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.0)),
            )?
            .into(),
            note: NoteGadget {
                rcm: Element::alloc(
                    dr,
                    allocator,
                    data.as_ref().map(|fields| Fp::from(fields.1.rcm)),
                )?
                .into(),
                pk: Element::alloc(
                    dr,
                    allocator,
                    data.as_ref().map(|fields| Fp::from(fields.1.pk)),
                )?
                .into(),
                value: Element::alloc(
                    dr,
                    allocator,
                    data.as_ref()
                        .map(|fields| Fp::from(u64::from(fields.1.value))),
                )?
                .into(),
                psi: Element::alloc(
                    dr,
                    allocator,
                    data.as_ref().map(|fields| Fp::from(fields.1.psi)),
                )?
                .into(),
            },
            mk: Element::alloc(dr, allocator, data.as_ref().map(|fields| fields.2.0))?.into(),
        })
    }
}

/// A proven contiguous range of derived nullifiers (wallet-only).
///
/// `(cm, epoch_start, nf_commit, epoch_end)`: covers epochs
/// `[epoch_start, epoch_end]`; `nf_commit` commits the range's nullifier
/// sequence as an [`NfSeqPoly`], exactly one member per covered epoch. That
/// invariant is established at [`NullifierDerive`], preserved by
/// [`NullifierFuse`]'s contiguity check, and what the divisibility binds
/// lean on for per-epoch completeness. `cm` binds the range to the real
/// note.
///
/// No consumer reads the range. It serves [`NullifierFuse`]'s contiguity
/// check, which keeps the product squarefree, and squarefreeness forces a
/// tested sequence's members distinct at
/// [`UnspentBind`](crate::stamp::proof::pool::UnspentBind).
///
/// Masking is the consuming step's responsibility.
#[derive(Clone, Debug)]
pub struct NoteNullifiers;

output_gadget!(NoteNullifiersOutput, "NoteNullifiersOutput(..)", {
    cm: NoteCommitmentGadget,
    epoch_start: EpochIndexGadget,
    epoch_end: EpochIndexGadget,
    nf_commit: NfSeqCommitGadget,
});

impl Header for NoteNullifiers {
    type Data = (note::Commitment, EpochIndex, NfSeqCommit, EpochIndex);
    type Output = Kind![Fp; NoteNullifiersOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        data: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteNullifiersOutput {
            cm: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.0)),
            )?
            .into(),
            epoch_start: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.1)),
            )?
            .into(),
            epoch_end: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.3)),
            )?
            .into(),
            nf_commit: HostCommitment::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Eq::from(fields.2).to_affine()),
            )?
            .into(),
        })
    }
}
