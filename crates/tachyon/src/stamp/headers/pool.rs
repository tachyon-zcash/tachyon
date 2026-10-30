//! Semantic headers for pool steps.
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
        anchor::AnchorGadget,
        commitment::HostCommitment,
        epoch::EpochIndexGadget,
        note::NoteCommitmentGadget,
        sets::{AnchorSetCommitGadget, NfSeqCommitGadget},
    },
    note,
    primitives::{Anchor, AnchorSetCommit, EpochIndex, NfSeqCommit},
};
/// Multi-stamp / multi-epoch nf-exclusion proof over arbitrary values.
///
/// The tested values are arbitrary field elements until
/// [`UnspentBind`](crate::stamp::proof::pool::UnspentBind) attributes them to a
/// note's derivation. No step producing one touches a note, `cm`, or `mk`, so
/// the segment is safe to delegate.
///
/// A segment covers whole epochs, half-open on both axes:
/// `[anchor_start, anchor_next)` and `[epoch_start, epoch_next)`.
/// `anchor_start` is the entry anchor of `epoch_start`, and `anchor_next` is
/// the entry anchor of `epoch_next`. It starts at
/// [`QrUnspentInit`](crate::stamp::proof::qr::QrUnspentInit) over one epoch's
/// [`QrBucket`](crate::stamp::headers::qr::QrBucket),
/// [`UnspentLift`](crate::stamp::proof::pool::UnspentLift) appends the next
/// epoch's bucket, and [`UnspentFuse`](crate::stamp::proof::pool::UnspentFuse)
/// joins segments on a shared boundary. Each producer takes an anchor bound and
/// its epoch from the same bucket or the same half, and
/// [`QrBucketSeal`](crate::stamp::proof::qr::QrBucketSeal) gives every bucket
/// that form.
///
/// An `elapsed` [`NfSeqPoly`](crate::primitives::NfSeqPoly) holds one tested
/// nullifier per epoch in `[epoch_start, epoch_next)`. `epoch_next`'s nullifier
/// is the next segment's to test, or
/// [`SpendBind`](crate::stamp::proof::spend::SpendBind)'s once a spendable
/// rests on `anchor_next`.
///
/// Every producer maintains the provenance
/// [`UnspentBind`](crate::stamp::proof::pool::UnspentBind)'s completeness
/// argument leans on. Each member's epoch lies in `[epoch_start, epoch_next)`,
/// because `QrUnspentInit` and
/// [`UnspentLift`](crate::stamp::proof::pool::UnspentLift) encode their member
/// from the bucket's own epoch. Each epoch carries exactly one member:
/// `QrUnspentInit` pins its one member by its challenge identity, `UnspentLift`
/// adds exactly one at `epoch_next` by its, and
/// [`UnspentFuse`](crate::stamp::proof::pool::UnspentFuse)'s identity
/// determines the combined polynomial exactly, so the property composes by
/// induction.
#[derive(Clone, Debug)]
pub struct ArbitraryUnspent;

output_gadget!(ArbitraryUnspentOutput, "ArbitraryUnspentOutput(..)", {
    anchor_start: AnchorGadget,
    epoch_start: EpochIndexGadget,
    epoch_next: EpochIndexGadget,
    anchor_next: AnchorGadget,
    elapsed: NfSeqCommitGadget,
});

impl Header for ArbitraryUnspent {
    type Data = (Anchor, EpochIndex, NfSeqCommit, EpochIndex, Anchor);
    type Output = Kind![Fp; ArbitraryUnspentOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(ArbitraryUnspentOutput {
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?
            .into(),
            epoch_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?
            .into(),
            epoch_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.3)),
            )?
            .into(),
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.4)),
            )?
            .into(),
            elapsed: HostCommitment::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Eq::from(fields.2).to_affine()),
            )?
            .into(),
        })
    }
}

/// A note proven unspent across a span: an [`ArbitraryUnspent`] whose values
/// [`UnspentBind`](crate::stamp::proof::pool::UnspentBind) has attributed to
/// the note's genuine derivation.
#[derive(Clone, Debug)]
pub struct NoteUnspent;

output_gadget!(NoteUnspentOutput, "NoteUnspentOutput(..)", {
    cm: NoteCommitmentGadget,
    anchor_start: AnchorGadget,
    epoch_start: EpochIndexGadget,
    epoch_next: EpochIndexGadget,
    anchor_next: AnchorGadget,
});

impl Header for NoteUnspent {
    type Data = (note::Commitment, Anchor, EpochIndex, EpochIndex, Anchor);
    type Output = Kind![Fp; NoteUnspentOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteUnspentOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?
            .into(),
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?
            .into(),
            epoch_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?
            .into(),
            epoch_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.3)),
            )?
            .into(),
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.4)),
            )?
            .into(),
        })
    }
}

/// An anchor path with a commitment to the anchors inside it.
///
/// `members` commits to a polynomial with one root for each stamp folded into
/// the span. The root is the anchor that fold produces. `anchor_end` is a
/// member and `anchor_start` is not. [`crate::stamp::proof::stamp::StampLift`]
/// uses spans to advance a stamp's anchor. A spendable's anchor advances
/// through [`ArbitraryUnspent`], whose steps prove the note's nullifiers
/// absent.
///
/// A span stays within one epoch.
/// [`AnchorSpanSeed`](crate::stamp::proof::pool::AnchorSpanSeed) folds only
/// with [`Anchor::next_stamp`], which hashes under the `Tachyon-AnchorSt`
/// domain. Entering the next epoch takes [`Anchor::next_epoch`], which hashes
/// under `Tachyon-AnchorEp`. Among the proof steps, only
/// [`QrBucketSeal`](crate::stamp::proof::qr::QrBucketSeal) computes it.
/// Consensus also rejects a tachygram published twice within two epochs. That
/// check catches a tachygram already published earlier in the epoch a stamp is
/// lifted across.
///
/// [`AnchorSpanSeed`](crate::stamp::proof::pool::AnchorSpanSeed) takes
/// `anchor_start` as a free witness. A span on its own is not tied to the
/// published chain. Consensus ties it when it checks the anchor of the stamp
/// that [`crate::stamp::proof::stamp::StampLift`] outputs.
#[derive(Clone, Debug)]
pub struct AnchorSpan;

output_gadget!(AnchorSpanOutput, "AnchorSpanOutput(..)", {
    anchor_start: AnchorGadget,
    anchor_end: AnchorGadget,
    members: AnchorSetCommitGadget,
});

impl Header for AnchorSpan {
    type Data = (Anchor, AnchorSetCommit, Anchor);
    type Output = Kind![Fp; AnchorSpanOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(14);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(AnchorSpanOutput {
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?
            .into(),
            anchor_end: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?
            .into(),
            members: HostCommitment::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Eq::from(fields.1).to_affine()),
            )?
            .into(),
        })
    }
}
