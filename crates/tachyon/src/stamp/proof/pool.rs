//! Anchor-bound primitives over consensus state.
//!
//! Hosts the nf-free anchor path ([`AnchorChain`]) used by
//! [`super::stamp::StampLift`] to advance a stamp's anchor, and the
//! multi-stamp / multi-epoch exclusion proof ([`ArbitraryUnspent`]) used by
//! [`super::spendable::SpendableLift`] to advance a spendable.
//!
//! An [`ArbitraryUnspent`] covers whole epochs, `[anchor_start, anchor_next)`:
//! both bounds are entry anchors, and `anchor_next` belongs to the epoch after
//! the segment. An [`AnchorChain`] `[anchor_start, anchor_end]` certifies none
//! of its folds, and both endpoints are members.
//!
//! Anchor advances are single-level: every fold absorbs the containing
//! block's epoch and one stamp's tachygram-set commitment into the running
//! [`Anchor`] via [`Anchor::next_stamp`]. There is no per-block hash domain;
//! block alignment is a consensus convention, with validators checking that
//! anchor endpoints belong to the published per-block anchor sequence.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use super::delegation::NoteNullifiers;
use crate::{
    note::{self},
    primitives::{Anchor, EpochIndex, NfSeqCommit, NfSeqPoly, TachygramSetCommit},
    ragu_constraint::{enforce_equal_point, enforce_zero},
    relations::enforce::enforce_poly_product,
};

/// Anchor path between two positions. Composable via [`AnchorFuse`].
///
/// Sole consumer: [`super::stamp::StampLift`] advances a stamp's anchor.
/// Extending a spendable's anchor must instead go through
/// [`ArbitraryUnspent`] so each step proves nf-exclusion.
///
/// Structurally intra-epoch: the sole builder ([`AnchorSeed`]) invokes only
/// [`Anchor::next_stamp`], which binds an epoch. The [`Anchor::next_epoch`]
/// epoch-link domain is distinct and never a stamp link; it is folded at a
/// crossing by [`QrBucketSeal`](super::qr::QrBucketSeal).
///
/// The within-epoch property pairs with a consensus-side two-epoch
/// tachygram scan that catches any tachygram already published earlier
/// in the epoch a stamp is lifted across. See the Tachygrams book chapter.
///
/// `anchor_start` at [`AnchorSeed`] has PCD lineage rooted in an unbound
/// `anchor_start: Anchor` witness, so a standalone path proves nothing about
/// real chain history. Final binding closes through a consensus-published
/// stamp's anchor membership at [`super::stamp::StampLift`]'s emitted stamp.
#[derive(Clone, Debug)]
pub struct AnchorChain;

impl Header for AnchorChain {
    /// `(anchor_start, anchor_end)`. `anchor_start` roots in an unbound
    /// witness at [`AnchorSeed`] and flows to [`super::stamp::StampLift`]
    /// which must ultimately be checked by consensus. `anchor_end` is always
    /// computed in-circuit as `anchor_start.next_stamp(epoch, ...)`.
    type Data = (Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        (
            vec![Fp::from(data.0), Fp::from(data.1)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Multi-stamp / multi-epoch nf-exclusion proof over arbitrary values.
///
/// The tested values are arbitrary field elements until [`UnspentBind`]
/// attributes them to a note's derivation. No step producing one touches a
/// note, `cm`, or `mk`, so the segment is safe to delegate.
///
/// A segment covers whole epochs, half-open on both axes:
/// `[anchor_start, anchor_next)` and `[epoch_start, epoch_next)`.
/// `anchor_start` is the entry anchor of `epoch_start`, and `anchor_next` is
/// the entry anchor of `epoch_next`. Each producer takes an anchor bound and
/// its epoch from the same [`QrBucket`](super::qr::QrBucket) or the same half,
/// and [`QrBucketSeal`](super::qr::QrBucketSeal) gives every bucket that form.
///
/// An `elapsed` [`NfSeqPoly`] holds one tested nullifier per epoch in
/// `[epoch_start, epoch_next)`. `epoch_next`'s nullifier is the next segment's
/// to test, or [`SpendBind`](super::spend::SpendBind)'s once a spendable rests
/// on `anchor_next`.
///
/// Every producer maintains the provenance [`UnspentBind`]'s completeness
/// argument leans on. Each member's epoch lies in `[epoch_start, epoch_next)`,
/// because `QrUnspentInit` encodes its member from the bucket's own epoch.
/// Each epoch carries exactly one member: `QrUnspentInit` pins its one member
/// by its challenge identity, and [`UnspentFuse`]'s identity determines the
/// combined polynomial exactly, so the property composes by induction.
#[derive(Clone, Debug)]
pub struct ArbitraryUnspent;

impl Header for ArbitraryUnspent {
    /// `(anchor_start, epoch_start, elapsed, epoch_next, anchor_next)`
    type Data = (Anchor, EpochIndex, NfSeqCommit, EpochIndex, Anchor);

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (anchor_start, epoch_start, elapsed, epoch_next, anchor_next) = *data;
        (
            vec![
                Fp::from(anchor_start),
                Fp::from(epoch_start),
                Fp::from(epoch_next),
                Fp::from(anchor_next),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(elapsed)],
        )
    }
}

/// A note proven unspent across a span: an [`ArbitraryUnspent`] whose values
/// [`UnspentBind`] has attributed to the note's genuine derivation.
#[derive(Clone, Debug)]
pub struct NoteUnspent;

impl Header for NoteUnspent {
    /// `(cm, anchor_start, epoch_start, epoch_next, anchor_next)`. `cm` leads;
    /// the rest mirrors the [`ArbitraryUnspent`] without `elapsed`.
    type Data = (note::Commitment, Anchor, EpochIndex, EpochIndex, Anchor);

    const SUFFIX: Suffix = Suffix::new(4);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, anchor_start, epoch_start, epoch_next, anchor_next) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(anchor_start),
                Fp::from(epoch_start),
                Fp::from(epoch_next),
                Fp::from(anchor_next),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Single-stamp [`AnchorChain`] seed.
///
/// Used for forward extension (consumed by `StampLift`'s span builder).
///
/// # Soundness
///
/// `epoch` is unconstrained here. Consensus recomputes the anchor chain from
/// block data with the containing block's epoch, so a segment built on any
/// other value ends at an anchor that is not a chain member.
#[derive(Debug)]
pub struct AnchorSeed;

impl Step for AnchorSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorChain;
    type Right = ();
    /// `(anchor_start, epoch, stamp_commit)`
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetCommit);

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_start, epoch, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let anchor_end = anchor_start
            .next_stamp(epoch, &stamp_commit)
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;

        Ok(((anchor_start, anchor_end), ()))
    }
}

/// Concatenate two [`AnchorChain`] paths that share a vertex, with
/// `left.anchor_end == right.anchor_start`.
#[derive(Debug)]
pub struct AnchorFuse;

impl Step for AnchorFuse {
    type Aux<'source> = ();
    type Left = AnchorChain;
    type Output = AnchorChain;
    type Right = AnchorChain;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(3);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (left_anchor_start, left_anchor_end): <Self::Left as Header>::Data,
        (right_anchor_start, right_anchor_end): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_anchor_end) - Fp::from(right_anchor_start),
            "AnchorFuse: paths do not share a vertex",
        )?;
        Ok(((left_anchor_start, right_anchor_end), ()))
    }
}

/// Compose two [`ArbitraryUnspent`] lineages meeting at an entry anchor.
///
/// The halves meet at one boundary: `left.anchor_next == right.anchor_start`
/// and `left.epoch_next == right.epoch_start`. The left half holds members
/// below that epoch and the right half from it, so the combined sequence is
/// their product.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = ArbitraryUnspent;
    /// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(4);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq): Self::Witness<'source>,
        (left_anchor_start, left_epoch_start, left_elapsed, left_epoch_next, left_anchor_next): <Self::Left as Header>::Data,
        (right_anchor_start, right_epoch_start, right_elapsed, right_epoch_next, right_anchor_next): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(left_elapsed_seq.commit()),
            Eq::from(left_elapsed),
            "UnspentFuse: left polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(right_elapsed_seq.commit()),
            Eq::from(right_elapsed),
            "UnspentFuse: right polynomial does not match header",
        )?;
        enforce_zero(
            Fp::from(left_anchor_next) - Fp::from(right_anchor_start),
            "UnspentFuse: left.anchor_next must equal right.anchor_start",
        )?;
        enforce_zero(
            Fp::from(right_epoch_start) - Fp::from(left_epoch_next),
            "UnspentFuse: halves do not meet at one epoch",
        )?;
        enforce_poly_product(
            ctx,
            left_elapsed_seq.as_ref(),
            right_elapsed_seq.as_ref(),
            combined_elapsed_seq.as_ref(),
            "UnspentFuse: combined is not the concatenation of the halves",
        )?;
        Ok((
            (
                left_anchor_start,
                left_epoch_start,
                combined_elapsed_seq.commit(),
                right_epoch_next,
                right_anchor_next,
            ),
            (),
        ))
    }
}

/// Bind an [`ArbitraryUnspent`]'s free-witness nullifiers to a note's genuine
/// nullifiers, by divisibility into the derivation's sequence.
///
/// Consumes any [`NoteNullifiers`], `elapsed` covering
/// `[epoch_start, epoch_next)`, one member per epoch:
///
/// `nf_seq` factors as
///
/// $$
///   \mathsf{elapsed}(X) \cdot \mathsf{complement}(X)
/// $$
///
/// The complement holds the derivation's members outside the lineage: epochs
/// below it, and the epochs it runs ahead of the exclusion evidence, since a
/// spend publishes two nullifiers while the lineage stops at published
/// evidence.
///
/// # Soundness
///
/// `elapsed` is a subsequence of the derivation, so every one of its members
/// is a genuine derived pair and coverage is a conclusion of the identity.
///
/// Completeness rides `elapsed`'s provenance invariants, so every epoch of
/// `[epoch_start, epoch_next)` was tested with its own genuine nullifier.
///
/// The lineage is note-blind, so the bind stamps the derivation's `cm` onto
/// the validated [`NoteUnspent`].
#[derive(Debug)]
pub struct UnspentBind;

impl Step for UnspentBind {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = NoteUnspent;
    type Right = NoteNullifiers;
    /// `(elapsed_seq, nf_seq, complement_seq)`
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(5);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (elapsed_seq, nf_seq, complement_seq): Self::Witness<'source>,
        (
            unspent_anchor_start,
            unspent_epoch_start,
            unspent_elapsed,
            unspent_epoch_next,
            unspent_anchor_next,
        ): <Self::Left as Header>::Data,
        (nullifiers_cm, _, nf_commit, _): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Defensive: every producer covers at least one epoch.
        // TODO: a real circuit needs a range decomposition of the difference;
        // mock ragu accepts the native comparison.
        if unspent_epoch_next <= unspent_epoch_start {
            return Err(ragu_core::Error::InvalidWitness(
                "UnspentBind: segment covers no epoch".into(),
            ));
        }

        enforce_equal_point(
            elapsed_seq.commit().into(),
            Eq::from(unspent_elapsed),
            "UnspentBind: elapsed polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(nf_seq.commit()),
            Eq::from(nf_commit),
            "UnspentBind: covering sequence does not match header",
        )?;

        // The divisibility bind: `nf_seq = elapsed · complement`, so every
        // elapsed member is a genuine derived pair.
        enforce_poly_product(
            ctx,
            elapsed_seq.as_ref(),
            complement_seq.as_ref(),
            nf_seq.as_ref(),
            "UnspentBind: sequence does not match the derivation",
        )?;

        Ok((
            (
                nullifiers_cm,
                unspent_anchor_start,
                unspent_epoch_start,
                unspent_epoch_next,
                unspent_anchor_next,
            ),
            (),
        ))
    }
}
