//! Anchor-bound primitives over consensus state.
//!
//! Hosts the nf-free anchor path ([`AnchorChain`]) used by
//! [`super::stamp::StampLift`] to advance a stamp's anchor, and the
//! multi-stamp / multi-epoch exclusion proof ([`ArbitraryUnspent`]) used by
//! [`super::spendable::SpendableLift`] to advance a spendable.
//!
//! A coverage segment `(anchor_prev, anchor_end]` certifies the folds after
//! `anchor_prev` through `anchor_end`. An [`AnchorChain`]
//! `[anchor_start, anchor_end]` certifies none of its folds, and both
//! endpoints are members.
//!
//! Anchor advances are single-level: every fold absorbs the containing
//! block's epoch and one stamp's tachygram-set commitment into the running
//! [`Anchor`] via [`Anchor::next_stamp`]. There is no per-block hash domain;
//! block alignment is a consensus convention, with validators checking that
//! anchor endpoints belong to the published per-block anchor sequence.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use super::delegation::NoteNullifiers;
use crate::{
    collections::indexed_multiset,
    note::{self},
    nullifier::Nullifier,
    primitives::{Anchor, EpochIndex, NfSeqCommit, NfSeqPoly, TachygramSetCommit},
    ragu_constraint::{conditional_enforce_equal, enforce_equal_point, enforce_zero},
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
/// An `elapsed` [`NfSeqPoly`] holds one tested nullifier per covered epoch
/// over `[epoch_start, epoch_end]`.
///
/// Every segment runs from one entry anchor to another: its only producer is
/// [`QrUnspentInit`](super::qr::QrUnspentInit), over one epoch's
/// [`QrBucket`](super::qr::QrBucket), and [`UnspentFuse`] joins segments end
/// to end.
///
/// Every producer maintains the provenance [`UnspentBind`]'s completeness
/// argument leans on. Each member's epoch lies in
/// `[epoch_start, epoch_end]`, because `QrUnspentInit` encodes each member
/// from the bucket's own epoch. Each epoch carries exactly one member:
/// `QrUnspentInit` pins its member count by its challenge identity, and
/// [`UnspentFuse`]'s identity determines the combined polynomial exactly, so
/// the property composes by induction.
///
/// `nf_start` and `nf_end` are scalar caches of the sequence's boundary
/// members, consumed by [`UnspentFuse`]'s junction check. `QrUnspentInit`
/// absorbs the scalars it emits into the challenge that pins its sequence, so
/// each cache is the member the sequence holds. [`UnspentBind`] binds every
/// member, boundaries included, to the note's genuine derivation nullifiers.
#[derive(Clone, Debug)]
pub struct ArbitraryUnspent;

impl Header for ArbitraryUnspent {
    /// `(anchor_prev, (epoch_start, nf_start), elapsed,
    /// (epoch_end, nf_end), anchor_end)`
    type Data = (
        Anchor,
        (EpochIndex, Nullifier),
        NfSeqCommit,
        (EpochIndex, Nullifier),
        Anchor,
    );

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (anchor_prev, (epoch_start, nf_start), elapsed, (epoch_end, nf_end), anchor_end) =
            *data;
        (
            vec![
                Fp::from(anchor_prev),
                Fp::from(epoch_start),
                Fp::from(nf_start),
                Fp::from(epoch_end),
                Fp::from(nf_end),
                Fp::from(anchor_end),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(elapsed)],
        )
    }
}

/// A note proven unspent across a span: an [`ArbitraryUnspent`] whose values
/// [`UnspentBind`] has attributed to the note's genuine derivation, collapsed
/// to boundary scalars.
#[derive(Clone, Debug)]
pub struct NoteUnspent;

impl Header for NoteUnspent {
    /// `(cm, anchor_prev, (epoch_start, nf_start), (epoch_end, nf_end),
    /// anchor_end)`. `cm` leads; the rest mirrors the [`ArbitraryUnspent`]
    /// boundaries collapsed to scalars (no `elapsed` poly).
    type Data = (
        note::Commitment,
        Anchor,
        (EpochIndex, Nullifier),
        (EpochIndex, Nullifier),
        Anchor,
    );

    const SUFFIX: Suffix = Suffix::new(4);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, anchor_prev, (epoch_start, nf_start), (epoch_end, nf_end), anchor_end) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(anchor_prev),
                Fp::from(epoch_start),
                Fp::from(nf_start),
                Fp::from(epoch_end),
                Fp::from(nf_end),
                Fp::from(anchor_end),
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

/// Compose two [`ArbitraryUnspent`] lineages sharing a junction epoch.
///
/// The halves meet at an entry anchor (`left.anchor_end ==
/// right.anchor_prev`), label it with one epoch (`right.epoch_start ==
/// left.epoch_end`), and agree on the junction nullifier (`left.nf_end ==
/// right.nf_start`). The junction epoch's member appears in both sequences,
/// so the concatenation keeps it once (`combined = left ++ right[1..]`).
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
        (
            left_anchor_prev,
            (left_epoch_start, left_nf_start),
            left_elapsed,
            (left_epoch_end, left_nf_end),
            left_anchor_end,
        ): <Self::Left as Header>::Data,
        (
            right_anchor_prev,
            (right_epoch_start, right_nf_start),
            right_elapsed,
            (right_epoch_end, right_nf_end),
            right_anchor_end,
        ): <Self::Right as Header>::Data,
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
            Fp::from(left_anchor_end) - Fp::from(right_anchor_prev),
            "UnspentFuse: left.anchor_end must equal right.anchor_prev",
        )?;
        enforce_zero(
            Fp::from(right_epoch_start) - Fp::from(left_epoch_end),
            "UnspentFuse: forwards half must sit in left's last epoch",
        )?;
        // Seam bind: both halves tested the junction epoch at the same nf, so the
        // merged history's view of it is unambiguous.
        enforce_zero(
            Fp::from(left_nf_end) - Fp::from(right_nf_start),
            "UnspentFuse: halves disagree on the junction nullifier",
        )?;
        let combined_commit = combined_elapsed_seq.commit();
        // Junction dedup: both halves carry the junction epoch's member, and
        // the combined lineage keeps it once, so
        // `combined · F_junction = left · right`. The junction member is
        // native from left-header scalars, fixed by the recursive
        // verification of the left PCD before the challenge. At a one-member
        // right the identity degenerates to `combined = left`: the merge adds
        // stamps, not members.
        let z = ctx.derive_challenge(&[
            combined_commit.into(),
            left_elapsed_seq.commit().into(),
            right_elapsed_seq.commit().into(),
        ])?;
        let combined_at_z = combined_elapsed_seq.eval(z);
        let left_at_z = left_elapsed_seq.eval(z);
        let right_at_z = right_elapsed_seq.eval(z);

        let junction_at_z =
            indexed_multiset::direct_eval([(left_epoch_end.into(), left_nf_end.into())], z);
        enforce_zero(
            combined_at_z * junction_at_z - left_at_z * right_at_z,
            "UnspentFuse: combined is not the concatenation of the halves",
        )?;
        ctx.enforce_poly_query(combined_commit.into(), z, combined_at_z)?;
        ctx.enforce_poly_query(left_elapsed_seq.commit().into(), z, left_at_z)?;
        ctx.enforce_poly_query(right_elapsed_seq.commit().into(), z, right_at_z)?;
        Ok((
            (
                left_anchor_prev,
                (left_epoch_start, left_nf_start),
                combined_commit,
                (right_epoch_end, right_nf_end),
                right_anchor_end,
            ),
            (),
        ))
    }
}

/// Bind an [`ArbitraryUnspent`]'s free-witness nullifiers to a note's genuine
/// nullifiers, by divisibility into the derivation's sequence.
///
/// Consumes any [`NoteNullifiers`], `elapsed` covering
/// `[epoch_start, epoch_end]` inclusive, one member per epoch:
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
/// the span was tested with its own genuine nullifier, and [`UnspentFuse`]'s
/// junction check is well-formedness only.
///
/// The boundary scalars need no check here.
/// [`QrUnspentInit`](super::qr::QrUnspentInit) pins its boundary members into
/// `elapsed` at a challenge absorbing them, [`UnspentFuse`]
/// inherits boundaries whose members survive into `combined = left · right /
/// F_junction`, and this identity makes them genuine.
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
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            unspent_elapsed,
            (unspent_epoch_end, unspent_nf_end),
            unspent_anchor_end,
        ): <Self::Left as Header>::Data,
        (nullifiers_cm, _, nf_commit, _): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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

        // Defensive: a single-epoch segment's boundary caches coincide.
        let span = Fp::from(unspent_epoch_end) - Fp::from(unspent_epoch_start);
        conditional_enforce_equal(
            bool::from(span.is_zero()),
            Fp::from(unspent_nf_start),
            Fp::from(unspent_nf_end),
            "UnspentBind: single-epoch segment boundary nullifiers differ",
        )?;

        Ok((
            (
                nullifiers_cm,
                unspent_anchor_prev,
                (unspent_epoch_start, unspent_nf_start),
                (unspent_epoch_end, unspent_nf_end),
                unspent_anchor_end,
            ),
            (),
        ))
    }
}
