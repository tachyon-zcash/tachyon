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
//! of its folds, and includes both endpoints. An [`AnchorSpan`] is an anchor
//! path that also commits to the anchors its folds produce, and
//! [`AnchorSpanCut`] turns it into the [`AnchorChain`] from its start to any of
//! them, or from any of them to its end.
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
use ragu_arithmetic::{Cycle as _, FixedGenerators as _};
use ragu_pasta::Pasta;

use super::{
    delegation::NoteNullifiers,
    qr::{QrBucket, enforce_value_profile},
};
use crate::{
    collections::indexed_multiset,
    note::{self},
    primitives::{
        Anchor, AnchorSetCommit, AnchorSetPoly, EpochIndex, NfSeqCommit, NfSeqPoly, QrClassRoot,
        QrProfile, Tachygram, TachygramSetCommit, TachygramSetPoly,
    },
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
    relations::enforce::enforce_poly_product,
};

/// Anchor path between two positions. Composable via [`AnchorFuse`].
///
/// Sole consumer: [`super::stamp::StampLift`] advances a stamp's anchor.
/// Extending a spendable's anchor must instead go through
/// [`ArbitraryUnspent`] so each step proves nf-exclusion.
///
/// Structurally intra-epoch: both builders, [`AnchorSeed`] and
/// [`AnchorSpanCut`] over spans from [`AnchorSpanSeed`], fold only with
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
/// the entry anchor of `epoch_next`. It starts at
/// [`QrUnspentInit`](super::qr::QrUnspentInit) over one epoch's [`QrBucket`],
/// [`UnspentLift`] appends the next epoch's bucket, and [`UnspentFuse`] joins
/// segments on a shared boundary. Each producer takes an anchor bound and its
/// epoch from the same bucket or the same half, and
/// [`QrBucketSeal`](super::qr::QrBucketSeal) gives every bucket that form.
///
/// An `elapsed` [`NfSeqPoly`] holds one tested nullifier per epoch in
/// `[epoch_start, epoch_next)`. `epoch_next`'s nullifier is the next segment's
/// to test, or [`SpendBind`](super::spend::SpendBind)'s once a spendable rests
/// on `anchor_next`.
///
/// Every producer maintains the provenance [`UnspentBind`]'s completeness
/// argument leans on. Each member's epoch lies in `[epoch_start, epoch_next)`,
/// because `QrUnspentInit` and [`UnspentLift`] encode their member from the
/// bucket's own epoch. Each epoch carries exactly one member: `QrUnspentInit`
/// pins its one member by its challenge identity, `UnspentLift` adds exactly
/// one at `epoch_next` by its, and [`UnspentFuse`]'s identity determines the
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

/// Anchor path that commits to the anchors its folds produce.
///
/// `members` holds the anchors the span's folds produce, one per fold: the end
/// is a member and the start is not. [`AnchorSpanCut`] is the sole
/// consumer.
///
/// Like [`AnchorChain`], a span stays within one epoch, and `anchor_start`
/// roots in an unbound witness at [`AnchorSpanSeed`].
#[derive(Clone, Debug)]
pub struct AnchorSpan;

impl Header for AnchorSpan {
    /// `(anchor_start, members, anchor_end)`
    type Data = (Anchor, AnchorSetCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(15);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (anchor_start, members, anchor_end) = *data;
        (
            vec![Fp::from(anchor_start), Fp::from(anchor_end)],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(members)],
        )
    }
}

/// Single-stamp [`AnchorSpan`] seed.
///
/// Folds one stamp as [`AnchorSeed`] does. The one member is the anchor the
/// fold produces, committed from the fixed generators by
/// [`AnchorSetCommit::singleton`].
///
/// # Soundness
///
/// `epoch` is unconstrained here, as at [`AnchorSeed`]. Consensus recomputes
/// the anchor chain with the containing block's epoch, so a span built on any
/// other value holds anchors the published chain never reaches.
#[derive(Debug)]
pub struct AnchorSpanSeed;

impl Step for AnchorSpanSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorSpan;
    type Right = ();
    /// `(anchor_start, epoch, stamp_commit)`
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetCommit);

    const INDEX: Index = Index::new(34);

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

        Ok((
            (
                anchor_start,
                AnchorSetCommit::singleton(anchor_end),
                anchor_end,
            ),
            (),
        ))
    }
}

/// Concatenate two [`AnchorSpan`]s that share a vertex, with
/// `left.anchor_end == right.anchor_start`.
///
/// The vertex is a left member and not a right one, so the halves' members are
/// disjoint and the combined set is their product.
///
/// # Soundness
///
/// Both halves are bound to their headers by commit-equality, and all three
/// operands are absorbed into the product challenge, so `combined` holds
/// exactly the union of the halves' members.
#[derive(Debug)]
pub struct AnchorSpanFuse;

impl Step for AnchorSpanFuse {
    type Aux<'source> = ();
    type Left = AnchorSpan;
    type Output = AnchorSpan;
    type Right = AnchorSpan;
    /// `(left_members, combined, right_members)`
    type Witness<'source> = (AnchorSetPoly, AnchorSetPoly, AnchorSetPoly);

    const INDEX: Index = Index::new(35);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_members, combined, right_members): Self::Witness<'source>,
        (left_anchor_start, left_members_commit, left_anchor_end): <Self::Left as Header>::Data,
        (right_anchor_start, right_members_commit, right_anchor_end): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_anchor_end) - Fp::from(right_anchor_start),
            "AnchorSpanFuse: spans do not share a vertex",
        )?;
        enforce_equal_point(
            Eq::from(left_members.commit()),
            Eq::from(left_members_commit),
            "AnchorSpanFuse: left members do not match header",
        )?;
        enforce_equal_point(
            Eq::from(right_members.commit()),
            Eq::from(right_members_commit),
            "AnchorSpanFuse: right members do not match header",
        )?;
        enforce_poly_product(
            ctx,
            left_members.as_ref(),
            right_members.as_ref(),
            combined.as_ref(),
            "AnchorSpanFuse: combined is not the union of the halves",
        )?;

        Ok(((left_anchor_start, combined.commit(), right_anchor_end), ()))
    }
}

/// Cut an [`AnchorSpan`] to the [`AnchorChain`] `(from, to)`, from its start
/// to a member or from a member to its end.
///
/// - `from` is the start or a member: $M(\mathsf{from}) \cdot (\mathsf{from}
///   - \mathsf{anchor\_start}) = 0$.
/// - `to` is a member: $M(\mathsf{to}) = 0$.
/// - The cut keeps one of the span's endpoints: $(\mathsf{from} -
///   \mathsf{anchor\_start}) \cdot (\mathsf{to} - \mathsf{anchor\_end}) = 0$. A
///   root set carries no order between members, so a cut between two members
///   would have no direction.
///
/// Every cut advances: each member follows the start, and the end follows
/// each member. The one degenerate cut is `(anchor_end, anchor_end)`, a chain
/// that moves a stamp nowhere.
///
/// # Soundness
///
/// $M$ is bound to the header by commit-equality, so its openings at the
/// witnessed `from` and `to` need no challenge. A member outside the span
/// needs an anchor collision.
///
/// One committed polynomial, opened twice.
#[derive(Debug)]
pub struct AnchorSpanCut;

impl Step for AnchorSpanCut {
    type Aux<'source> = ();
    type Left = AnchorSpan;
    type Output = AnchorChain;
    type Right = ();
    /// `(from, to, members)`
    type Witness<'source> = (Anchor, Anchor, AnchorSetPoly);

    const INDEX: Index = Index::new(36);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (from, to, members): Self::Witness<'source>,
        (span_anchor_start, span_members, span_anchor_end): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(members.commit()),
            Eq::from(span_members),
            "AnchorSpanCut: members do not match header",
        )?;

        let from_eval = members.eval(Fp::from(from));
        let to_eval = members.eval(Fp::from(to));
        enforce_zero(
            from_eval * (Fp::from(from) - Fp::from(span_anchor_start)),
            "AnchorSpanCut: from is neither the start nor a member",
        )?;
        enforce_zero(to_eval, "AnchorSpanCut: to is not a member")?;
        enforce_zero(
            (Fp::from(from) - Fp::from(span_anchor_start))
                * (Fp::from(to) - Fp::from(span_anchor_end)),
            "AnchorSpanCut: the cut keeps neither endpoint",
        )?;
        ctx.enforce_poly_query(Eq::from(span_members), Fp::from(from), from_eval)?;
        ctx.enforce_poly_query(Eq::from(span_members), Fp::from(to), to_eval)?;

        Ok(((from, to), ()))
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

/// Append one epoch to an [`ArbitraryUnspent`] from that epoch's
/// [`QrBucket`].
///
/// The bucket starts on the segment's excluded bound: `anchor_next` and
/// `epoch_next` are the bucket's `anchor_start` and `epoch`. The step tests one
/// value against the bucket as [`QrUnspentInit`](super::qr::QrUnspentInit)
/// does, appends it to `elapsed` as the member at `epoch_next`, and moves the
/// segment's bound to the bucket's `anchor_next`. One step per epoch, where
/// [`QrUnspentInit`](super::qr::QrUnspentInit) then [`UnspentFuse`] takes two.
///
/// # Soundness
///
/// `elapsed_seq` is bound to the header by commit-equality and `contents` to
/// the bucket. The challenge absorbs both sequences and `[value]·G_0`, so the
/// identity $\mathsf{extended}(z) = \mathsf{elapsed}(z) \cdot F(z)$, with $F$
/// the one indexed member `(epoch_next, value)`, fixes `extended` to `elapsed`
/// plus exactly that member. The member's epoch is `epoch_next`, which
/// advances by one, so `extended` keeps one member per epoch in
/// `[epoch_start, epoch_next)`. `value` is free until
/// [`UnspentBind`] forces it against the note's derivation.
///
/// Three committed polynomials, each opened once.
#[derive(Debug)]
pub struct UnspentLift;

impl Step for UnspentLift {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = QrBucket;
    /// `(value, classes, mask, elapsed_seq, extended_seq, contents)`
    type Witness<'source> = (
        Tachygram,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
        NfSeqPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(26);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (value, classes, mask, elapsed_seq, extended_seq, contents): Self::Witness<'source>,
        (
            unspent_anchor_start,
            unspent_epoch_start,
            unspent_elapsed,
            unspent_epoch_next,
            unspent_anchor_next,
        ): <Self::Left as Header>::Data,
        (
            bucket_epoch,
            bucket_anchor_start,
            bucket_anchor_next,
            discriminant,
            profile,
            contents_commit,
        ): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(unspent_anchor_next) - Fp::from(bucket_anchor_start),
            "UnspentLift: the bucket does not start where the segment ends",
        )?;
        enforce_zero(
            Fp::from(unspent_epoch_next) - Fp::from(bucket_epoch),
            "UnspentLift: the bucket is not the segment's next epoch",
        )?;
        enforce_equal_point(
            Eq::from(contents.commit()),
            Eq::from(contents_commit),
            "UnspentLift: contents do not match the bucket",
        )?;
        enforce_equal_point(
            Eq::from(elapsed_seq.commit()),
            Eq::from(unspent_elapsed),
            "UnspentLift: elapsed does not match header",
        )?;
        enforce_nonzero(Fp::from(value), "UnspentLift: tested value is zero")?;
        enforce_value_profile(value, discriminant, profile, &classes, &mask)?;

        let epoch_next = bucket_epoch.next().ok_or_else(|| {
            ragu_core::Error::InvalidWitness("UnspentLift: bucket has no next epoch".into())
        })?;

        let z =
            ctx.derive_challenge(
                &[elapsed_seq.commit().into(), extended_seq.commit().into(), {
                    // The mock absorbs only points, so absorb `[value]·G_0`.
                    #[expect(clippy::expect_used, reason = "constant size")]
                    let &g0 = Pasta::host_generators(Pasta::baked())
                        .g()
                        .first()
                        .expect("at least one generator");
                    g0 * Fp::from(value)
                }],
            )?;
        let elapsed_at_z = elapsed_seq.eval(z);
        let extended_at_z = extended_seq.eval(z);
        ctx.enforce_poly_query(elapsed_seq.commit().into(), z, elapsed_at_z)?;
        ctx.enforce_poly_query(extended_seq.commit().into(), z, extended_at_z)?;
        enforce_zero(
            extended_at_z
                - (elapsed_at_z
                    * indexed_multiset::direct_eval([(u64::from(bucket_epoch), value.into())], z)),
            "UnspentLift: extended is not elapsed with the tested pair",
        )?;

        let contents_at_value = contents.eval(value.into());
        ctx.enforce_poly_query(contents_commit.into(), value.into(), contents_at_value)?;
        enforce_nonzero(
            contents_at_value,
            "UnspentLift: found nullifier in the bucket",
        )?;

        Ok((
            (
                unspent_anchor_start,
                unspent_epoch_start,
                extended_seq.commit(),
                epoch_next,
                bucket_anchor_next,
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
        // Defensive. `QrUnspentInit` emits `epoch_next = epoch_start + 1`, and
        // every other producer only raises `epoch_next`, so every
        // `ArbitraryUnspent` covers at least one epoch.
        // TODO: a real circuit needs a range decomposition of
        // `epoch_next - epoch_start`; mock ragu accepts the native comparison.
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
