//! Anchor-bound primitives over consensus state.
//!
//! Hosts the nf-free anchor path ([`AnchorSpan`]) used by
//! [`super::stamp::StampLift`] to advance a stamp's anchor, and the
//! multi-stamp / multi-epoch exclusion proof ([`ArbitraryUnspent`]) used by
//! [`super::spendable::SpendableLift`] to advance a spendable.
//!
//! An [`ArbitraryUnspent`] covers whole epochs, `[anchor_start, anchor_next)`:
//! both bounds are entry anchors, and `anchor_next` belongs to the epoch after
//! the segment. An [`AnchorSpan`] covers `[anchor_start, anchor_end]`, both
//! endpoints included. Its `members` commit to the anchors in
//! `(anchor_start, anchor_end]`.
//!
//! Anchor advances are single-level: every fold absorbs the containing
//! block's epoch and one stamp's tachygram-set commitment into the running
//! [`Anchor`] via [`Anchor::next_stamp`]. There is no per-block hash domain;
//! block alignment is a consensus convention, with validators checking that
//! anchor endpoints belong to the published per-block anchor sequence.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

use alloc::{vec, vec::Vec};

use ragu::{Header, Index, Step, Suffix};

use super::{
    delegation::NoteNullifiers,
    qr::{QrBucket, enforce_value_profile},
};
use crate::{
    collections::indexed_multiset,
    note::{self},
    nullifier::Nullifier,
    pasta::{Ep, Eq, Fp, Fq},
    primitives::{
        Anchor, AnchorSetCommit, AnchorSetPoly, EpochIndex, NfSeqCommit, NfSeqPoly, QrClassRoot,
        QrProfile, Tachygram, TachygramSetCommit, TachygramSetPoly,
    },
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
    relations::enforce::enforce_poly_product,
};

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
/// `nf_last` is the member at `epoch_next - 1`.
/// The step that tests a value writes it to `nf_last`, and
/// the step that next takes the segment as a prefix checks that `elapsed` ends
/// with it: [`UnspentLift`], [`UnspentFuse`] for its left half, or
/// [`UnspentBind`]. A right half's `nf_last` becomes the fused segment's.
///
/// Every producer maintains the provenance [`UnspentBind`]'s completeness
/// argument leans on. Each member's epoch lies in `[epoch_start, epoch_next)`,
/// because `QrUnspentInit` and [`UnspentLift`] encode their member from the
/// bucket's own epoch. Each epoch carries exactly one member: `QrUnspentInit`
/// pins its one member by its challenge identity, `UnspentLift` adds exactly
/// one at `epoch_next` by its, and [`UnspentFuse`]'s identity determines the
/// combined polynomial exactly, so the property composes by induction. The
/// tested value is free at its own challenge, so the first two identities hold
/// as polynomials once the last-member check above confines the value to the
/// sequence's factors.
#[derive(Clone, Debug)]
pub struct ArbitraryUnspent;

impl Header for ArbitraryUnspent {
    /// `(anchor_start, epoch_start, elapsed, nf_last, epoch_next, anchor_next)`
    type Data = (
        Anchor,
        EpochIndex,
        NfSeqCommit,
        Nullifier,
        EpochIndex,
        Anchor,
    );

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (anchor_start, epoch_start, elapsed, nf_last, epoch_next, anchor_next) = *data;
        (
            vec![
                Fp::from(anchor_start),
                Fp::from(epoch_start),
                Fp::from(nf_last),
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
    /// the rest mirrors the [`ArbitraryUnspent`] without `elapsed` or
    /// `nf_last`.
    type Data = (note::Commitment, Anchor, EpochIndex, EpochIndex, Anchor);

    const SUFFIX: Suffix = Suffix::new(3);

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

/// An anchor path with a commitment to the anchors inside it.
///
/// `members` commits to a polynomial with one root for each stamp folded into
/// the span. The root is the anchor that fold produces. `anchor_end` is a
/// member and `anchor_start` is not. [`super::stamp::StampLift`] uses spans to
/// advance a stamp's anchor. A spendable's anchor advances through
/// [`ArbitraryUnspent`], whose steps prove the note's nullifiers absent.
///
/// A span stays within one epoch. [`AnchorSpanSeed`] folds only with
/// [`Anchor::next_stamp`], which hashes under the `Tachyon-AnchorSt` domain.
/// Entering the next epoch takes [`Anchor::next_epoch`], which hashes under
/// `Tachyon-AnchorEp`. Among the proof steps, only
/// [`QrBucketSeal`](super::qr::QrBucketSeal) computes it. Consensus also
/// rejects a tachygram published twice within two epochs. That check catches a
/// tachygram already published earlier in the epoch a stamp is lifted across.
///
/// [`AnchorSpanSeed`] takes `anchor_start` as a free witness. A span on its own
/// is not tied to the published chain. Consensus ties it when it checks the
/// anchor of the stamp that [`super::stamp::StampLift`] outputs.
#[derive(Clone, Debug)]
pub struct AnchorSpan;

impl Header for AnchorSpan {
    /// `(anchor_start, members, anchor_end)`
    type Data = (Anchor, AnchorSetCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(14);

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

/// Start an [`AnchorSpan`] from one stamp.
///
/// The step folds the stamp into `anchor_start` with [`Anchor::next_stamp`].
/// The span's only member is the resulting anchor, committed with
/// [`AnchorSetCommit::singleton`].
///
/// # Soundness
///
/// `epoch` is a free witness. Consensus computes each fold with the epoch of
/// the block that contains the stamp. A span built with a different epoch
/// holds anchors that are not on the published chain.
#[derive(Debug)]
pub struct AnchorSpanSeed;

impl Step for AnchorSpanSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorSpan;
    type Right = ();
    /// `(anchor_start, epoch, stamp_commit)`
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetCommit);

    const INDEX: Index = Index::new(31);

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

/// Concatenate two [`AnchorSpan`]s with
/// `left.anchor_end == right.anchor_start`.
///
/// The shared anchor is a member of the left span and not of the right span.
/// The two member sets are therefore disjoint, and the combined members
/// polynomial is the product of the two.
///
/// # Soundness
///
/// The step checks each half's witnessed polynomial against its header's
/// `members`. The product check's challenge absorbs all three commitments.
/// `combined` therefore holds exactly the members of both halves.
#[derive(Debug)]
pub struct AnchorSpanFuse;

impl Step for AnchorSpanFuse {
    type Aux<'source> = ();
    type Left = AnchorSpan;
    type Output = AnchorSpan;
    type Right = AnchorSpan;
    /// `(left_members, combined, right_members)`
    type Witness<'source> = (AnchorSetPoly, AnchorSetPoly, AnchorSetPoly);

    const INDEX: Index = Index::new(32);

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

/// Compose two [`ArbitraryUnspent`] lineages meeting at an entry anchor.
///
/// The halves meet at one boundary: `left.anchor_next == right.anchor_start`
/// and `left.epoch_next == right.epoch_start`. The left half holds members
/// below that epoch and the right half from it, so the combined sequence is
/// their product.
/// The fused segment takes `nf_last` from the right.
///
/// # Soundness
///
/// The left half's last member becomes interior here, so the step checks that
/// `left_elapsed` ends with it,
///
/// $$
///   \mathsf{left\_elapsed}(X) = \mathsf{left\_prefix}(X) \cdot
///   F_{(\mathsf{left.epoch\_next} - 1,\, \mathsf{left.nf\_last})}(X),
/// $$
///
/// at a challenge absorbing both sequences. `left.nf_last` and
/// `left.epoch_next` are header fields, fixed before that challenge.
///
/// Four committed polynomials: the left prefix and the three sequences.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = ArbitraryUnspent;
    /// `(left_prefix_seq, left_elapsed_seq, combined_elapsed_seq,
    /// right_elapsed_seq)`
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_prefix_seq, left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq): Self::Witness<
            'source,
        >,
        (
            left_anchor_start,
            left_epoch_start,
            left_elapsed,
            left_nf_last,
            left_epoch_next,
            left_anchor_next,
        ): <Self::Left as Header>::Data,
        (
            right_anchor_start,
            right_epoch_start,
            right_elapsed,
            right_nf_last,
            right_epoch_next,
            right_anchor_next,
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
            Fp::from(left_anchor_next) - Fp::from(right_anchor_start),
            "UnspentFuse: left.anchor_next must equal right.anchor_start",
        )?;
        enforce_zero(
            Fp::from(right_epoch_start) - Fp::from(left_epoch_next),
            "UnspentFuse: halves do not meet at one epoch",
        )?;
        // The factor is not absorbed into the challenge. Its member is
        // `(left.epoch_next − 1, left.nf_last)`, both fields of the left header.
        let prefix_commit = left_prefix_seq.commit();
        let elapsed_commit = left_elapsed_seq.commit();
        let z = ctx.derive_challenge(&[prefix_commit.into(), elapsed_commit.into()])?;
        let prefix_at_z = left_prefix_seq.eval(z);
        let elapsed_at_z = left_elapsed_seq.eval(z);
        ctx.enforce_poly_query(prefix_commit.into(), z, prefix_at_z)?;
        ctx.enforce_poly_query(elapsed_commit.into(), z, elapsed_at_z)?;
        let factor = indexed_multiset::direct_eval(
            [(u64::from(left_epoch_next) - 1, left_nf_last.into())],
            z,
        );
        if elapsed_at_z != prefix_at_z * factor {
            return Err(ragu_core::Error::InvalidWitness(
                "UnspentFuse: left does not end with its last member".into(),
            ));
        }
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
                right_nf_last,
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
/// segment's bound to the bucket's `anchor_next`. The value becomes the
/// segment's `nf_last`. One step per epoch, where
/// [`QrUnspentInit`](super::qr::QrUnspentInit) then [`UnspentFuse`] takes two.
///
/// # Soundness
///
/// `elapsed_seq` is bound to the header by commit-equality and `contents` to
/// the bucket. The segment's last member becomes interior here, so the step
/// checks that `elapsed` ends with `unspent.nf_last` at `epoch_next - 1`, at
/// its own challenge. `unspent.nf_last` is a header field, fixed before that
/// challenge.
///
/// The identity $\mathsf{extended}(z) = \mathsf{elapsed}(z) \cdot F(z)$, with
/// $F$ the one indexed member `(epoch_next, value)`, is checked at a challenge
/// absorbing both sequences and `contents`. `value` is free and not absorbed,
/// so a prover can pick it after the challenge. `value` is also the output's
/// `nf_last`, and the step that next takes the output as a prefix checks that
/// `extended` has the factor `(epoch_next, nf_last)`, at a challenge over that
/// prefix and `extended`. That challenge is drawn after `value` is fixed. It
/// differs from this one because this one also absorbs `contents`: with the
/// honest prefix `elapsed`, the two would otherwise coincide, and a value
/// picked here would pass both. The later check confines `value` to
/// `extended`'s own factors at `epoch_next`, all fixed before this step's
/// challenge, so the identity here holds as polynomials: `extended` is
/// `elapsed` plus exactly that member. The member's epoch is `epoch_next`,
/// which advances by one, so `extended` keeps one member per epoch in
/// `[epoch_start, epoch_next)`. [`UnspentBind`] forces `value` against the
/// note's derivation.
///
/// Four committed polynomials: the prefix, the two sequences and the contents.
#[derive(Debug)]
pub struct UnspentLift;

impl Step for UnspentLift {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = QrBucket;
    /// `(value, classes, mask, prefix_seq, elapsed_seq, extended_seq,
    /// contents)`
    type Witness<'source> = (
        Tachygram,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
        NfSeqPoly,
        NfSeqPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(24);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (value, classes, mask, prefix_seq, elapsed_seq, extended_seq, contents): Self::Witness<
            'source,
        >,
        (
            unspent_anchor_start,
            unspent_epoch_start,
            unspent_elapsed,
            unspent_nf_last,
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
        // The factor is not absorbed into the challenge. Its member is
        // `(epoch_next − 1, nf_last)`, both fields of the left header.
        {
            let prefix_commit = prefix_seq.commit();
            let elapsed_commit = elapsed_seq.commit();
            let z = ctx.derive_challenge(&[prefix_commit.into(), elapsed_commit.into()])?;
            let prefix_at_z = prefix_seq.eval(z);
            let elapsed_at_z = elapsed_seq.eval(z);
            ctx.enforce_poly_query(prefix_commit.into(), z, prefix_at_z)?;
            ctx.enforce_poly_query(elapsed_commit.into(), z, elapsed_at_z)?;
            let factor = indexed_multiset::direct_eval(
                [(u64::from(unspent_epoch_next) - 1, unspent_nf_last.into())],
                z,
            );
            if elapsed_at_z != prefix_at_z * factor {
                return Err(ragu_core::Error::InvalidWitness(
                    "UnspentLift: elapsed does not end with its last member".into(),
                ));
            }
        }
        enforce_nonzero(Fp::from(value), "UnspentLift: tested value is zero")?;
        enforce_value_profile(value, discriminant, profile, &classes, &mask)?;

        let epoch_next = bucket_epoch.next().ok_or_else(|| {
            ragu_core::Error::InvalidWitness("UnspentLift: bucket has no next epoch".into())
        })?;

        let z = ctx.derive_challenge(&[
            elapsed_seq.commit().into(),
            extended_seq.commit().into(),
            contents_commit.into(),
        ])?;
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
                value.into(),
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
/// No later step takes the segment as a prefix, so the bind checks that
/// `elapsed` ends with `nf_last` at `epoch_next - 1`, at its own challenge.
/// `nf_last` is a header field, fixed before that challenge.
///
/// The lineage is note-blind, so the bind stamps the derivation's `cm` onto
/// the validated [`NoteUnspent`].
///
/// Four committed polynomials: the prefix, `elapsed`, `nf_seq` and the
/// complement.
#[derive(Debug)]
pub struct UnspentBind;

impl Step for UnspentBind {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = NoteUnspent;
    type Right = NoteNullifiers;
    /// `(prefix_seq, elapsed_seq, nf_seq, complement_seq)`
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(3);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (prefix_seq, elapsed_seq, nf_seq, complement_seq): Self::Witness<'source>,
        (
            unspent_anchor_start,
            unspent_epoch_start,
            unspent_elapsed,
            unspent_nf_last,
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
        // The factor is not absorbed into the challenge. Its member is
        // `(epoch_next − 1, nf_last)`, both fields of the left header.
        let prefix_commit = prefix_seq.commit();
        let elapsed_commit = elapsed_seq.commit();
        let z = ctx.derive_challenge(&[prefix_commit.into(), elapsed_commit.into()])?;
        let prefix_at_z = prefix_seq.eval(z);
        let elapsed_at_z = elapsed_seq.eval(z);
        ctx.enforce_poly_query(prefix_commit.into(), z, prefix_at_z)?;
        ctx.enforce_poly_query(elapsed_commit.into(), z, elapsed_at_z)?;
        let factor = indexed_multiset::direct_eval(
            [(u64::from(unspent_epoch_next) - 1, unspent_nf_last.into())],
            z,
        );
        if elapsed_at_z != prefix_at_z * factor {
            return Err(ragu_core::Error::InvalidWitness(
                "UnspentBind: elapsed does not end with its last member".into(),
            ));
        }

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
