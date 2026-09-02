//! Anchor-bound primitives over consensus state.
//!
//! Hosts the nf-free anchor segment ([`AnchorChain`]) used by
//! [`super::stamp::StampLift`] to advance a stamp's anchor, and the
//! multi-stamp / multi-epoch exclusion proof ([`ArbitraryUnspent`]) used by
//! [`super::spendable::SpendableLift`] to advance a spendable.
//!
//! Anchor advances are single-level: every link absorbs the containing
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
use ragu_arithmetic::{Cycle as _, FixedGenerators as _};
use ragu_pasta::Pasta;

use super::{delegation::NullifierDerivation, summary::Summary};
use crate::{
    collections::indexed_multiset,
    note::{self},
    nullifier::Nullifier,
    primitives::{
        Anchor, EpochIndex, NfSeqCommit, NfSeqPoly, TachygramSetCommit, TachygramSetPoly,
    },
    relations::{
        constraint::{
            conditional_enforce_equal, enforce_equal_point, enforce_nonzero, enforce_zero,
        },
        enforce::enforce_poly_product,
    },
};

/// Anchor segment between two endpoints. Composable via [`AnchorFuse`].
///
/// Direction-agnostic: `start` and `end` are both anchors. Sole consumer:
/// [`super::stamp::StampLift`] advances a stamp's anchor. Extending a
/// spendable's anchor must instead go through [`ArbitraryUnspent`] so each
/// step proves nf-exclusion.
///
/// Structurally intra-epoch: the sole builder ([`AnchorSeed`]) invokes only
/// [`Anchor::next_stamp`], which binds an epoch. The [`Anchor::next_epoch`]
/// boundary domain is distinct and never a chain link; it is folded at a
/// crossing by [`EndEpochUnspentSeed`].
///
/// The within-epoch property pairs with a consensus-side two-epoch
/// tachygram scan that catches any tachygram already published earlier
/// in the epoch a stamp is lifted across. See the Tachygrams book chapter.
///
/// `start` at [`AnchorSeed`] has
/// PCD lineage rooted in an unbound `start: Anchor` witness, so a
/// standalone segment proves nothing about real coverage. Final binding
/// closes through a consensus-published stamp's anchor membership at
/// [`super::stamp::StampLift`]'s emitted stamp.
#[derive(Clone, Debug)]
pub struct AnchorChain;

impl Header for AnchorChain {
    /// `(start, end)`. `start` roots in an unbound witness at [`AnchorSeed`]
    /// and flows to [`super::stamp::StampLift`] which must ultimately be
    /// checked by consensus. `end` is always computed in-circuit as
    /// `start.next_stamp(epoch, ...)`.
    type Data = (Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(5);

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
/// over `[epoch_start, epoch_last]`.
///
/// Every producer maintains the provenance [`UnspentBind`]'s completeness
/// argument leans on. Each member's epoch lies in
/// `[epoch_start, epoch_last]`, because the seeds encode each member from the
/// same epoch scalar they fold into the anchor. Each epoch carries exactly
/// one member: the seeds pin their member counts by their challenge
/// identities, and [`UnspentFuse`]'s identity determines the combined
/// polynomial exactly, so the property composes by induction. The boundary
/// caches name members the sequence holds, pinned at each seed and inherited
/// through the fuse.
///
/// Member count tracks span size structurally: [`UnspentSeed`] spans one
/// epoch, [`EndEpochUnspentSeed`] two, and [`UnspentFuse`] requires
/// `right.epoch_start == left.epoch_last`, so each composition adds the same
/// to the count as to the span.
///
/// `nf_start` and `nf_last` are scalar caches of the sequence's boundary
/// members, consumed by [`UnspentFuse`]'s junction check and
/// [`super::spendable::SpendableLift`]'s seam. [`UnspentBind`] binds every
/// member, boundaries included, to the note's genuine derivation nullifiers.
#[derive(Clone, Debug)]
pub struct ArbitraryUnspent;

impl Header for ArbitraryUnspent {
    /// `(anchor_prev, (epoch_start, nf_start), elapsed,
    /// (epoch_last, nf_last), anchor_last)`.
    type Data = (
        Anchor,
        (EpochIndex, Nullifier),
        NfSeqCommit,
        (EpochIndex, Nullifier),
        Anchor,
    );

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (anchor_prev, (epoch_start, nf_start), elapsed, (epoch_last, nf_last), anchor_last) =
            *data;
        (
            vec![
                Fp::from(anchor_prev),
                Fp::from(u64::from(epoch_start.0)),
                Fp::from(nf_start),
                Fp::from(u64::from(epoch_last.0)),
                Fp::from(nf_last),
                Fp::from(anchor_last),
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
pub struct Unspent;

impl Header for Unspent {
    /// `(cm, anchor_prev, (epoch_start, nf_start), (epoch_last, nf_last),
    /// anchor_last)`. `cm` leads; the rest mirrors the [`ArbitraryUnspent`]
    /// boundaries collapsed to scalars (no `elapsed` poly).
    type Data = (
        note::Commitment,
        Anchor,
        (EpochIndex, Nullifier),
        (EpochIndex, Nullifier),
        Anchor,
    );

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, anchor_prev, (epoch_start, nf_start), (epoch_last, nf_last), anchor_last) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(anchor_prev),
                Fp::from(u64::from(epoch_start.0)),
                Fp::from(nf_start),
                Fp::from(u64::from(epoch_last.0)),
                Fp::from(nf_last),
                Fp::from(anchor_last),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Single-stamp [`AnchorChain`] seed. Witness `(start, epoch, stamp_commit)`;
/// emit `(start, start.next_stamp(epoch, &stamp_commit))`.
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
    /// `(start, epoch, stamp_commit)`.
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetCommit);

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (start, epoch, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let end = start
            .next_stamp(epoch, &stamp_commit)
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;

        Ok(((start, end), ()))
    }
}

/// Compose two adjacent [`AnchorChain`] segments — `left.end ==
/// right.start`.
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
        (left_start, left_end): <Self::Left as Header>::Data,
        (right_start, right_end): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_end) - Fp::from(right_start),
            "AnchorFuse: segments not adjacent",
        )?;
        Ok(((left_start, right_end), ()))
    }
}

/// Per-stamp exclusion seed.
///
/// Verify $\mathsf{nf} \notin \mathsf{stamp\_tg\_set}$ and use the stamp's
/// commit to produce the appropriate anchor. The `elapsed` sequence is the
/// single member $\mathsf{nf}$ at the epoch under test.
///
/// # Soundness
///
/// `nf` is free, pinned by absorbing $G_0 \cdot \mathsf{nf}$, so the identity
/// forces the witnessed one-member `elapsed` to the emitted pair.
///
/// `epoch` needs no pin of its own, being one variable entering the member
/// encoding, the emitted header and the anchor fold alike. A solved value
/// lands in an anchor off the consensus-published chain, and the member it
/// encodes still names the epoch the header announces, giving
/// [`UnspentBind`] its epoch support.
#[derive(Debug)]
pub struct UnspentSeed;

impl Step for UnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = ArbitraryUnspent;
    type Right = ();
    /// `(anchor_prev, (epoch, nf), stamp_tg_set, elapsed_seq)`.
    type Witness<'source> = (Anchor, (EpochIndex, Nullifier), TachygramSetPoly, NfSeqPoly);

    const INDEX: Index = Index::new(4);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, (epoch, nf), stamp_tg_set, elapsed_seq): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Exclusion: nf ∉ set ⇔ the set polynomial is nonzero at nf.
        let eval = stamp_tg_set.eval(Fp::from(nf));
        ctx.enforce_poly_query(stamp_tg_set.commit().into(), Fp::from(nf), eval)?;
        enforce_nonzero(eval, "UnspentSeed: found nullifier in set")?;
        let stamp_commit = stamp_tg_set.commit();
        let tested_anchor = anchor_prev
            .next_stamp(epoch, &stamp_commit)
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
        // Nonzero guard, defensive: zero is reserved.
        enforce_nonzero(Fp::from(nf), "UnspentSeed: tested nullifier is zero")?;

        // One-member elapsed: bind the witnessed sequence to the emitted
        // pair's encoding at a challenge absorbing the commitment and the
        // scalar-binding point.
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let elapsed_commit = elapsed_seq.commit();
        let z = ctx.derive_challenge(&[elapsed_commit.into(), g0 * Fp::from(nf)])?;
        let elapsed_at_z = elapsed_seq.eval(z);

        let member_at_z = indexed_multiset::direct_eval([(epoch.into(), nf.into())], z);

        enforce_zero(
            elapsed_at_z - member_at_z,
            "UnspentSeed: elapsed does not match the tested pair",
        )?;
        ctx.enforce_poly_query(elapsed_commit.into(), z, elapsed_at_z)?;

        Ok((
            (
                anchor_prev,
                (epoch, nf),
                elapsed_commit,
                (epoch, nf),
                tested_anchor,
            ),
            (),
        ))
    }
}

/// Seed spanning one epoch boundary link, from an epoch's terminal anchor to
/// the next epoch's opening boundary anchor.
///
/// The segment covers exactly the tick `anchor_prev.next_epoch(epoch_prev +
/// 1)`, so it covers two epochs and its `elapsed` is the two-member sequence
/// `[nf_prev, nf]`: the nullifier tested in the epoch being left, and the one
/// that opens the epoch being entered.
///
/// # Soundness
///
/// `nf_prev` and `nf` are unconstrained here, as at every seed;
/// [`UnspentBind`] forces every `elapsed` member against the note's genuine
/// derivation. Both are pinned against the header scalars by absorbing
/// $G_0 \cdot \mathsf{nf\_prev} + G_1 \cdot \mathsf{nf}$, so the identity
/// forces the sequence to the two crossing members.
///
/// `anchor_prev` is likewise unconstrained, and nothing here requires it to be
/// its epoch's terminal anchor. A tick folded from a short anchor is rejected
/// by adjacency at the consuming fuses and by consensus membership of the
/// eventual spend's anchor.
#[derive(Debug)]
pub struct EndEpochUnspentSeed;

impl Step for EndEpochUnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = ArbitraryUnspent;
    type Right = ();
    /// `(anchor_prev, (epoch_prev, nf_prev), nf, elapsed_seq)`.
    type Witness<'source> = (Anchor, (EpochIndex, Nullifier), Nullifier, NfSeqPoly);

    const INDEX: Index = Index::new(5);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, (epoch_prev, nf_prev), nf, elapsed_seq): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Nonzero guards, defensive: zero is reserved.
        enforce_nonzero(
            Fp::from(nf_prev),
            "EndEpochUnspentSeed: outgoing nullifier is zero",
        )?;
        enforce_nonzero(
            Fp::from(nf),
            "EndEpochUnspentSeed: incoming nullifier is zero",
        )?;

        let epoch = epoch_prev.next();
        let anchor = anchor_prev
            .next_epoch(epoch)
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;

        // Two-member elapsed: bind the witnessed sequence to the two
        // crossing members at a challenge absorbing the commitment and the
        // two-scalar binding point.
        #[expect(clippy::expect_used, reason = "constant size")]
        let (&g0, &g1) = {
            let generators = Pasta::host_generators(Pasta::baked());
            (
                generators.g().first().expect("at least one generator"),
                generators.g().get(1).expect("at least two generators"),
            )
        };
        let elapsed_commit = elapsed_seq.commit();
        let binding = g0 * Fp::from(nf_prev) + g1 * Fp::from(nf);
        let z = ctx.derive_challenge(&[elapsed_commit.into(), binding])?;
        let elapsed_at_z = elapsed_seq.eval(z);

        let epoch_prev_idx = u64::from(u32::from(epoch_prev));
        let crossing_at_z = indexed_multiset::direct_eval(
            [
                (epoch_prev_idx, nf_prev.into()),
                (epoch_prev_idx + 1, nf.into()),
            ],
            z,
        );

        enforce_zero(
            elapsed_at_z - crossing_at_z,
            "EndEpochUnspentSeed: elapsed does not match the crossing pairs",
        )?;
        ctx.enforce_poly_query(elapsed_commit.into(), z, elapsed_at_z)?;

        Ok((
            (
                anchor_prev,
                (epoch_prev, nf_prev),
                elapsed_commit,
                (epoch, nf),
                anchor,
            ),
            (),
        ))
    }
}

/// Compose two [`ArbitraryUnspent`] lineages sharing a mid-epoch junction.
///
/// The halves meet inside one epoch (`right.epoch_start == left.epoch_last`),
/// at adjacent anchors (`left.anchor_last == right.anchor_prev`), and agree on
/// the junction nullifier (`left.nf_last == right.nf_start`). The junction
/// epoch's member appears in both sequences, so the concatenation keeps it once
/// (`combined = left ++ right[1..]`).
///
/// A crossing is its own segment ([`EndEpochUnspentSeed`]), so every seam this
/// fuse sees is a shared junction.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = ArbitraryUnspent;
    /// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(6);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq): Self::Witness<'source>,
        (
            left_anchor_prev,
            (left_epoch_start, left_nf_start),
            left_elapsed,
            (left_epoch_last, left_nf_last),
            left_anchor_last,
        ): <Self::Left as Header>::Data,
        (
            right_anchor_prev,
            (right_epoch_start, right_nf_start),
            right_elapsed,
            (right_epoch_last, right_nf_last),
            right_anchor_last,
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
            Fp::from(left_anchor_last) - Fp::from(right_anchor_prev),
            "UnspentFuse: left.anchor_last must equal right.anchor_prev",
        )?;
        enforce_zero(
            Fp::from(right_epoch_start) - Fp::from(left_epoch_last),
            "UnspentFuse: forwards half must sit in left's tip epoch",
        )?;
        // Seam bind: both halves tested the junction epoch at the same nf, so the
        // merged history's view of it is unambiguous.
        enforce_zero(
            Fp::from(left_nf_last) - Fp::from(right_nf_start),
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
            indexed_multiset::direct_eval([(left_epoch_last.into(), left_nf_last.into())], z);
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
                (right_epoch_last, right_nf_last),
                right_anchor_last,
            ),
            (),
        ))
    }
}

/// Bind an [`ArbitraryUnspent`]'s free-witness nullifiers to a note's genuine
/// nullifiers, by divisibility into the derivation's sequence.
///
/// Consumes any [`NullifierDerivation`], `elapsed` covering
/// `[epoch_start, epoch_last]` inclusive, one member per epoch:
///
/// $$\mathsf{nf\_seq}(X) = \mathsf{elapsed}(X) \cdot \mathsf{complement}(X)$$
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
/// The boundary scalars need no check here. Both seeds pin their boundary
/// members into `elapsed`, [`UnspentFuse`] inherits boundaries whose members
/// survive into `combined = left · right / F_junction`, and this identity
/// makes them genuine, which [`super::spendable::SpendableLift`] relies on.
///
/// The lineage is note-blind, so the bind stamps the derivation's `cm` onto
/// the validated [`Unspent`].
#[derive(Debug)]
pub struct UnspentBind;

impl Step for UnspentBind {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = Unspent;
    type Right = NullifierDerivation;
    /// `(elapsed_seq, nf_seq, complement_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (elapsed_seq, nf_seq, complement_seq): Self::Witness<'source>,
        (
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            unspent_elapsed,
            (unspent_epoch_last, unspent_nf_last),
            unspent_anchor_last,
        ): <Self::Left as Header>::Data,
        (deriv_cm, _, nf_commit, _): <Self::Right as Header>::Data,
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
        let span = Fp::from(unspent_epoch_last) - Fp::from(unspent_epoch_start);
        conditional_enforce_equal(
            bool::from(span.is_zero()),
            Fp::from(unspent_nf_start),
            Fp::from(unspent_nf_last),
            "UnspentBind: single-epoch segment boundary nullifiers differ",
        )?;

        Ok((
            (
                deriv_cm,
                unspent_anchor_prev,
                (unspent_epoch_start, unspent_nf_start),
                (unspent_epoch_last, unspent_nf_last),
                unspent_anchor_last,
            ),
            (),
        ))
    }
}

/// Start an [`ArbitraryUnspent`] from a [`Summary`]: [`UnspentSeed`] with one
/// exclusion query over the whole run.
///
/// Committed polynomials: `summary_set`, `elapsed_seq`; two oracles.
///
/// # Soundness
///
/// `summary_set` is pinned to the header by commit-equality; epoch and anchors
/// are threaded. `nf` is free, pinned by absorbing $G_0 \cdot \mathsf{nf}$, so
/// the identity forces the one-member `elapsed` to the emitted pair.
#[derive(Debug)]
pub struct SummaryUnspentInit;

impl Step for SummaryUnspentInit {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = ArbitraryUnspent;
    type Right = ();
    /// `(nf, summary_set, elapsed_seq)`.
    type Witness<'source> = (Nullifier, TachygramSetPoly, NfSeqPoly);

    const INDEX: Index = Index::new(19);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (nf, summary_set, elapsed_seq): Self::Witness<'source>,
        (summary_epoch, summary_anchor_prev, summary_anchor_last, summary_acc_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(summary_set.commit()),
            Eq::from(summary_acc_commit),
            "SummaryUnspentInit: accumulator does not match header",
        )?;

        let tested = Fp::from(nf);
        let eval = summary_set.eval(tested);
        ctx.enforce_poly_query(summary_set.commit().into(), tested, eval)?;
        enforce_nonzero(eval, "SummaryUnspentInit: found nullifier in summary")?;
        enforce_nonzero(tested, "SummaryUnspentInit: tested nullifier is zero")?;

        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let elapsed_commit = elapsed_seq.commit();
        let z = ctx.derive_challenge(&[elapsed_commit.into(), g0 * tested])?;
        let elapsed_at_z = elapsed_seq.eval(z);

        let member_at_z = indexed_multiset::direct_eval([(summary_epoch.into(), nf.into())], z);

        enforce_zero(
            elapsed_at_z - member_at_z,
            "SummaryUnspentInit: elapsed does not match the tested pair",
        )?;
        ctx.enforce_poly_query(elapsed_commit.into(), z, elapsed_at_z)?;

        Ok((
            (
                summary_anchor_prev,
                (summary_epoch, nf),
                elapsed_commit,
                (summary_epoch, nf),
                summary_anchor_last,
            ),
            (),
        ))
    }
}
