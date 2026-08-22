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
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Step, Suffix,
    constraint::{conditional_enforce_equal, enforce_equal_point, enforce_nonzero, enforce_zero},
};

use super::delegation::NullifierDerivation;
use crate::{
    note::{self},
    nullifier::Nullifier,
    primitives::{
        Anchor, EpochIndex, NF_FACTOR_RESIDUE, NfSeqCommit, NfSeqPoly, TachygramSetCommit,
        TachygramSetPoly,
    },
    relations::enforce::enforce_poly_product,
};

/// Anchor segment between two endpoints. Composable via [`AnchorFuse`].
///
/// Direction-agnostic: `start` and `end` are both anchors. Sole consumer:
/// [`super::stamp::StampLift`] advances a stamp's anchor.
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
/// attributes them to a note's derivation, which is what makes the segment
/// safe to delegate: no step producing one touches a note, `cm`, or `mk`.
///
/// An `elapsed` polynomial holds one tested nullifier per covered epoch over
/// `[epoch_start, epoch_last]`, as the factor product (see [`NfSeqPoly`]):
/// each member rides an indexed cubic factor carrying its own epoch.
///
/// Three provenance invariants bind every producer of this header, and
/// [`UnspentBind`]'s completeness argument leans on all of them: **epoch
/// support** (every factor's epoch lies in `[epoch_start, epoch_last]`; the
/// seeds build each factor from the same epoch scalar they fold into the
/// anchor), **exactly one member per epoch** (the seeds pin their factor
/// counts by their challenge identities; [`UnspentFuse`]'s identity determines
/// the combined polynomial exactly, so the invariants compose by induction),
/// and **boundary caches naming held factors** (each seed pins its boundary
/// factors into `elapsed`, and the fuse inherits boundaries whose factors
/// survive into `combined`).
///
/// Member count equals span size structurally rather than by any check:
/// [`UnspentSeed`] spans one epoch, [`EndEpochUnspentSeed`] spans two, and
/// [`UnspentFuse`] requires `right.epoch_start == left.epoch_last`, so each
/// composition adds the same to the count as to the span.
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
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let end = start.next_stamp(epoch, &stamp_commit);
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
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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
/// The witnessed one-member `elapsed` is pinned to the emitted pair
/// unconditionally: its commitment and the scalar-binding point
/// $G_0 \cdot \mathsf{nf}$ (an injective in-circuit function of the free
/// nullifier) are absorbed into the challenge before it exists, so the
/// identity at the challenge forces `elapsed` to exactly the pair's factor,
/// so the post-challenge cube-root solve is unavailable.
///
/// `epoch` is free, and needs no pin of its own: it is one variable, entering
/// the factor, the emitted header and the anchor fold alike. A solved value
/// therefore lands in an anchor off the consensus-published chain, and the
/// factor it builds still names the epoch the header announces — which is the
/// epoch-support invariant [`UnspentBind`] leans on.
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
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Exclusion: nf ∉ set ⇔ the set polynomial is nonzero at nf.
        let nf_point = Fp::from(nf);
        let eval = stamp_tg_set.eval(nf_point);
        ctx.enforce_poly_query(stamp_tg_set.commit().into(), nf_point, eval)?;
        enforce_nonzero(eval, "UnspentSeed: found nullifier in set")?;
        let stamp_commit = stamp_tg_set.commit();
        let tested_anchor = anchor_prev.next_stamp(epoch, &stamp_commit);
        // Nonzero guard, defensive: zero is reserved.
        enforce_nonzero(nf_point, "UnspentSeed: tested nullifier is zero")?;

        // One-member elapsed: bind the witnessed sequence to the emitted
        // pair's factor at a challenge absorbing the commitment and the
        // scalar-binding point.
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");
        let elapsed_commit = elapsed_seq.commit();
        let z = ctx.derive_challenge(&[elapsed_commit.into(), g0 * nf_point])?;
        let elapsed_at_z = elapsed_seq.eval(z);
        let linear = Fp::from(u64::from(epoch.0) + 1) * z + nf_point;
        enforce_zero(
            elapsed_at_z - (linear.square() * linear - NF_FACTOR_RESIDUE),
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
/// that opens the epoch being entered. An epoch that published nothing is two
/// such crossings with no stamp segment between them, and there is no
/// exclusion to prove in it because no tachygram was published.
///
/// # Soundness
///
/// `nf_prev` and `nf` are unconstrained here, as at every seed;
/// [`UnspentBind`] forces every `elapsed` member against the note's genuine
/// derivation. The witnessed `elapsed` cannot disagree with the header
/// scalars: its commitment and the two-scalar binding point
/// $G_0 \cdot \mathsf{nf\_prev} + G_1 \cdot \mathsf{nf}$ are absorbed into
/// the challenge before it exists, and the identity at the challenge forces
/// the sequence to exactly the two crossing factors.
///
/// `anchor_prev` is likewise unconstrained, and nothing here requires it to be
/// its epoch's terminal anchor. Adjacency at the fuses that consume this
/// segment, and consensus membership of the eventual spend's anchor, are what
/// reject a tick folded from a short anchor.
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
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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
        let anchor = anchor_prev.next_epoch(epoch);

        // Two-member elapsed: bind the witnessed sequence to the two
        // crossing factors at a challenge absorbing the commitment and the
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
        let linear_prev = Fp::from(u64::from(epoch_prev.0) + 1) * z + Fp::from(nf_prev);
        let linear = Fp::from(u64::from(epoch.0) + 1) * z + Fp::from(nf);
        enforce_zero(
            elapsed_at_z
                - (linear_prev.square() * linear_prev - NF_FACTOR_RESIDUE)
                    * (linear.square() * linear - NF_FACTOR_RESIDUE),
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
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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
        // Junction dedup: both halves carry the junction epoch's factor, and
        // the combined lineage keeps it once, so
        // `combined · F_junction = left · right`. The junction factor is
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
        let junction_linear =
            Fp::from(u64::from(left_epoch_last.0) + 1) * z + Fp::from(left_nf_last);
        let junction_at_z = junction_linear.square() * junction_linear - NF_FACTOR_RESIDUE;
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
/// Consumes any [`NullifierDerivation`], with no bound comparison against the
/// unspent span: coverage is a *conclusion* of the read, not a precondition
/// for it, because each factor carries its own epoch. `elapsed` covers
/// `[epoch_start, epoch_last]` inclusive, one factor per epoch, and the bind
/// is the divisibility
///
/// $$\mathsf{nf\_seq}(X) = \mathsf{elapsed}(X) \cdot \mathsf{complement}(X)$$
///
/// with the complement the product of the derivation's factors outside
/// the lineage: epochs below it (including before the note existed), and
/// the epochs the derivation runs ahead of the exclusion evidence — a spend
/// publishes two nullifiers, so the wallet derives past the lineage while
/// the lineage stops at published evidence.
///
/// # Soundness
///
/// Every factor is irreducible, so divisibility is multiset containment:
/// the identity forces every `elapsed` factor — each an `(epoch, nf)` pair,
/// position included — to be a genuine derived pair. An epoch the derivation
/// does not hold has no matching factor to divide out, so an uncovering
/// derivation is rejected by this identity alone; that is why the step
/// compares no bounds. Completeness rides
/// `elapsed`'s provenance invariants (epoch support inside the span and
/// exactly one member per epoch: the seeds pin their factor counts by their
/// challenge identities, and the fuse identity determines `combined`
/// exactly), so the genuine members are distinct, in-span, and
/// `span`-many: every epoch of the span was tested with exactly its
/// genuine nullifier. [`UnspentFuse`]'s junction check is a
/// well-formedness check, not the genuineness pin: a consistent pair of
/// lies there yields a wrong merged `elapsed`, which this identity
/// rejects.
///
/// The emitted boundary scalars are not checked against `elapsed` here, and
/// need no check: both seeds pin their boundary factors into `elapsed` by
/// their own identities, and [`UnspentFuse`] inherits `left_nf_start` and
/// `right_nf_last`, whose factors are contained in
/// `combined = left · right / F_junction`. So every producer of this header
/// leaves the boundary caches naming factors `elapsed` actually holds, and
/// this identity makes those factors genuine — which is what
/// [`super::spendable::SpendableLift`] relies on when it advances a lineage
/// across the segment.
///
/// The lineage is note-blind, so the bind *stamps* the derivation's `cm` onto
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
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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
        // elapsed factor is a genuine derived pair.
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
