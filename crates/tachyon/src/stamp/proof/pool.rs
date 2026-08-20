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
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

use super::delegation::NullifierHeader;
use crate::{
    note,
    nullifier::Nullifier,
    primitives::{
        Anchor, EpochIndex, NfSeqCommit, NfSeqPoly, TachygramSetCommit, TachygramSetPoly,
    },
    relations::enforce::enforce_shifted_combination,
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
/// attributes them to a note's derivation, which is what makes the segment
/// safe to delegate: no step producing one touches a note, `cm`, or `mk`.
///
/// An `elapsed` polynomial holds one nullifier per crossed epoch boundary over
/// `[epoch_start, epoch_end)`, sentinel-terminated (see
/// [`NfSeqPoly`]): the crossings sit at ascending degree with a coefficient
/// `1` at the crossing count, so the commitment is never the identity point
/// (the empty sequence is the constant `1`, committing to `g0`) and the
/// sequence's exact rank is pinned. The seeds establish the sentinel form and
/// the fuses preserve it.
///
/// `nf_start` is the range's first tested nullifier (the leaf at
/// `epoch_start`); the in-progress `nf_end` corresponds to `epoch_end` and is
/// represented in `elapsed` only once a segment covering its epoch's closing
/// boundary joins on, since [`EndEpochUnspentSeed`] is where a member is added.
/// [`UnspentBind`] binds both endpoints to the note's genuine derivation
/// nullifiers.
///
/// `epoch_start` is the epoch of the exclusive `anchor_prev`; `epoch_end` the
/// epoch of `anchor_last`, not yet represented in `elapsed`, so
/// [`UnspentBind`]'s derived range runs one epoch past it.
#[derive(Clone, Debug)]
pub struct ArbitraryUnspent;

impl Header for ArbitraryUnspent {
    /// `(anchor_prev, (epoch_start, nf_start), elapsed,
    /// (epoch_end, nf_end), anchor_last)`.
    type Data = (
        Anchor,
        (EpochIndex, Nullifier),
        NfSeqCommit,
        (EpochIndex, Nullifier),
        Anchor,
    );

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (anchor_prev, (epoch_start, nf_start), elapsed, (epoch_end, nf_end), anchor_last) =
            *data;
        (
            vec![
                Fp::from(anchor_prev),
                Fp::from(u64::from(epoch_start.0)),
                Fp::from(nf_start),
                Fp::from(u64::from(epoch_end.0)),
                Fp::from(nf_end),
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
    /// `(cm, anchor_prev, (epoch_start, nf_start), (epoch_end, nf_end),
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
        let (cm, anchor_prev, (epoch_start, nf_start), (epoch_end, nf_end), anchor_last) = *data;
        (
            vec![
                Fp::from(cm),
                Fp::from(anchor_prev),
                Fp::from(u64::from(epoch_start.0)),
                Fp::from(nf_start),
                Fp::from(u64::from(epoch_end.0)),
                Fp::from(nf_end),
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

    const INDEX: Index = Index::new(4);

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

    const INDEX: Index = Index::new(5);

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
/// Verify `nf ∉ stamp_tg_set` and use the stamp's commit to produce the
/// appropriate anchor. The `elapsed` sequence is empty, since we have not
/// progressed past any nullifiers yet.
#[derive(Debug)]
pub struct UnspentSeed;

impl Step for UnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = ArbitraryUnspent;
    type Right = ();
    /// `(anchor_prev, (epoch, nf), stamp_tg_set)`.
    type Witness<'source> = (Anchor, (EpochIndex, Nullifier), TachygramSetPoly);

    const INDEX: Index = Index::new(6);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, (epoch, nf), stamp_tg_set): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");

        // Exclusion: nf ∉ set ⇔ the set polynomial is nonzero at nf.
        let nf_point = Fp::from(nf);
        let eval = stamp_tg_set.eval(nf_point);
        ctx.enforce_poly_query(stamp_tg_set.commit().into(), nf_point, eval)?;
        enforce_nonzero(eval, "UnspentSeed: found nullifier in set")?;
        let stamp_commit = stamp_tg_set.commit();
        let tested_anchor = anchor_prev.next_stamp(epoch, &stamp_commit);
        // Empty elapsed: the sentinel constant `1` commits to `g0`, never the
        // identity point.
        let elapsed_commit = NfSeqCommit::from(g0 * Fp::ONE);
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
/// 1)`, so its `elapsed` holds the single nullifier `nf_prev` tested in the
/// epoch being left, and `nf` opens as the tip in the epoch being entered.
///
/// # Soundness
///
/// `nf_prev` and `nf` are unconstrained here, as at every seed;
/// [`UnspentBind`] forces the endpoints against the note's genuine derivation.
/// `elapsed` is derived from `nf_prev` rather than witnessed, so the two cannot
/// disagree.
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
    /// `(anchor_prev, (epoch_prev, nf_prev), nf)`.
    type Witness<'source> = (Anchor, (EpochIndex, Nullifier), Nullifier);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, (epoch_prev, nf_prev), nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        #[expect(clippy::expect_used, reason = "constant size")]
        let (&g0, &g1) = {
            let generators = Pasta::host_generators(Pasta::baked());
            (
                generators.g().first().expect("at least one generator"),
                generators.g().get(1).expect("at least two generators"),
            )
        };

        // One-member elapsed: `[nf_prev]` plus the sentinel `1`.
        let elapsed_commit = NfSeqCommit::from(g0 * Fp::from(nf_prev) + g1);

        let epoch = epoch_prev.next();
        let anchor = anchor_prev.next_epoch(epoch);

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
/// The halves meet inside one epoch (`right.epoch_start == left.epoch_end`), at
/// adjacent anchors (`left.anchor_last == right.anchor_prev`), and agree on the
/// junction nullifier (`left.nf_end == right.nf_start`); their histories are
/// concatenated (`combined = left_elapsed ++ right_elapsed`). No epoch boundary
/// is crossed, so `elapsed` gains no entry (the junction nf is
/// `right_elapsed`'s head if right later crossed a boundary; otherwise it stays
/// the in-progress `nf_end`). A crossing is its own segment
/// ([`EndEpochUnspentSeed`]), so every seam this fuse sees is intra-epoch.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = ArbitraryUnspent;
    /// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq): Self::Witness<'source>,
        (
            left_anchor_prev,
            (left_epoch_start, left_nf_start),
            left_elapsed,
            (left_epoch_end, left_nf_end),
            left_anchor_last,
        ): <Self::Left as Header>::Data,
        (
            right_anchor_prev,
            (right_epoch_start, right_nf_start),
            right_elapsed,
            (right_epoch_end, right_nf_end),
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
            Fp::from(right_epoch_start) - Fp::from(left_epoch_end),
            "UnspentFuse: forwards half must sit in left's tip epoch",
        )?;
        // Seam bind: both halves tested the junction epoch at the same nf, so the
        // merged history's view of it is unambiguous.
        enforce_zero(
            Fp::from(left_nf_end) - Fp::from(right_nf_start),
            "UnspentFuse: halves disagree on the junction nullifier",
        )?;
        let combined_commit = combined_elapsed_seq.commit();
        let offset = left_epoch_end - left_epoch_start;
        // Sentinel concat: a sequence of `k` members is `Σ n_i·X^i + X^k`, so
        // `combined = left ++ right` is the shifted combination
        // `combined(X) = left(X) + X^offset·right(X) - X^offset`. The
        // `-X^offset` monomial cancels left's sentinel, right's first crossing
        // lands in the vacated slot, and right's own sentinel re-terminates
        // `combined`. The monomial's constant coefficient is trivially
        // challenge-independent, and `offset` is left's header-fixed span.
        enforce_shifted_combination(
            ctx,
            [
                (left_elapsed_seq.as_ref(), 0),
                (right_elapsed_seq.as_ref(), offset.into()),
            ],
            [(-Fp::ONE, offset.into())],
            combined_elapsed_seq.as_ref(),
            "UnspentFuse: combined is not the concatenation of the halves",
        )?;
        Ok((
            (
                left_anchor_prev,
                (left_epoch_start, left_nf_start),
                combined_commit,
                (right_epoch_end, right_nf_end),
                right_anchor_last,
            ),
            (),
        ))
    }
}

/// Bind an [`ArbitraryUnspent`]'s free-witness nullifiers to a
/// note's genuine nullifiers.
///
/// Proves `range == elapsed ++ [nf_end]` against the derived
/// [`NullifierHeader`], emitting an [`Unspent`] with the `cm`. The tip
/// enters as a monomial coefficient of [`enforce_shifted_combination`]:
/// `unspent_nf_end` is a left-header value, fixed by the recursive
/// verification of the [`ArbitraryUnspent`] PCD before the challenge.
#[derive(Debug)]
pub struct UnspentBind;

impl Step for UnspentBind {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = Unspent;
    type Right = NullifierHeader;
    /// `(elapsed_seq, nf_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (elapsed_seq, nf_seq): Self::Witness<'source>,
        (
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            unspent_elapsed,
            (unspent_epoch_end, unspent_nf_end),
            unspent_anchor_last,
        ): <Self::Left as Header>::Data,
        (nf_cm, (nf_epoch_start, nf_start), nf_seq_commit, (nf_epoch_end, nf_end)): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(nf_epoch_start) - Fp::from(unspent_epoch_start),
            "UnspentBind: derived range does not start at the unspent's start epoch",
        )?;
        enforce_zero(
            Fp::from(nf_epoch_end) - Fp::from(unspent_epoch_end.next()),
            "UnspentBind: derived range does not span the crossings plus the tip",
        )?;
        enforce_equal_point(
            Eq::from(elapsed_seq.commit()),
            Eq::from(unspent_elapsed),
            "UnspentBind: elapsed polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(nf_seq.commit()),
            Eq::from(nf_seq_commit),
            "UnspentBind: range polynomial does not match header",
        )?;
        let offset = unspent_epoch_end - unspent_epoch_start;
        // Sentinel append: a sequence of `k` members is `Σ n_i·X^i + X^k`, so
        // `nf_seq = elapsed ++ [unspent_nf_end]` is the shifted combination
        // `nf_seq(X) = elapsed(X) + (unspent_nf_end - 1)·X^offset +
        // X^{offset+1}`. The first monomial overwrites elapsed's sentinel with
        // the appended tip; the second re-terminates `nf_seq`. Both
        // coefficients are challenge-independent: `unspent_nf_end` is a
        // left-header value, fixed by the recursive verification of the
        // [`ArbitraryUnspent`] PCD; `offset` is elapsed's header-fixed span.
        enforce_shifted_combination(
            ctx,
            [(elapsed_seq.as_ref(), 0)],
            [
                (Fp::from(unspent_nf_end) - Fp::ONE, offset.into()),
                (Fp::ONE, u64::from(offset) + 1),
            ],
            nf_seq.as_ref(),
            "UnspentBind: range is not elapsed followed by the tip",
        )?;
        // Bind the unspent's free-witness boundary nullifiers to the range's
        // genuine boundary leaves, which the derivation header proved by
        // construction.
        enforce_zero(
            Fp::from(unspent_nf_start) - Fp::from(nf_start),
            "UnspentBind: start nullifier does not match the derived range",
        )?;
        enforce_zero(
            Fp::from(unspent_nf_end) - Fp::from(nf_end),
            "UnspentBind: end nullifier does not match the derived range",
        )?;
        Ok((
            (
                nf_cm,
                unspent_anchor_prev,
                (unspent_epoch_start, unspent_nf_start),
                (unspent_epoch_end, unspent_nf_end),
                unspent_anchor_last,
            ),
            (),
        ))
    }
}
