//! Anchor-bound primitives over consensus state.
//!
//! Hosts the nf-free anchor segment ([`AnchorChain`]) used by
//! [`super::stamp::StampLift`] to advance a stamp's anchor, and the
//! multi-stamp / multi-epoch exclusion proof ([`Unspent`]) used by
//! [`super::spendable::SpendableLift`] to advance a spendable.
//!
//! Anchor advances are single-level: every link absorbs one stamp's
//! tachygram-set commitment into the running [`Anchor`] via
//! [`Anchor::next_stamp`]. There is no per-block hash domain — block
//! alignment is a consensus convention (validators check that anchor
//! endpoints belong to the published per-block anchor sequence).

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::Field as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Polynomial, Step, Suffix,
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

use super::delegation::NullifierDerivation;
use crate::{
    note::{self, Nullifier},
    primitives::{
        Anchor, EpochIndex, NfSeqCommit, NfSeqPoly, TachygramSetCommit, TachygramSetPoly,
    },
    relations::enforce::enforce_shifted_combination,
};

/// Anchor segment between two endpoints. Composable via [`AnchorFuse`].
///
/// Direction-agnostic: `start` and `end` are both anchors. Two consumers:
/// [`super::stamp::StampLift`] advances a stamp's anchor, and
/// [`super::spendable::SpendableInit`] consumes a boundary-rooted segment (from
/// the epoch boundary through the cm-stamp) to pin a spendable's starting
/// epoch. Extending an *existing* spendable's anchor must instead go through
/// [`Unspent`] so each step proves nf-exclusion.
///
/// Structurally intra-epoch: the builders ([`AnchorSeed`] / [`EmptyBlockSeed`])
/// invoke only [`Anchor::next_stamp`] / [`Anchor::next_empty`]. The
/// [`Anchor::next_epoch`] boundary domain is never a chain link; it is folded
/// at a crossing by [`UnspentEpochFuse`] and checked against a chain's `start`
/// by [`super::spendable::SpendableInit`].
///
/// The within-epoch property pairs with a consensus-side two-epoch
/// tachygram scan that catches any tachygram already published earlier
/// in the epoch a stamp is lifted across. See the Tachygrams book chapter.
///
/// `start` at the seed steps ([`AnchorSeed`] / [`EmptyBlockSeed`]) has
/// PCD lineage rooted in an unbound `start: Anchor` witness, so a
/// standalone segment proves nothing about real coverage. Final binding
/// closes through a consensus-published stamp's anchor membership:
/// [`super::stamp::StampLift`] emits that stamp directly, while a segment
/// consumed by [`super::spendable::SpendableInit`] binds only once the
/// resulting (private) spendable is spent into a stamp.
#[derive(Clone, Debug)]
pub struct AnchorChain;

impl Header for AnchorChain {
    /// `(start, end)`. `start` roots in an unbound witness at [`AnchorSeed`] or
    /// [`EmptyBlockSeed`] and flows to [`super::stamp::StampLift`] which must
    /// ultimately be checked by consensus. `end` is always computed in-circuit
    /// as `start.next_stamp(...)` or `start.next_empty()`.
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

/// Multi-stamp / multi-epoch nf-exclusion proof
///
/// An `elapsed` polynomial holds one nullifier per crossed epoch boundary over
/// `[epoch_start, epoch_end)`, sentinel-terminated (see
/// [`NfSeqPoly`]): the crossings sit at ascending degree with a coefficient
/// `1` at the crossing count, so the commitment is never the identity point
/// (the empty sequence is the constant `1`, committing to `g0`) and the
/// sequence's exact rank is pinned. The seeds establish the sentinel form and
/// both fuses preserve it.
///
/// `nf_start` is the range's first tested nullifier (the leaf at
/// `epoch_start`); the in-progress `nf_end` corresponds to `epoch_end` and is
/// folded into `elapsed` when its epoch completes. [`UnspentBind`] binds both
/// endpoints to the note's genuine derivation nullifiers.
#[derive(Clone, Debug)]
pub struct Unspent;

impl Header for Unspent {
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

/// An [`Unspent`] bound to a note's genuine derivation nullifiers by
/// [`UnspentBind`], collapsed to boundary scalars.
#[derive(Clone, Debug)]
pub struct VerifiedUnspent;

impl Header for VerifiedUnspent {
    /// `(cm, anchor_prev, (epoch_start, nf_start), (epoch_end, nf_end),
    /// anchor_last)`. `cm` leads; the rest mirrors the [`Unspent`] boundaries
    /// collapsed to scalars (no `elapsed` poly).
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

/// Single-stamp [`AnchorChain`] seed. Witness `(start, stamp_commit)`;
/// emit `(start, start.next_stamp(&stamp_commit))`.
///
/// Used for forward extension (consumed by `StampLift`'s span builder).
#[derive(Debug)]
pub struct AnchorSeed;

impl Step for AnchorSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorChain;
    type Right = ();
    /// `(start, stamp_commit)`.
    type Witness<'source> = (Anchor, TachygramSetCommit);

    const INDEX: Index = Index::new(5);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (start, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let end = start.next_stamp(&stamp_commit);
        Ok(((start, end), ()))
    }
}

/// One-empty-block [`AnchorChain`] seed. Witness `(start,)`; emit
/// `(start, start.next_empty())`.
///
/// Advances the anchor through one block that contains zero stamps.
/// Used alongside [`AnchorSeed`] when an anchor segment must traverse
/// a mix of empty and non-empty blocks.
#[derive(Debug)]
pub struct EmptyBlockSeed;

impl Step for EmptyBlockSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorChain;
    type Right = ();
    /// `(start,)`.
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(6);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (start,): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok(((start, start.next_empty()), ()))
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

    const INDEX: Index = Index::new(7);

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
    type Output = Unspent;
    type Right = ();
    /// `(anchor_prev, (epoch, nf), stamp_tg_set)`.
    type Witness<'source> = (Anchor, (EpochIndex, Nullifier), TachygramSetPoly);

    const INDEX: Index = Index::new(8);

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
        let tested_anchor = anchor_prev.next_stamp(&stamp_commit);
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

/// One-empty-block [`Unspent`] seed: emit a one-block segment that crosses no
/// epoch boundary (an empty block trivially excludes any nf, so no set check).
#[derive(Debug)]
pub struct EmptyBlockUnspentSeed;

impl Step for EmptyBlockUnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Unspent;
    type Right = ();
    /// `(anchor_prev, (epoch, nf))`.
    type Witness<'source> = (Anchor, (EpochIndex, Nullifier));

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, (epoch, nf)): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        #[expect(clippy::expect_used, reason = "constant size")]
        let &g0 = Pasta::host_generators(Pasta::baked())
            .g()
            .first()
            .expect("at least one generator");

        let tested_anchor = anchor_prev.next_empty();
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

/// Compose two [`Unspent`] lineages sharing a mid-epoch junction.
///
/// The halves meet inside one epoch (`right.epoch_start == left.epoch_end`), at
/// adjacent anchors (`left.anchor_last == right.anchor_prev`), and agree on the
/// junction nullifier (`left.nf_end == right.nf_start`); their histories are
/// concatenated (`combined = left_elapsed ++ right_elapsed`). No epoch boundary
/// is crossed, so `elapsed` gains no entry (the junction nf is
/// `right_elapsed`'s head if right later crossed a boundary; otherwise it stays
/// the in-progress `nf_end`). A crossing is [`UnspentEpochFuse`]'s job.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = Unspent;
    type Right = Unspent;
    /// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(10);

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
        let offset =
            usize::try_from(left_epoch_end.0 - left_epoch_start.0).map_err(|_too_many_epochs| {
                ragu::Error::InvalidWitness("UnspentFuse: crossing count exceeds usize".into())
            })?;
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
                (&Polynomial::from(left_elapsed_seq), 0),
                (&Polynomial::from(right_elapsed_seq), offset),
            ],
            [(-Fp::ONE, offset)],
            &Polynomial::from(combined_elapsed_seq),
        )
        .map_err(|_relation_err| {
            ragu::Error::InvalidWitness(
                "UnspentFuse: combined is not the concatenation of the halves".into(),
            )
        })?;
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

/// Cross-epoch [`Unspent`] composition. This is the only step that grows
/// `elapsed`.
///
/// At the boundary, left's tip epoch completes
/// (`left.anchor_last.next_epoch(new_epoch) == right.anchor_prev`) and is
/// folded into `elapsed`.
#[derive(Debug)]
pub struct UnspentEpochFuse;

impl Step for UnspentEpochFuse {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = Unspent;
    type Right = Unspent;
    /// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(11);

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
            (right_epoch_start, _right_nf_start),
            right_elapsed,
            (right_epoch_end, right_nf_end),
            right_anchor_last,
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(left_elapsed_seq.commit()),
            Eq::from(left_elapsed),
            "UnspentEpochFuse: left polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(right_elapsed_seq.commit()),
            Eq::from(right_elapsed),
            "UnspentEpochFuse: right polynomial does not match header",
        )?;
        enforce_zero(
            Fp::from(right_epoch_start) - Fp::from(left_epoch_end.next()),
            "UnspentEpochFuse: right epoch must be one past left's tip",
        )?;
        enforce_zero(
            Fp::from(left_anchor_last.next_epoch(right_epoch_start)) - Fp::from(right_anchor_prev),
            "UnspentEpochFuse: boundary anchor does not match right.anchor_prev",
        )?;
        let combined_commit = combined_elapsed_seq.commit();
        let offset =
            usize::try_from(left_epoch_end.0 - left_epoch_start.0).map_err(|_too_many_epochs| {
                ragu::Error::InvalidWitness("UnspentEpochFuse: crossing count exceeds usize".into())
            })?;
        // Sentinel splice: a sequence of `k` members is `Σ n_i·X^i + X^k`, so
        // `combined = left ++ [left_nf_end] ++ right` is the shifted
        // combination `combined(X) = left(X) + (left_nf_end - 1)·X^offset +
        // X^{offset+1}·right(X)`. The monomial overwrites left's sentinel with
        // the folded tip nullifier and right's own sentinel re-terminates
        // `combined`. The monomial's coefficient is challenge-independent:
        // `left_nf_end` is a left-header value, fixed by the recursive
        // verification of the left PCD; `offset` is left's header-fixed span.
        enforce_shifted_combination(
            ctx,
            [
                (&Polynomial::from(left_elapsed_seq), 0),
                (&Polynomial::from(right_elapsed_seq), offset + 1),
            ],
            [(Fp::from(left_nf_end) - Fp::ONE, offset)],
            &Polynomial::from(combined_elapsed_seq),
        )
        .map_err(|_relation_err| {
            ragu::Error::InvalidWitness(
                "UnspentEpochFuse: combined is not the splice of the halves".into(),
            )
        })?;
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

/// Bind an [`Unspent`]'s free-witness nullifiers to a note's genuine
/// nullifiers, by coverage.
///
/// Consumes a [`NullifierDerivation`] that merely *covers* the unspent span
/// (`deriv.start <= unspent.start`, `unspent.end < deriv.end`), not one aligned
/// to it. First rebuilds the tested sub-sequence `nf_seq = elapsed ++
/// [unspent_nf_end]` (the `[start, end]` nullifiers). Then coverage-extracts it
/// from the derivation's sequence `q`: `q = prefix ++ nf_seq ++ suffix` is the
/// shifted combination `q(X) = prefix(X) + X^off·nf_seq(X) +
/// X^{off+len}·suffix(X) - X^off - X^{off+len}`, whose `-X^off`/`-X^{off+len}`
/// monomials cancel `prefix`/`nf_seq` sentinels; the sentinels pin each part's
/// length so, with the header-fixed offsets, the decomposition is unique. The
/// boundary nullifiers are read as degree-0 openings and emitted on the
/// [`VerifiedUnspent`].
#[derive(Debug)]
pub struct UnspentBind;

impl Step for UnspentBind {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = VerifiedUnspent;
    type Right = NullifierDerivation;
    /// `(elapsed_seq, nf_seq, deriv_seq, prefix_seq, suffix_seq)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (elapsed_seq, nf_seq, deriv_seq, prefix_seq, suffix_seq): Self::Witness<'source>,
        (
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            unspent_elapsed,
            (unspent_epoch_end, unspent_nf_end),
            unspent_anchor_last,
        ): <Self::Left as Header>::Data,
        (deriv_cm, deriv_start, deriv_end, deriv_seq_commit): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(elapsed_seq.commit()),
            Eq::from(unspent_elapsed),
            "UnspentBind: elapsed polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(deriv_seq.commit()),
            Eq::from(deriv_seq_commit),
            "UnspentBind: derivation polynomial does not match header",
        )?;

        // The tested sub-sequence `nf_seq = elapsed ++ [unspent_nf_end]` spans
        // `[unspent_epoch_start, unspent_epoch_end]` (the crossings plus the
        // tip). `span` is elapsed's member count; `len = span + 1` is nf_seq's.
        let span =
            usize::try_from(unspent_epoch_end.0 - unspent_epoch_start.0).map_err(|_too_many| {
                ragu::Error::InvalidWitness("UnspentBind: crossing count exceeds usize".into())
            })?;
        let nf_poly = Polynomial::from(nf_seq);
        enforce_shifted_combination(
            ctx,
            [(&Polynomial::from(elapsed_seq), 0)],
            [
                (Fp::from(unspent_nf_end) - Fp::ONE, span),
                (Fp::ONE, span + 1),
            ],
            &nf_poly,
        )
        .map_err(|_relation_err| {
            ragu::Error::InvalidWitness(
                "UnspentBind: sub-sequence is not elapsed followed by the tip".into(),
            )
        })?;

        // Coverage extraction: the derivation covers the unspent span, so
        // `off = unspent_start - deriv_start >= 0` and the suffix is
        // non-empty-or-empty within `deriv_end`. `q = prefix ++ nf_seq ++
        // suffix`.
        let off = usize::try_from(
            unspent_epoch_start
                .0
                .checked_sub(deriv_start.0)
                .ok_or_else(|| {
                    ragu::Error::InvalidWitness(
                        "UnspentBind: derivation does not cover the unspent start".into(),
                    )
                })?,
        )
        .map_err(|_too_far| {
            ragu::Error::InvalidWitness("UnspentBind: coverage offset exceeds usize".into())
        })?;
        let len = span + 1;
        // Require `deriv_end > unspent_epoch_end` so the covered `[start, end]`
        // sits inside the derivation.
        if deriv_end.0 <= unspent_epoch_end.0 {
            return Err(ragu::Error::InvalidWitness(
                "UnspentBind: derivation does not cover the unspent end".into(),
            ));
        }
        enforce_shifted_combination(
            ctx,
            [
                (&Polynomial::from(prefix_seq), 0),
                (&nf_poly, off),
                (&Polynomial::from(suffix_seq), off + len),
            ],
            [(-Fp::ONE, off), (-Fp::ONE, off + len)],
            &Polynomial::from(deriv_seq),
        )
        .map_err(|_relation_err| {
            ragu::Error::InvalidWitness(
                "UnspentBind: sub-sequence is not covered by the derivation".into(),
            )
        })?;

        // Boundary nullifiers: `unspent_nf_start` is the sub-sequence's
        // degree-0 coefficient (its first covered leaf); `unspent_nf_end` is
        // already pinned as the append monomial and bound to `q` by the
        // coverage extraction above.
        ctx.enforce_poly_query(nf_poly.commit(), Fp::ZERO, Fp::from(unspent_nf_start))?;

        Ok((
            (
                deriv_cm,
                unspent_anchor_prev,
                (unspent_epoch_start, unspent_nf_start),
                (unspent_epoch_end, unspent_nf_end),
                unspent_anchor_last,
            ),
            (),
        ))
    }
}
