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
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Step, Suffix,
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

use super::delegation::NullifierDerivation;
use crate::{
    constants::NF_DERIVATION_WIDTH,
    digest::poseidon,
    note::{self},
    nullifier::{
        NfFoldAccumulator, NfWhitenedSpectrum, Nullifier,
        derivation::{NF_COSET_SHIFT, NF_EPOCH_STEP},
    },
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
/// `nf_start` is the range's first tested nullifier (the nullifier at
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

    const INDEX: Index = Index::new(0);

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

    const INDEX: Index = Index::new(1);

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

    const INDEX: Index = Index::new(2);

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
/// commit to produce the
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

    const INDEX: Index = Index::new(3);

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

    const INDEX: Index = Index::new(4);

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

    const INDEX: Index = Index::new(5);

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

    const INDEX: Index = Index::new(6);

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
        let offset = left_epoch_end - left_epoch_start;
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
                (left_elapsed_seq.as_ref(), 0),
                (right_elapsed_seq.as_ref(), u64::from(offset) + 1),
            ],
            [(Fp::from(left_nf_end) - Fp::ONE, offset.into())],
            combined_elapsed_seq.as_ref(),
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
/// nullifiers, by a partial telescope over the covering derivation's whitened
/// trace.
///
/// Consumes a [`NullifierDerivation`] that merely *covers* the unspent span
/// (`deriv.start <= unspent.start`, `unspent.end < deriv.end`), not one
/// aligned to it. The fold accumulator $A$ satisfies $A(X) - \chi A(\zeta X)
/// = W(\sigma X)$ exactly as polynomials (checked at a free $z$), so
/// iterating at $X = \zeta^{\mathsf{off}}, \ldots,
/// \zeta^{\mathsf{off}+\mathsf{span}}$ telescopes to
///
/// $$
/// A(\zeta^{\mathsf{off}})
///     - \chi^{\mathsf{span}+1} A(\zeta^{\mathsf{off}+\mathsf{span}+1})
///     = \sum_{i \le \mathsf{span}} \chi^i \, W(\sigma \zeta^{\mathsf{off}+i}),
/// $$
///
/// the genuine nullifiers over the covered span, folded at $\chi$. The
/// tested sub-sequence `nf_seq = elapsed ++ [unspent_nf_end]` must discharge
/// against it at $\chi$:
///
/// $$
/// \mathsf{elapsed}(\chi) + (\mathsf{nf\_end} - 1) \chi^{\mathsf{span}}
///     = A(\zeta^{\mathsf{off}})
///     - \chi^{\mathsf{span}+1} A(\zeta^{\mathsf{off}+\mathsf{span}+1})
/// $$
///
/// (the monomial swaps elapsed's sentinel for the tip; the
/// sentinel-turned-$\chi^{\mathsf{span}}$ coefficient keeps junk above
/// degree $\mathsf{span}$ from hiding). Since $\chi$ is
/// Poseidon-bound to `elapsed`'s commitment, the single-point check forces
/// every coefficient to the genuine nullifier. `nf_start` is read as a
/// degree-0 opening of `elapsed` (or equals `nf_end` when no epoch was
/// crossed), and both boundary nullifiers are emitted on the
/// [`VerifiedUnspent`].
#[derive(Debug)]
pub struct UnspentBind;

impl Step for UnspentBind {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = VerifiedUnspent;
    type Right = NullifierDerivation;
    /// `(elapsed_seq, nf_spectrum, accumulator)`.
    type Witness<'source> = (NfSeqPoly, NfWhitenedSpectrum, NfFoldAccumulator);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (elapsed_seq, nf_spectrum, accumulator): Self::Witness<'source>,
        (
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            unspent_elapsed,
            (unspent_epoch_end, unspent_nf_end),
            unspent_anchor_last,
        ): <Self::Left as Header>::Data,
        (deriv_cm, deriv_start, deriv_end, nf_commit): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            elapsed_seq.commit().into(),
            Eq::from(unspent_elapsed),
            "UnspentBind: elapsed polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(nf_spectrum.commit()),
            Eq::from(nf_commit),
            "UnspentBind: whitened trace does not match header",
        )?;

        // Native coverage guards: the covered `[start, end]` sits inside the
        // derivation, so the telescope's epoch offsets never wrap past the
        // window. Mock stand-ins for range constraints, as is the belt-and-
        // braces single-window width check (only `WrapStep` emits the header,
        // always one window wide).
        if deriv_end.0 - deriv_start.0 != NF_DERIVATION_WIDTH {
            return Err(ragu::Error::InvalidWitness(
                "UnspentBind: derivation is not a single window".into(),
            ));
        }
        if deriv_start.0 > unspent_epoch_start.0 {
            return Err(ragu::Error::InvalidWitness(
                "UnspentBind: derivation does not cover the unspent start".into(),
            ));
        }
        if deriv_end.0 <= unspent_epoch_end.0 {
            return Err(ragu::Error::InvalidWitness(
                "UnspentBind: derivation does not cover the unspent end".into(),
            ));
        }

        // `span` is elapsed's member count (the crossings); the tested
        // sub-sequence `nf_seq = elapsed ++ [unspent_nf_end]` spans
        // `[unspent_epoch_start, unspent_epoch_end]`.
        let off = unspent_epoch_start - deriv_start;
        let span = unspent_epoch_end - unspent_epoch_start;

        // $\chi$: the fold weight, Poseidon over the trace and elapsed
        // commitments; $A$ is built for it, and the single-point discharge
        // below is sound only because $\chi$ binds elapsed's commitment.
        let chi = poseidon::fold_challenge(nf_commit.into(), elapsed_seq.commit().into());

        // `z`: a fresh transcript challenge over the three commitments, so
        // the fold identity's operands are fixed before it (Schwartz-Zippel).
        let z = ctx.derive_challenge(&[
            nf_spectrum.commit().into(),
            accumulator.commit().into(),
            elapsed_seq.commit().into(),
        ])?;

        // Fold identity: $A(X) - \chi A(\zeta X) = W(\sigma X)$, exact as
        // polynomials (both
        // sides have degree below `|D|`), so the point check forces it
        // coefficient-wise and the partial telescope below is sound.
        let zeta = *NF_EPOCH_STEP;
        let whitened_at_coset = nf_spectrum.as_ref().eval(*NF_COSET_SHIFT * z);
        ctx.enforce_poly_query(
            nf_spectrum.commit().into(),
            *NF_COSET_SHIFT * z,
            whitened_at_coset,
        )?;
        let accumulator_at_z = accumulator.as_ref().eval(z);
        ctx.enforce_poly_query(accumulator.commit().into(), z, accumulator_at_z)?;
        let accumulator_folded = accumulator.as_ref().eval(zeta * z);
        ctx.enforce_poly_query(accumulator.commit().into(), zeta * z, accumulator_folded)?;
        if accumulator_at_z - chi * accumulator_folded != whitened_at_coset {
            return Err(ragu::Error::InvalidWitness(
                "UnspentBind: fold accumulator identity fails at challenge".into(),
            ));
        }

        // Partial telescope endpoints $A(\zeta^{\mathsf{off}})$ and
        // $A(\zeta^{\mathsf{off}+\mathsf{span}+1})$, and the fold weights
        // $\chi^{\mathsf{span}}$, $\chi^{\mathsf{span}+1}$. The powers are
        // native
        // mock stand-ins for fixed-width (log-width bit) exponentiation
        // chains over the header-pinned `off` and `span`.
        let telescope_head = zeta.pow_vartime([u64::from(off)]);
        let telescope_tail = zeta.pow_vartime([u64::from(off) + u64::from(span) + 1]);
        let chi_span = chi.pow_vartime([u64::from(span)]);
        let chi_len = chi_span * chi;
        let accumulator_head = accumulator.as_ref().eval(telescope_head);
        ctx.enforce_poly_query(
            accumulator.commit().into(),
            telescope_head,
            accumulator_head,
        )?;
        let accumulator_tail = accumulator.as_ref().eval(telescope_tail);
        ctx.enforce_poly_query(
            accumulator.commit().into(),
            telescope_tail,
            accumulator_tail,
        )?;

        // Discharge: $\mathsf{elapsed}(\chi) + (\mathsf{nf\_end} - 1)
        // \chi^{\mathsf{span}}$ is $\mathsf{nf\_seq}(\chi)$ with its sentinel
        // stripped (the monomial overwrites elapsed's sentinel with the
        // tip); the telescope is the genuine fold of the covered leaves.
        // Equality at the Poseidon-bound $\chi$ forces every coefficient
        // of `elapsed` and the tip to the genuine nullifiers.
        let elapsed_at_chi = elapsed_seq.eval(chi);
        ctx.enforce_poly_query(elapsed_seq.commit().into(), chi, elapsed_at_chi)?;
        let folded_leaves = accumulator_head - chi_len * accumulator_tail;
        if elapsed_at_chi + (Fp::from(unspent_nf_end) - Fp::ONE) * chi_span != folded_leaves {
            return Err(ragu::Error::InvalidWitness(
                "UnspentBind: sub-sequence does not match the derivation".into(),
            ));
        }

        // Boundary nullifiers: `unspent_nf_end` is pinned as the tip monomial
        // and bound by the discharge above. `unspent_nf_start` is `elapsed`'s
        // degree-0 coefficient (its first crossing), or the tip itself when
        // no epoch was crossed and `elapsed` is empty.
        if u64::from(span) == 0 {
            enforce_zero(
                Fp::from(unspent_nf_start) - Fp::from(unspent_nf_end),
                "UnspentBind: single-epoch segment boundary nullifiers differ",
            )?;
        } else {
            ctx.enforce_poly_query(
                elapsed_seq.commit().into(),
                Fp::ZERO,
                Fp::from(unspent_nf_start),
            )?;
        }

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
