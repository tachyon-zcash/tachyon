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

use super::delegation::NullifierDerivation;
use crate::{
    note::{self},
    nullifier::Nullifier,
    primitives::{
        Anchor, EpochIndex, NfMarginPoly, NfSeqCommit, NfSeqPoly, NfTailPoly, TachygramSetCommit,
        TachygramSetPoly,
    },
    relations::{enforce::enforce_shifted_combination, read::enforce_covering_read},
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
/// `[epoch_start, epoch_last]`, in bare Horner order (see [`NfSeqPoly`]):
/// `nf_start` at the top degree, the present `nf_last` at degree `0`. The
/// seeds establish the form and the fuses preserve it; every relation over
/// the sequence takes its exponents from the header-pinned epoch spans.
///
/// `nf_start` and `nf_last` are scalar caches of the sequence's boundary
/// members. [`UnspentBind`] binds both, and every interior member, to the
/// note's genuine derivation nullifiers.
///
/// `nf_start` is also the **rank pin**, as at
/// [`super::delegation::NullifierDerivation`]: it is
/// `elapsed`'s top coefficient, guarded nonzero at both seeds and threaded by
/// the fuse, so the announced span is the exact rank. Without it a two-member
/// sequence with a zero head would commit exactly as a one-member sequence
/// does, and a crossing could present itself as a point segment.
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
/// single member $\mathsf{nf}$, the epoch under test.
#[derive(Debug)]
pub struct UnspentSeed;

impl Step for UnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = ArbitraryUnspent;
    type Right = ();
    /// `(anchor_prev, (epoch, nf), stamp_tg_set)`.
    type Witness<'source> = (Anchor, (EpochIndex, Nullifier), TachygramSetPoly);

    const INDEX: Index = Index::new(4);

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
        // Nonzero guard: a nonzero `nf` is the sequence's rank pin, and it
        // keeps the one-member commitment below off the identity point, which
        // the in-circuit point representation cannot hold. Zero is reserved.
        enforce_nonzero(nf_point, "UnspentSeed: tested nullifier is zero")?;

        // One-member elapsed: the Horner encoding of `[nf]` is the constant
        // `nf`, committing to `g0 * nf`.
        let elapsed_commit = NfSeqCommit::from(g0 * nf_point);
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
/// derivation. `elapsed` is derived from them rather than witnessed, so the
/// commitment and the header scalars cannot disagree.
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

    const INDEX: Index = Index::new(5);

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

        // Nonzero guard: a nonzero `nf_prev` is the sequence's rank pin, and
        // without it the two-member encoding below collapses onto the
        // one-member commitment `UnspentSeed` emits. Zero is reserved.
        enforce_nonzero(
            Fp::from(nf_prev),
            "EndEpochUnspentSeed: outgoing nullifier is zero",
        )?;
        enforce_nonzero(
            Fp::from(nf),
            "EndEpochUnspentSeed: incoming nullifier is zero",
        )?;

        // Two-member elapsed: the Horner encoding of `[nf_prev, nf]` is
        // `nf_prev·X + nf`, the first member at the top degree as at
        // `UnspentSeed`, which is the one-member case of the same encoding.
        let elapsed_commit = NfSeqCommit::from(g0 * Fp::from(nf) + g1 * Fp::from(nf_prev));

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
        let offset = right_epoch_last - right_epoch_start;
        // Junction dedup: a sequence of `k` members is `Σ n_i·X^{k-1-i}`, and
        // the halves share the junction member (left's degree 0, right's top
        // degree `k_R - 1`), so `combined = left ++ right[1..]` is the shifted
        // combination `combined(X) = X^{k_R-1}·left(X) + right(X) -
        // nf_j·X^{k_R-1}`: the monomial removes the double-counted junction.
        // Its coefficient is challenge-independent: `left_nf_last` is a
        // left-header value, fixed by the recursive verification of the left
        // PCD; the exponent `k_R - 1` is right's header-fixed span. At a
        // one-member right (`k_R = 1`) the identity degenerates to
        // `combined = left`: the merge adds stamps, not members.
        enforce_shifted_combination(
            ctx,
            [
                (left_elapsed_seq.as_ref(), offset.into()),
                (right_elapsed_seq.as_ref(), 0),
            ],
            [(-Fp::from(left_nf_last), offset.into())],
            combined_elapsed_seq.as_ref(),
            "UnspentFuse: combined is not the concatenation of the halves",
        )?;
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
/// nullifiers, by a covering read out of the derivation's sequence.
///
/// Consumes a [`NullifierDerivation`] that merely *covers* the unspent span
/// (`deriv.epoch_start <= unspent.epoch_start`,
/// `unspent.epoch_last < deriv.epoch_end`). Any window covering the span
/// serves, at any margin sizes. `elapsed` covers
/// `[epoch_start, epoch_last]` inclusive, one member per epoch; the read
/// window `[epoch_start, epoch_last + 1)` converts to the derivation's
/// exclusive convention. The margins absorb whatever the window covers
/// outside the lineage: `older` any epochs below it (including before the
/// note existed), `tail` the epochs the derivation runs ahead of the
/// exclusion evidence — a spend publishes two nullifiers, so the wallet
/// derives past the lineage while the lineage stops at published evidence.
///
/// # Soundness
///
/// The read identity forces elapsed's *content*. Of the endpoint scalar
/// caches, `nf_last` is `elapsed`'s degree-0 coefficient (the present
/// value), pinned here by a repeat opening; `nf_start` is the
/// non-extractable top coefficient, equal to `nf_last` when the segment
/// covers a single epoch and otherwise forced downstream where the join
/// pins it against the spendable's independently pinned `present_nf` (with
/// `epoch_start == spendable.epoch` stopping a right value at a wrong
/// epoch). [`UnspentFuse`]'s junction check is therefore a well-formedness
/// check, not the genuineness pin: a consistent pair of lies there yields a
/// wrong merged `elapsed`, which this identity rejects.
///
/// The lineage is note-blind, so the bind *stamps* the derivation's `cm` onto
/// the validated [`Unspent`].
///
/// # Committed polynomials
///
/// | polynomial | role |
/// |---|---|
/// | `elapsed` | the tested sequence, bound to the unspent header |
/// | `g` | the covering sequence, bound to the derivation header |
/// | `older` | sentineled absorbing margin above the read |
/// | `tail` | cap-shifted sentineled absorbing margin below the read |
#[derive(Debug)]
pub struct UnspentBind;

impl Step for UnspentBind {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = Unspent;
    type Right = NullifierDerivation;
    /// `(elapsed_seq, g, older, tail)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfMarginPoly, NfTailPoly);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (elapsed_seq, g, older, tail): Self::Witness<'source>,
        (
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            unspent_elapsed,
            (unspent_epoch_last, unspent_nf_last),
            unspent_anchor_last,
        ): <Self::Left as Header>::Data,
        (
            deriv_cm,
            (deriv_start, _deriv_nf_start),
            nf_commit,
            (deriv_end, _deriv_nf_last),
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            elapsed_seq.commit().into(),
            Eq::from(unspent_elapsed),
            "UnspentBind: elapsed polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(g.commit()),
            Eq::from(nf_commit),
            "UnspentBind: covering sequence does not match header",
        )?;

        // Native coverage guards: mock stand-ins for range constraints over
        // the header-pinned bounds.
        if deriv_start.0 > unspent_epoch_start.0 {
            return Err(ragu::Error::InvalidWitness(
                "UnspentBind: derivation does not cover the unspent start".into(),
            ));
        }
        if deriv_end.0 <= unspent_epoch_last.0 {
            return Err(ragu::Error::InvalidWitness(
                "UnspentBind: derivation does not cover the unspent end".into(),
            ));
        }

        // The read window is `[epoch_start, epoch_last + 1)`: the `+1` is the
        // declared conversion between the unspent's inclusive bounds and the
        // derivation's exclusive one.
        let members = u64::from(unspent_epoch_last - unspent_epoch_start) + 1;
        let margin = u64::from(deriv_end - unspent_epoch_last) - 1;
        enforce_covering_read(
            ctx,
            g.as_ref(),
            older.as_ref(),
            tail.as_ref(),
            elapsed_seq.as_ref(),
            members,
            margin,
            "UnspentBind: sequence does not match the derivation",
        )?;

        // Boundary nullifiers, per the step's soundness section.
        ctx.enforce_poly_query(
            elapsed_seq.commit().into(),
            Fp::ZERO,
            Fp::from(unspent_nf_last),
        )?;
        if members == 1 {
            enforce_zero(
                Fp::from(unspent_nf_start) - Fp::from(unspent_nf_last),
                "UnspentBind: single-epoch segment boundary nullifiers differ",
            )?;
        }

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
