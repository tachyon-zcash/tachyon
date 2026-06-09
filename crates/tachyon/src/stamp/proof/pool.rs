//! Anchor-bound primitives over consensus state.
//!
//! Hosts the nf-free anchor segment ([`AnchorChain`]) used by
//! [`super::stamp::StampLift`] to advance a stamp's anchor, and the
//! multi-stamp exclusion proof ([`Unspent`]) used by
//! [`super::spendable::SpendableLift`] to advance a spendable.
//!
//! Anchor advances are single-level: every link absorbs one stamp's
//! tachygram-set commitment into the running [`Anchor`] via
//! [`Anchor::next_stamp`]. There is no per-block hash domain — block
//! alignment is a consensus convention (validators check that anchor
//! endpoints belong to the published per-block anchor sequence).

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use ragu::{Header, Index, Step, Suffix};

use crate::{
    note::Nullifier,
    primitives::{Anchor, TachygramSetCommit, TachygramSetPoly},
};

/// Anchor segment between two endpoints. Composable via [`AnchorFuse`].
///
/// Direction-agnostic: `start` and `end` are both anchors. Consumed only
/// by [`super::stamp::StampLift`] — extending a spendable's anchor must
/// instead go through [`Unspent`] so each step proves nf-exclusion.
///
/// Structurally intra-epoch because only intra-epoch [`Anchor::next_stamp`]
/// is invoked anywhere in the [`AnchorChain`] builders — crossing an
/// epoch boundary requires the [`Anchor::next_epoch`] domain only
/// emitted by `SpendableRollover`.
///
/// The within-epoch property pairs with a consensus-side two-epoch
/// tachygram scan that catches any tachygram already published earlier
/// in the epoch a stamp is lifted across. See the Tachygrams book chapter.
///
/// `start` at the seed steps ([`AnchorSeed`] / [`EmptyBlockSeed`]) has
/// PCD lineage rooted in an unbound `start: Anchor` witness, so a
/// standalone segment proves nothing about real coverage. Final binding
/// closes when [`super::stamp::StampLift`] consumes the segment and the
/// resulting stamp is accepted by consensus (anchor membership).
#[derive(Clone, Debug)]
pub struct AnchorChain;

impl Header for AnchorChain {
    /// `(start, end)`. `start` roots in an unbound witness at [`AnchorSeed`] or
    /// [`EmptyBlockSeed`] and flows to [`super::stamp::StampLift`] which must
    /// ultimately be checked by consensus. `end` is always computed in-circuit
    /// as `start.next_stamp(...)` or `start.next_empty()`.
    type Data = (Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Per-nf range exclusion proof.
///
/// `nf` is absent from every stamp covered by the anchor segment from
/// `start` to `end`. Built per-stamp at seed and fused with adjacent
/// fragments — fusion now spans block boundaries because anchor
/// advances are continuous.
///
/// Same-epoch is structurally guaranteed by GGM-binding of `nf` to one
/// epoch and by the intra-epoch-only `Anchor::next_stamp` advances —
/// crossing an epoch boundary requires matching a boundary anchor that
/// no `Unspent` builder ever emits.
///
/// At the seed steps the PCD lineage of `nf` and `start` roots in
/// freely-chosen witnesses. `nf`'s binding closes at the consumer
/// ([`super::spendable::SpendableLift`] checks `unspent.nf ==
/// spendable.nf`; the spendable's `nf` is itself bound upstream at
/// [`super::delegation::NullifierHeader`]); `start`'s binding closes
/// through the spendable lineage plus consensus anchor membership.
#[derive(Clone, Debug)]
pub struct Unspent;

impl Header for Unspent {
    /// `(nf, start, end)`. `nf` roots in a seed witness, bound by the
    /// consumer ([`super::spendable::SpendableLift`] checks
    /// `unspent.nf == spendable.nf`, and the spendable's `nf` is
    /// GGM-bound upstream). `start` roots in a seed witness, bound
    /// through the spendable lineage plus consensus anchor membership.
    /// `end` is always computed in-circuit as `start.next_stamp(...)`
    /// or `start.next_empty()`.
    type Data = (Nullifier, Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out
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

    const INDEX: Index = Index::new(7);

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

    const INDEX: Index = Index::new(8);

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

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (left_start, left_end): <Self::Left as Header>::Data,
        (right_start, right_end): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if left_end != right_start {
            return Err(ragu::Error("AnchorFuse: segments not adjacent"));
        }
        Ok(((left_start, right_end), ()))
    }
}

/// Per-stamp exclusion seed: verify `nf ∉ stamp_tg_set` and absorb the
/// stamp's commit at `start`, producing a one-stamp [`Unspent`].
///
/// `start` is freely witnessed — the seed proves nothing about real
/// coverage on its own. Final binding happens transitively through the
/// spendable lineage plus consensus-side anchor membership.
#[derive(Debug)]
pub struct UnspentSeed;

impl Step for UnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Unspent;
    type Right = ();
    /// `(start, stamp_tg_set, nf)`.
    type Witness<'source> = (Anchor, TachygramSetPoly, Nullifier);

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (start, stamp_tg_set, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Exclusion: nf ∉ set ⇔ the set polynomial is nonzero at nf.
        let nf_point = Fp::from(nf);
        let eval = stamp_tg_set.eval(nf_point);
        ctx.enforce_poly_query(stamp_tg_set.commit().into(), nf_point, eval)?;
        if eval == Fp::ZERO {
            return Err(ragu::Error("UnspentSeed: found nullifier in set"));
        }
        let stamp_commit = stamp_tg_set.commit();
        let end = start.next_stamp(&stamp_commit);
        Ok(((nf, start, end), ()))
    }
}

/// One-empty-block [`Unspent`] seed for any `nf`. No exclusion check is
/// needed — an empty block contains no stamps, so any nf is trivially
/// absent.
///
/// Witness `(start, nf)`; emit `(nf, start, start.next_empty())`. An
/// attacker can claim any nf at an empty-block segment, but the consumer
/// (`SpendableLift`) checks `unspent.nf == spendable.nf` and the
/// spendable's nf is GGM-bound upstream — so a fake-nf empty segment can
/// only "advance" a non-existent fake spendable.
#[derive(Debug)]
pub struct EmptyBlockUnspentSeed;

impl Step for EmptyBlockUnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Unspent;
    type Right = ();
    /// `(start, nf)`.
    type Witness<'source> = (Anchor, Nullifier);

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (start, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok(((nf, start, start.next_empty()), ()))
    }
}

/// Compose two adjacent [`Unspent`] segments for the same `nf`.
/// Verify same `nf` and `left.end == right.start`.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = Unspent;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (left_nf, left_start, left_end): <Self::Left as Header>::Data,
        (right_nf, right_start, right_end): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if left_nf != right_nf {
            return Err(ragu::Error(
                "UnspentFuse: left and right must share the same nf",
            ));
        }
        if left_end != right_start {
            return Err(ragu::Error("UnspentFuse: left.end must equal right.start"));
        }
        Ok(((left_nf, left_start, right_end), ()))
    }
}
