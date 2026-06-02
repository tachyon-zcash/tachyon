//! Anchor-bound primitives over consensus state.
//!
//! Hosts two range shapes:
//!
//! - [`AnchorChain`] — set-free anchor continuity, consumed by
//!   [`super::stamp::StampLift`] to advance a stamp's anchor.
//! - [`RangeSummary`] — bounded anchor segment that additionally carries the
//!   union of every absorbed stamp's tachygram set, the foundation for
//!   inclusion and exclusion tests against a segment.
//!
//! Per-nf exclusion lives in [`super::spendable`] as `Unspent`, built
//! from a [`RangeSummary`] via `UnspentRange`.
//!
//! Anchor advances are single-level: every link absorbs one stamp's
//! tachygram-set commitment into the running [`Anchor`] via
//! [`Anchor::next_stamp`]. There is no per-block hash domain — block
//! alignment is a consensus convention (validators check that anchor
//! endpoints belong to the published per-block anchor sequence).
//!
//! `RangeSummary` is bounded by the per-step multiset budget (~8192
//! items across all sets in a single step). Above that ceiling, proofs
//! transition into set-free `Unspent` (for per-nf exclusion) or
//! `AnchorChain` (for anchor-only continuity); the `UnspentRange`
//! step in [`super::spendable`] is the natural transition.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use crate::primitives::{Anchor, TachygramSetCommit, TachygramSetGadget};

/// Set-free anchor segment between two endpoints. Composable via
/// [`AnchorFuse`].
///
/// Direction-agnostic: `start` and `end` are both anchors. Consumed only
/// by [`super::stamp::StampLift`] — extending a spendable's anchor must
/// instead go through [`super::spendable::Unspent`] so each step proves
/// nf-exclusion.
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
///
/// Unlike [`RangeSummary`], `AnchorChain` carries no tachygram data, so
/// it composes to arbitrary length without bumping into the per-step
/// multiset budget — aggregator-side stamp lifts ride this set-free path.
#[derive(Clone, Debug)]
pub struct AnchorChain;

impl Header for AnchorChain {
    /// `(start, end)`. `start` roots in an unbound witness at [`AnchorSeed`] or
    /// [`EmptyBlockSeed`] and flows to [`super::stamp::StampLift`] which must
    /// ultimately be checked by consensus. `end` is always computed in-circuit
    /// as `start.next_stamp(...)` or `start.next_empty()`.
    type Data<'source> = (Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Bounded anchor segment that additionally carries the union of every
/// absorbed stamp's tachygram set — the foundation for inclusion and
/// exclusion tests against the segment.
///
/// `start` and `end` mark the segment's anchor endpoints exactly as in
/// [`AnchorChain`]. `tg_set` is a Pedersen commitment to the union of
/// every stamp link's tachygram set absorbed along the segment;
/// empty-block links contribute the empty multiset (identity under
/// merge).
///
/// Intra-epoch is structurally inherited from [`AnchorChain`]: only
/// [`Anchor::next_stamp`] / [`Anchor::next_empty`] are invoked, never
/// [`Anchor::next_epoch`]. Crossing the boundary would require either a
/// real anchor pair that the in-circuit hashes don't connect (the
/// fuse's adjacency check rejects) or freely-witnessed endpoints that
/// then fail consensus anchor membership at consumption.
///
/// # Bounded by the per-step multiset budget
///
/// The per-step multiset budget caps total items across all sets at
/// roughly 8192. Every [`RangeSummaryFuse`] merges two
/// `TachygramSetGadget`s, so a segment can only grow as long as the
/// union of all its absorbed tachygrams stays under that ceiling
/// (minus the bookkeeping for the merge itself). Above that, build
/// the segment in chunks and transition to [`super::spendable::Unspent`]
/// via [`super::spendable::UnspentRange`] before fusing further.
#[derive(Clone, Debug)]
pub struct RangeSummary;

impl Header for RangeSummary {
    /// `(start, end, tg_set)`. `start` is freely witnessed at the seed
    /// steps ([`RangeSummaryStampSeed`] / [`RangeSummaryEmptySeed`]).
    /// `end` is computed in-circuit as `start.next_stamp(...)` or
    /// `start.next_empty()`. `tg_set` is the commitment of the gadget
    /// multiset witnessed at the seed (a single stamp's tachygram set,
    /// or the empty multiset for an empty-block link).
    type Data<'source> = (Anchor, Anchor, TachygramSetCommit);

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&<[u8; 32]>::from(data.2.0));
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
        (start, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
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
        (start,): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
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
        _witness: Self::Witness<'source>,
        (left_start, left_end): <Self::Left as Header>::Data<'source>,
        (right_start, right_end): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_end != right_start {
            return Err(mock_ragu::Error("AnchorFuse: segments not adjacent"));
        }
        Ok(((left_start, right_end), ()))
    }
}

/// Single-stamp [`RangeSummary`] seed. Witness `(start, stamp_tg_set)`;
/// commits `stamp_tg_set` to a `TachygramSetCommit`, absorbs it into
/// the anchor, and emits `(start, end, tg_commit)`.
///
/// `start` is freely witnessed; binding closes downstream at
/// [`super::spendable::UnspentRange`] /
/// [`super::spendable::SpendableInitRange`] and ultimately through consensus
/// anchor membership.
///
/// TODO: Multi-stamp composition steps (e.g. a two-stamp seed and a
/// stamp-absorb step) would collapse a sequence of seed+fuse pairs into
/// one step each, useful for wallets/sync services that build summaries
/// of known shape.
#[derive(Debug)]
pub struct RangeSummaryStampSeed;

impl Step for RangeSummaryStampSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = RangeSummary;
    type Right = ();
    /// `(start, stamp_tg_set)`.
    type Witness<'source> = (Anchor, TachygramSetGadget);

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        (start, stamp_tg_set): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let tg_commit = TachygramSetCommit::from(stamp_tg_set);
        let end = start.next_stamp(&tg_commit);
        Ok(((start, end, tg_commit), ()))
    }
}

/// One-empty-block [`RangeSummary`] seed. Witness `(start,)`;
/// emits `(start, start.next_empty(), empty_tg)`.
///
/// `empty_tg` is the commitment of the empty multiset; downstream
/// queries (`query(x)` for any x) return non-zero against it, so an
/// empty-block summary cleanly carries the "no tachygrams here"
/// semantics needed by [`super::spendable::UnspentRange`].
#[derive(Debug)]
pub struct RangeSummaryEmptySeed;

impl Step for RangeSummaryEmptySeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = RangeSummary;
    type Right = ();
    /// `(start,)`.
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        (start,): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let empty_tg = TachygramSetCommit::from([].as_slice());
        let end = start.next_empty();
        Ok(((start, end, empty_tg), ()))
    }
}

/// Compose two adjacent [`RangeSummary`] segments — `left.end ==
/// right.start`. Witness gadgets bind to each side's `tg_set` so the
/// merged commitment is verifiable.
#[derive(Debug)]
pub struct RangeSummaryFuse;

impl Step for RangeSummaryFuse {
    type Aux<'source> = ();
    type Left = RangeSummary;
    type Output = RangeSummary;
    type Right = RangeSummary;
    /// `(left_tg_gadget, right_tg_gadget)`.
    type Witness<'source> = (TachygramSetGadget, TachygramSetGadget);

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        (tgs0, tgs1): Self::Witness<'source>,
        (left_start, left_end, left_tg_commit): <Self::Left as Header>::Data<'source>,
        (right_start, right_end, right_tg_commit): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_end != right_start {
            return Err(mock_ragu::Error("RangeSummaryFuse: segments not adjacent"));
        }
        if tgs0.0.commit() != left_tg_commit.0 || tgs1.0.commit() != right_tg_commit.0 {
            return Err(mock_ragu::Error(
                "RangeSummaryFuse: witness gadgets must commit to header tg_set",
            ));
        }
        let merged_tg = TachygramSetGadget(tgs0.0.merge(&tgs1.0));
        let merged_commit = TachygramSetCommit::from(merged_tg);
        Ok(((left_start, right_end, merged_commit), ()))
    }
}
