//! Chain-bound primitives over consensus block state.
//!
//! Hosts the within-block tg-bound shards (`InclusionShard`,
//! `ExclusionShard`), the within-block tg-unbound rollback chain
//! (`InclusionComplement`), and the raw multi-block span (`AnchorSpan`).
//! The tg-bound multi-block span (`Unspent`) and its single-block seeds
//! live in the sibling `unspent` module.
//!
//! See the plan at `73a4847-implemented-a-new-snoopy-crown.md` for the
//! design rationale and step semantics.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::delegation::NullifierHeader;
use crate::{
    SubBlock,
    note::{self, Nullifier},
    primitives::{Anchor, TachygramSetCommit, TachygramSetGadget},
};

/// Wallet-bound per-stamp inclusion proof.
///
/// Asserts that `tg = cm` lies in some real stamp's set and `block_state`
/// is the running block-state immediately after the cm-stamp's
/// absorption. The wallet's `nf` is GGM-bound to `cm` upstream via
/// [`NullifierHeader`], so its epoch claim flows through the nf itself
/// — no epoch field is needed on the shard. Produced by
/// [`InclusionShardFuse`]. Consumed by `SpendableInit`.
#[derive(Clone, Debug)]
pub struct InclusionShard;

impl Header for InclusionShard {
    /// `(cm, nf, block_state)`.
    type Data<'source> = (note::Commitment, Nullifier, SubBlock);

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&data.2.0.to_repr());
        out
    }
}

/// Per-nf sub-block exclusion fragment: `tg = nf` is absent from every
/// stamp covered by this fragment. Built per-stamp at seed and fused with
/// adjacent fragments to cover larger ranges within a block.
#[derive(Clone, Debug)]
pub struct ExclusionShard;

impl Header for ExclusionShard {
    /// `(tg, start_state, end_state)` — `start_state` is the running
    /// block-state before this fragment's first covered stamp;
    /// `end_state` is after its last.
    type Data<'source> = (Nullifier, SubBlock, SubBlock);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&data.1.0.to_repr());
        out.extend_from_slice(&data.2.0.to_repr());
        out
    }
}

/// Tg-unbound rollback chain anchored at a known block.
///
/// Built linearly backward from the block's closing state via
/// [`InclusionComplementSeed`] + [`InclusionComplementStep`]. Every PCD
/// intermediate along the lineage is a valid Complement at some rollback
/// depth — wallets pick the depth matching their cm position. **Only
/// consumed by** `SpendableInit`.
#[derive(Clone, Debug)]
pub struct InclusionComplement;

impl Header for InclusionComplement {
    /// `(start_state, anchor)` — `start_state` is the rollback frontier
    /// (running block-state just before this Complement's first covered
    /// stamp; equals `closing_block_state` at seed), `anchor` is the
    /// block's published closing anchor (computed at seed).
    type Data<'source> = (SubBlock, Anchor);

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&data.0.0.to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Raw multi-block chain segment, composable via [`AnchorSpanFuse`].
///
/// Structurally intra-epoch because only intra-epoch [`Anchor::next_block`]
/// is invoked anywhere in the `AnchorSpan` builders — crossing an epoch
/// boundary requires the [`Anchor::next_epoch`] domain only emitted by
/// `SpendableRollover`.
#[derive(Clone, Debug)]
pub struct AnchorSpan;

impl Header for AnchorSpan {
    /// `(prev_anchor, end_anchor)` — `prev_anchor` is exclusive
    /// (predecessor of first covered block), `end_anchor` is inclusive
    /// (last covered block's anchor).
    type Data<'source> = (Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Fuse a wallet's [`NullifierHeader`] with a freely-witnessed
/// `(pre_cm_state, stamp_tg_set)` to produce an [`InclusionShard`] that
/// pins `cm`/`nf` to the running block-state after the cm-stamp.
///
/// Verifies `cm ∈ stamp_tg_set` (cm comes from the left header). The
/// `pre_cm_state` is freely witnessed — cm position within the cm-block
/// is unconstrained here; chain integrity at `SpendableInit` pins it.
/// The wallet's epoch claim is carried by `nf` (GGM-bound upstream) and
/// is dropped from the shard.
#[derive(Debug)]
pub struct InclusionShardFuse;

impl Step for InclusionShardFuse {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = InclusionShard;
    type Right = ();
    /// `(pre_cm_state, stamp_tg_set)`.
    type Witness<'source> = (SubBlock, TachygramSetGadget);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        (pre_cm_state, stamp_tg_set): Self::Witness<'source>,
        (cm, nf, _epoch): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Inclusion: cm ∈ set ⇔ query(cm) == 0.
        if stamp_tg_set.0.query(Fp::from(cm)) != Fp::ZERO {
            return Err(mock_ragu::Error(
                "InclusionShardFuse: commitment not in set",
            ));
        }
        let stamp_commit = TachygramSetCommit::from(stamp_tg_set);
        let block_state = pre_cm_state.next(&stamp_commit);
        Ok(((cm, nf, block_state), ()))
    }
}

/// Per-stamp exclusion seed: verify `nf ∉ stamp_tg_set` and absorb the
/// stamp's commit at `start_state`, producing a one-stamp [`ExclusionShard`].
///
/// `start_state` is freely witnessed — the seed proves nothing about
/// real-chain coverage on its own. Whole-block coverage is enforced at
/// [`super::unspent::UnspentInit`].
#[derive(Debug)]
pub struct ExclusionShardSeed;

impl Step for ExclusionShardSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = ExclusionShard;
    type Right = ();
    /// `(start_state, stamp_tg_set, nf)`.
    type Witness<'source> = (SubBlock, TachygramSetGadget, Nullifier);

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        (start_state, stamp_tg_set, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Exclusion: nf ∉ set ⇔ query(nf) != 0.
        if stamp_tg_set.0.query(Fp::from(nf)) == Fp::ZERO {
            return Err(mock_ragu::Error(
                "ExclusionShardSeed: found nullifier in set",
            ));
        }
        let stamp_commit = TachygramSetCommit::from(stamp_tg_set);
        let end_state = start_state.next(&stamp_commit);
        Ok(((nf, start_state, end_state), ()))
    }
}

/// Compose two adjacent [`ExclusionShard`] fragments for the same `nf`.
/// Verify same `tg` and `left.end_state == right.start_state`.
#[derive(Debug)]
pub struct ExclusionShardFuse;

impl Step for ExclusionShardFuse {
    type Aux<'source> = ();
    type Left = ExclusionShard;
    type Output = ExclusionShard;
    type Right = ExclusionShard;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_tg, left_start, left_end): <Self::Left as Header>::Data<'source>,
        (right_tg, right_start, right_end): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_tg != right_tg {
            return Err(mock_ragu::Error(
                "ExclusionShardFuse: left and right must share the same nf",
            ));
        }
        if left_end != right_start {
            return Err(mock_ragu::Error(
                "ExclusionShardFuse: left.end_state must equal right.start_state",
            ));
        }
        Ok(((left_tg, left_start, right_end), ()))
    }
}

/// Seed an [`InclusionComplement`] at a known block.
///
/// Witness the block's `(prev_anchor, closing_block_state)`; compute and
/// publish the block's `anchor` via intra-epoch [`Anchor::next_block`].
/// At seed `start_state == closing_block_state` (zero stamps covered).
#[derive(Debug)]
pub struct InclusionComplementSeed;

impl Step for InclusionComplementSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = InclusionComplement;
    type Right = ();
    /// `(prev_anchor, closing_block_state)`.
    type Witness<'source> = (Anchor, SubBlock);

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        (prev_anchor, closing_block_state): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let anchor = prev_anchor.next_block(closing_block_state);
        Ok(((closing_block_state, anchor), ()))
    }
}

/// Roll the [`InclusionComplement`] frontier back past one stamp.
///
/// Witness `(prev_state, prev_stamp_commit)` and verify
/// `prev_state.next(&prev_stamp_commit) == start_state`.
/// Output advances `start_state ← prev_state`.
#[derive(Debug)]
pub struct InclusionComplementStep;

impl Step for InclusionComplementStep {
    type Aux<'source> = ();
    type Left = InclusionComplement;
    type Output = InclusionComplement;
    type Right = ();
    /// `(prev_state, prev_stamp_commit)`.
    type Witness<'source> = (SubBlock, TachygramSetCommit);

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        (prev_state, prev_stamp_commit): Self::Witness<'source>,
        (start_state, anchor): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let recomputed = prev_state.next(&prev_stamp_commit);
        if recomputed != start_state {
            return Err(mock_ragu::Error(
                "InclusionComplementStep: cannot prepend incorrect preimage",
            ));
        }
        Ok(((prev_state, anchor), ()))
    }
}

/// Single-block raw span seed. Witness `(prev_anchor, block_state)`;
/// compute `end_anchor` and emit `(prev_anchor, end_anchor)`.
#[derive(Debug)]
pub struct AnchorSpanSeed;

impl Step for AnchorSpanSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorSpan;
    type Right = ();
    /// `(prev_anchor, block_state)`.
    type Witness<'source> = (Anchor, SubBlock);

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        (prev_anchor, block_state): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let end_anchor = prev_anchor.next_block(block_state);
        Ok(((prev_anchor, end_anchor), ()))
    }
}

/// Extend an [`AnchorSpan`] forward by one block.
///
/// Witness `next_block_state`; advance `end_anchor` via intra-epoch
/// [`Anchor::next_block`]. Adjacency is by construction. Intra-epoch-only
/// is structural: this step never invokes [`Anchor::next_epoch`].
#[derive(Debug)]
pub struct AnchorSpanStep;

impl Step for AnchorSpanStep {
    type Aux<'source> = ();
    type Left = AnchorSpan;
    type Output = AnchorSpan;
    type Right = ();
    /// `(next_block_state,)`.
    type Witness<'source> = (SubBlock,);

    const INDEX: Index = Index::new(13);

    fn witness<'source>(
        &self,
        (next_block_state,): Self::Witness<'source>,
        (prev_anchor, end_anchor): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let new_end = end_anchor.next_block(next_block_state);
        Ok(((prev_anchor, new_end), ()))
    }
}

/// Compose two adjacent [`AnchorSpan`]s — `left.end_anchor ==
/// right.prev_anchor`.
///
/// Same-epoch is structural via collision-resistance plus domain
/// separation (cross-epoch joins would require matching a boundary
/// anchor that no `AnchorSpan` builder ever emits).
#[derive(Debug)]
pub struct AnchorSpanFuse;

impl Step for AnchorSpanFuse {
    type Aux<'source> = ();
    type Left = AnchorSpan;
    type Output = AnchorSpan;
    type Right = AnchorSpan;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_prev, left_end): <Self::Left as Header>::Data<'source>,
        (right_prev, right_end): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_end != right_prev {
            return Err(mock_ragu::Error("AnchorSpanFuse: spans not adjacent"));
        }
        Ok(((left_prev, right_end), ()))
    }
}
