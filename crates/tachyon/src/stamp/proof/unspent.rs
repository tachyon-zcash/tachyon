//! Multi-block nullifier exclusion chain.
#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::pool::ExclusionShard;
use crate::{SubBlock, note::Nullifier, primitives::Anchor};

/// Multi-block exclusion-bound chain segment: `tg` is absent from every
/// stamp in every block in `(prev_anchor, end_anchor]`. Composable via
/// [`UnspentFuse`].
#[derive(Clone, Debug)]
pub struct Unspent;

impl Header for Unspent {
    /// `(tg, prev_anchor, end_anchor)`.
    type Data<'source> = (Nullifier, Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out
    }
}

/// Close a sentinel-rooted [`ExclusionShard`] (covering every stamp of a
/// non-empty block) into a single-block [`Unspent`].
///
/// Witness `prev_anchor`; compute `end_anchor` via intra-epoch
/// [`Anchor::next_block`].
#[derive(Debug)]
pub struct UnspentInit;

impl Step for UnspentInit {
    type Aux<'source> = ();
    type Left = ExclusionShard;
    type Output = Unspent;
    type Right = ();
    /// `(prev_anchor,)`.
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(16);

    fn witness<'source>(
        &self,
        (prev_anchor,): Self::Witness<'source>,
        (shard_tg, shard_start_state, shard_end_state): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if shard_start_state != SubBlock::default() {
            return Err(mock_ragu::Error(
                "UnspentInit: shard must start at empty SubBlock",
            ));
        }
        let end_anchor = prev_anchor.next_block(shard_end_state);
        Ok(((shard_tg, prev_anchor, end_anchor), ()))
    }
}

/// Direct-path single-block [`Unspent`] for an empty block.
///
/// Proves `nf` is absent from every stamp of an empty block at
/// `prev_anchor`. No [`ExclusionShard`] involved — empty blocks have
/// closing `block_state == SubBlock::default()` by definition.
#[derive(Debug)]
pub struct EmptyBlockUnspentSeed;

impl Step for EmptyBlockUnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Unspent;
    type Right = ();
    /// `(nf, prev_anchor)`.
    type Witness<'source> = (Nullifier, Anchor);

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        (nf, prev_anchor): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let end_anchor = prev_anchor.next_block(SubBlock::default());
        Ok(((nf, prev_anchor, end_anchor), ()))
    }
}

/// Compose two adjacent [`Unspent`]s for the same `tg`.
///
/// Convention: `left` covers earlier blocks than `right`; chain match is
/// `left.end_anchor == right.prev_anchor`. To "prepend" an earlier
/// `Unspent` to a later one, swap the arguments at the call site.
///
/// Same-epoch is structurally guaranteed by two independent properties:
/// (a) `left.tg == right.tg` already enforced here, and wallet nfs are
/// GGM-bound to one epoch each — distinct-epoch nfs never match; (b) the
/// join condition `left.end == right.prev` is over intra-epoch anchors
/// only, since cross-epoch transitions require the boundary domain that
/// no `Unspent` builder ever emits.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = Unspent;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(17);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_tg, left_prev, left_end): <Self::Left as Header>::Data<'source>,
        (right_tg, right_prev, right_end): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_tg != right_tg {
            return Err(mock_ragu::Error(
                "UnspentFuse: left and right must share the same nf",
            ));
        }
        if left_end != right_prev {
            return Err(mock_ragu::Error(
                "UnspentFuse: left.end_anchor must equal right.prev_anchor",
            ));
        }
        Ok(((left_tg, left_prev, right_end), ()))
    }
}
