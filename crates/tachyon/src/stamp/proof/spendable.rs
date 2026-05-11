//! Spendable bootstrap, lift, and cross-epoch rollover.
//!
//! Bootstrap runs entirely on the user device. The wallet's
//! [`NullifierHeader`] carries `(cm, nf, epoch)`; fusing it with a
//! freely-witnessed `(pre_cm_state, stamp_tg_set)` via
//! [`pool::InclusionShardFuse`] produces a wallet-bound
//! [`pool::InclusionShard`] carrying `(cm, nf, block_state)`.
//! [`SpendableInit`] then fuses that shard with a sync-service-supplied
//! [`pool::InclusionComplement`] (rolled back to the cm-stamp position),
//! verifying chain integrity, to produce a [`SpendableHeader`] carrying
//! only `(nf, anchor)`. The cm↔nf binding is structurally inherited
//! through the shard — no separate cm-equality check is needed at
//! `SpendableInit`. The wallet's epoch claim flows through `nf` itself
//! (GGM-bound at the NullifierHeader), so no epoch alignment check is
//! needed here either.
//!
//! Position-independence is intrinsic — the wallet seeds its
//! `InclusionShard` at whatever cm-pre-state its cm-stamp actually sits
//! at, and the sync service's per-block rollback lineage exposes a valid
//! `InclusionComplement` at every depth.
//!
//! Sync services update spendables via lifts ([`SpendableLift`]) and
//! cross-epoch rollovers ([`SpendableRollover`] →
//! [`SpendableEpochLift`]). [`SpendableRollover`] is the only step that
//! emits the [`Anchor::next_epoch`] boundary domain — it lifts the old
//! epoch's terminal anchor into the new epoch's initial anchor, which
//! the new-epoch [`Unspent`] chain then extends with ordinary block
//! steps.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::{
    delegation::{DelegateNullifierHeader, NullifierHeader},
    pool::{InclusionComplement, InclusionShard},
    unspent::Unspent,
};
use crate::{
    note::Nullifier,
    primitives::{Anchor, EpochIndex},
};

/// Wallet's spendable position. Identified by `nf` alone — `nf` uniquely
/// encodes `(key, epoch)` via GGM determinism, so sync services can update
/// a spendable by `nf` without knowing `delegation_id`.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    /// `(nf, anchor)`.
    type Data<'source> = (Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Cross-epoch nf rotation pair.
///
/// `nfs[0]` is the old-epoch `nf`, `nfs[1]` the new-epoch `nf`; the new
/// epoch index is exposed for downstream consumers (specifically
/// [`SpendableRollover`]'s boundary hash). Consecutive epochs are
/// verified at construction.
#[derive(Clone, Debug)]
pub struct NullifierRolloverHeader;

impl Header for NullifierRolloverHeader {
    /// `(old_nf, new_nf, new_epoch)`.
    type Data<'source> = (Nullifier, Nullifier, EpochIndex);

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 4);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&data.2.0.to_le_bytes());
        out
    }
}

/// A spendable rolled forward through an nf rotation, awaiting a
/// new-epoch chain anchor from [`SpendableEpochLift`].
///
/// Carries `new_nf` (which the new-epoch [`Unspent`] must cover) and
/// `boundary_anchor` (output of [`Anchor::next_epoch`] applied to the
/// old epoch's terminal anchor — i.e., the new epoch's initial chain
/// anchor). The new-epoch `Unspent`'s `prev_anchor` must equal this
/// boundary anchor. The old-epoch nullifier is dropped: [`SpendableRollover`]
/// has already discharged it against the input spendable's `nf`.
#[derive(Clone, Debug)]
pub struct SpendableRolloverHeader;

impl Header for SpendableRolloverHeader {
    /// `(new_nf, boundary_anchor)`.
    type Data<'source> = (Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Fuse a wallet's [`InclusionShard`] with a sync-service-supplied
/// [`InclusionComplement`] rolled back to the cm-stamp position, producing
/// a [`SpendableHeader`] anchored at the cm-block.
///
/// Verifies chain integrity (`shard.block_state == complement.start_state`).
/// The cm↔nf binding is structurally inherited through the shard, so no
/// cm-equality check is needed here. The cm-block structurally cannot
/// contain the wallet's nullifier (`nf` is Poseidon-bound to `cm`), so
/// `SpendableInit` does not carry an nf-exclusion check on the cm-block.
/// The wallet's epoch claim flows through `nf` (GGM-bound at the
/// NullifierHeader); no epoch alignment check is needed.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = InclusionShard;
    type Output = SpendableHeader;
    type Right = InclusionComplement;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (_shard_cm, shard_nf, shard_block_state): <Self::Left as Header>::Data<'source>,
        (complement_start_state, complement_anchor): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if shard_block_state != complement_start_state {
            return Err(mock_ragu::Error(
                "SpendableInit: wrong complement for shard state",
            ));
        }
        Ok(((shard_nf, complement_anchor), ()))
    }
}

/// Advance a [`SpendableHeader`]'s `anchor` along an [`Unspent`] chain
/// segment whose `prev_anchor` equals the spendable's current anchor.
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(19);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (spendable_nf, spendable_anchor): <Self::Left as Header>::Data<'source>,
        (unspent_nf, unspent_prev_anchor, unspent_end_anchor): <Self::Right as Header>::Data<
            'source,
        >,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if unspent_nf != spendable_nf {
            return Err(mock_ragu::Error(
                "SpendableLift: unspent does not relate to spendable",
            ));
        }
        if unspent_prev_anchor != spendable_anchor {
            return Err(mock_ragu::Error(
                "SpendableLift: unspent not adjacent to spendable",
            ));
        }
        Ok(((spendable_nf, unspent_end_anchor), ()))
    }
}

/// Combine two [`NullifierHeader`]s into a [`NullifierRolloverHeader`] via
/// lineage-bound `cm` equality. **User device.**
#[derive(Debug)]
pub struct RolloverFuse;

impl Step for RolloverFuse {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = NullifierRolloverHeader;
    type Right = NullifierHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(20);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_cm, left_nf, left_epoch): <Self::Left as Header>::Data<'source>,
        (right_cm, right_nf, right_epoch): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_cm != right_cm {
            return Err(mock_ragu::Error("RolloverFuse: nullifiers not related"));
        }
        if right_epoch.0 != left_epoch.0 + 1 {
            return Err(mock_ragu::Error("RolloverFuse: nullifiers not adjacent"));
        }
        Ok(((left_nf, right_nf, right_epoch), ()))
    }
}

/// Combine two [`DelegateNullifierHeader`]s into a
/// [`NullifierRolloverHeader`] via `delegation_id` equality. **Sync service
/// or user.**
#[derive(Debug)]
pub struct DelegateRolloverFuse;

impl Step for DelegateRolloverFuse {
    type Aux<'source> = ();
    type Left = DelegateNullifierHeader;
    type Output = NullifierRolloverHeader;
    type Right = DelegateNullifierHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(21);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_nf, left_epoch, left_delegation_id): <Self::Left as Header>::Data<'source>,
        (right_nf, right_epoch, right_delegation_id): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_delegation_id != right_delegation_id {
            return Err(mock_ragu::Error(
                "DelegateRolloverFuse: nullifiers not related",
            ));
        }
        if right_epoch.0 != left_epoch.0 + 1 {
            return Err(mock_ragu::Error(
                "DelegateRolloverFuse: nullifiers not adjacent",
            ));
        }
        Ok(((left_nf, right_nf, right_epoch), ()))
    }
}

/// Lift a [`SpendableHeader`] across an epoch boundary.
///
/// Checks `spendable.nf == old_nf` from the [`NullifierRolloverHeader`],
/// then applies [`Anchor::next_epoch`] to the spendable's current anchor
/// to produce the new epoch's `boundary_anchor`. Emits `(new_nf,
/// boundary_anchor)` for [`SpendableEpochLift`] to consume against a
/// new-epoch [`Unspent`] whose `prev_anchor` equals this boundary.
///
/// This is the only step in the proof tree that invokes the
/// [`Anchor::next_epoch`] domain. `new_epoch` enters the boundary hash
/// directly, so any tampered value diverges from the published chain.
#[derive(Debug)]
pub struct SpendableRollover;

impl Step for SpendableRollover {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableRolloverHeader;
    type Right = NullifierRolloverHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(22);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (spendable_nf, spendable_anchor): <Self::Left as Header>::Data<'source>,
        (rollover_old_nf, rollover_new_nf, rollover_new_epoch): <Self::Right as Header>::Data<
            'source,
        >,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if spendable_nf != rollover_old_nf {
            return Err(mock_ragu::Error(
                "SpendableRollover: nullifiers don't match",
            ));
        }
        let boundary_anchor = spendable_anchor.next_epoch(rollover_new_epoch);
        Ok(((rollover_new_nf, boundary_anchor), ()))
    }
}

/// Land a rolled-over spendable on a new-epoch chain anchor.
///
/// Merges with a new-epoch [`Unspent`] whose `prev_anchor` equals the
/// rollover's `boundary_anchor`. The boundary anchor cryptographically
/// binds `new_epoch` via [`Anchor::next_epoch`], and the new-epoch
/// [`Unspent`] is bound to the wallet's new-epoch identity via
/// `unspent.nf == new_nf` (GGM-bound upstream in the NullifierHeader).
/// Together these pin the wallet to the real chain's E→E+1 transition.
#[derive(Debug)]
pub struct SpendableEpochLift;

impl Step for SpendableEpochLift {
    type Aux<'source> = ();
    type Left = SpendableRolloverHeader;
    type Output = SpendableHeader;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(23);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (rollover_new_nf, rollover_boundary_anchor): <Self::Left as Header>::Data<'source>,
        (unspent_nf, unspent_prev_anchor, unspent_end_anchor): <Self::Right as Header>::Data<
            'source,
        >,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if unspent_nf != rollover_new_nf {
            return Err(mock_ragu::Error(
                "SpendableEpochLift: nullifiers not related",
            ));
        }
        if unspent_prev_anchor != rollover_boundary_anchor {
            return Err(mock_ragu::Error(
                "SpendableEpochLift: unspent prev_anchor must equal rollover boundary_anchor",
            ));
        }
        Ok(((rollover_new_nf, unspent_end_anchor), ()))
    }
}
