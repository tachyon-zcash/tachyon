//! Spendable status headers and steps.
//!
//! Spendable state carries no `delegation_id`. `nf` uniquely encodes
//! `(key, epoch)` via GGM determinism and is bound to the wallet's `cm` by
//! the pre-blind chain rooted at `NfMasterSeed`; downstream nf-equality
//! (e.g. at `SpendStamp`) recovers any further binding required, by
//! composition of upstream PCDs.

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use mock_ragu::{Header, Index, Multiset, Step, Suffix};
use pasta_curves::Fp;

use super::delegation::{DelegateNullifierHeader, NullifierHeader};
use crate::{
    note::Nullifier,
    primitives::{Anchor, PoolDelta, PoolSet, epoch_seed_hash},
};

fn encode_spendable(nf: Nullifier, anchor: &Anchor) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 4 + 32);
    out.extend_from_slice(&Fp::from(nf).to_repr());
    out.extend_from_slice(&u32::from(anchor.0).to_le_bytes());
    let pool_bytes: [u8; 32] = anchor.1.0.into();
    out.extend_from_slice(&pool_bytes);
    out
}

/// Header attesting a note is spendable at a specific anchor.
///
/// Identified by `nf` alone — `nf` uniquely encodes `(key, epoch)` via
/// GGM determinism, so sync services can update a spendable by `nf`
/// without any `delegation_id`.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    /// `(nf, anchor)`.
    type Data<'source> = (Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        encode_spendable(data.0, &data.1)
    }
}

/// Header collecting information necessary for epoch transition. Carries
/// `(old_nf, new_nf, anchor)` — `delegation_id` is fused internally at
/// [`SpendableRollover`] and not propagated.
#[derive(Debug)]
pub struct SpendableRolloverHeader;

impl Header for SpendableRolloverHeader {
    /// `(old_nf, new_nf, new_anchor)`.
    type Data<'source> = (Nullifier, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(4);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 4 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&u32::from(data.2.0).to_le_bytes());
        let pool_bytes: [u8; 32] = data.2.1.0.into();
        out.extend_from_slice(&pool_bytes);
        out
    }
}

/// Seeds spendable status from a pre-blind GGM-leaf header.
///
/// Note-ownership and well-formedness are structurally enforced upstream by
/// `NfMasterSeed`; `cm` arrives on the leaf so this step only needs to
/// verify pool membership and epoch alignment. By PCD soundness, the
/// emitted `(nf, anchor)` carries forward the upstream `cm ↔ nf` binding —
/// any downstream nf-equality (e.g. at `SpendStamp`) reconnects to a
/// witnessed wallet without a `delegation_id` flowing through.
///
/// TODO: this should probably check a single block, instead of pool state.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableHeader;
    type Right = ();
    type Witness<'source> = (PoolSet<Multiset>, Anchor);

    const INDEX: Index = Index::new(6);

    fn witness<'source>(
        &self,
        (pool, anchor): Self::Witness<'source>,
        (cm_tg, nf, epoch): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if epoch != anchor.0.epoch() {
            return Err(mock_ragu::Error(
                "SpendableInit: nullifier epoch must match anchor epoch",
            ));
        }

        if pool.0.commit() != anchor.1.0 {
            return Err(mock_ragu::Error(
                "SpendableInit: pool must commit to anchor",
            ));
        }

        if pool.0.query(Fp::from(cm_tg)) != Fp::ZERO {
            return Err(mock_ragu::Error("SpendableInit: cm not in pool"));
        }
        if pool.0.query(Fp::from(nf)) == Fp::ZERO {
            return Err(mock_ragu::Error("SpendableInit: nullifier already in pool"));
        }

        Ok(((nf, anchor), ()))
    }
}

/// Collects prerequisites for epoch transition.
///
/// Consumes two post-blind `DelegateNullifierHeader`s and binds them as
/// same-wallet via `delegation_id`-equality; `delegation_id` is not
/// propagated to the output.
#[derive(Debug)]
pub struct SpendableRollover;

impl Step for SpendableRollover {
    type Aux<'source> = ();
    type Left = DelegateNullifierHeader;
    type Output = SpendableRolloverHeader;
    type Right = DelegateNullifierHeader;
    type Witness<'source> = (PoolSet<Multiset>, Anchor);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        (pool, anchor): Self::Witness<'source>,
        (old_nf, old_epoch, old_delegation_id): <Self::Left as Header>::Data<'source>,
        (new_nf, new_epoch, new_delegation_id): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if old_delegation_id != new_delegation_id {
            return Err(mock_ragu::Error(
                "SpendableRollover: delegations not related",
            ));
        }
        if new_epoch.0 != old_epoch.0 + 1 {
            return Err(mock_ragu::Error(
                "SpendableRollover: nullifiers not adjacent",
            ));
        }
        if new_epoch != anchor.0.epoch() {
            return Err(mock_ragu::Error(
                "SpendableRollover: new epoch must match anchor epoch",
            ));
        }

        if pool.0.commit() != anchor.1.0 {
            return Err(mock_ragu::Error(
                "SpendableRollover: pool must commit to anchor",
            ));
        }
        if pool.0.query(Fp::from(new_nf)) == Fp::ZERO {
            return Err(mock_ragu::Error(
                "SpendableRollover: new nullifier already in pool",
            ));
        }

        Ok(((old_nf, new_nf, anchor), ()))
    }
}

/// Advances spendable status to a later block within the same epoch.
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = ();
    type Witness<'source> = (PoolSet<Multiset>, PoolDelta<Multiset>, Anchor);

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        (old_pool, delta, to_anchor): Self::Witness<'source>,
        (nf, old_anchor): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if old_pool.0.commit() != old_anchor.1.0 {
            return Err(mock_ragu::Error(
                "SpendableLift: pool must commit to old anchor",
            ));
        }

        if to_anchor.0 <= old_anchor.0 || to_anchor.0.epoch() != old_anchor.0.epoch() {
            return Err(mock_ragu::Error(
                "SpendableLift: target anchor must be later within the same epoch",
            ));
        }

        let to_pool = old_pool.0.merge(&delta.0);
        if to_pool.commit() != to_anchor.1.0 {
            return Err(mock_ragu::Error(
                "SpendableLift: pool plus delta must commit to target anchor",
            ));
        }

        if delta.0.query(Fp::from(nf)) == Fp::ZERO {
            return Err(mock_ragu::Error(
                "SpendableLift: nullifier was spent in delta",
            ));
        }

        Ok(((nf, to_anchor), ()))
    }
}

/// Transitions an epoch-final spendable into the next epoch.
#[derive(Debug)]
pub struct SpendableEpochLift;

impl Step for SpendableEpochLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = SpendableRolloverHeader;
    type Witness<'source> = (PoolSet<Multiset>,);

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        (pool,): Self::Witness<'source>,
        (old_nf, old_anchor): <Self::Left as Header>::Data<'source>,
        (rollover_old_nf, new_nf, new_anchor): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if old_nf != rollover_old_nf {
            return Err(mock_ragu::Error(
                "SpendableEpochLift: rollover not related to spendable",
            ));
        }
        if !old_anchor.0.is_epoch_final() {
            return Err(mock_ragu::Error(
                "SpendableEpochLift: old anchor must be epoch-final",
            ));
        }
        if new_anchor.0.epoch().0 != old_anchor.0.epoch().0 + 1 {
            return Err(mock_ragu::Error(
                "SpendableEpochLift: anchors not in adjacent epochs",
            ));
        }

        if pool.0.commit() != new_anchor.1.0 {
            return Err(mock_ragu::Error(
                "SpendableEpochLift: pool must commit to new anchor",
            ));
        }

        let seed = epoch_seed_hash(&old_anchor.1);
        if pool.0.query(seed) != Fp::ZERO {
            return Err(mock_ragu::Error(
                "SpendableEpochLift: epoch seed not in new pool",
            ));
        }

        Ok(((new_nf, new_anchor), ()))
    }
}
