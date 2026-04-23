//! Spendable status headers and steps.

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use mock_ragu::{Header, Index, Multiset, Step, Suffix};
use pasta_curves::Fp;

use super::delegation::NullifierHeader;
use crate::{
    keys::ProofAuthorizingKey,
    note::{Note, Nullifier},
    primitives::{Anchor, DelegationId, DelegationTrapdoor, PoolDelta, PoolSet, epoch_seed_hash},
};

fn encode_spendable(delegation_id: DelegationId, nf: Nullifier, anchor: &Anchor) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32 + 4 + 32);
    out.extend_from_slice(&Fp::from(&delegation_id).to_repr());
    out.extend_from_slice(&Fp::from(&nf).to_repr());
    out.extend_from_slice(&u32::from(anchor.0).to_le_bytes());
    let pool_bytes: [u8; 32] = anchor.1.0.into();
    out.extend_from_slice(&pool_bytes);
    out
}

/// Header attesting a note is spendable at a specific anchor.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    type Data<'source> = (DelegationId, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        encode_spendable(data.0, data.1, &data.2)
    }
}

/// Header collecting information necessary for epoch transition.
#[derive(Debug)]
pub struct SpendableRolloverHeader;

impl Header for SpendableRolloverHeader {
    // (delegation_id, old_nf, new_nf, new_anchor)
    type Data<'source> = (DelegationId, Nullifier, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(4);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 4 + 32);
        out.extend_from_slice(&Fp::from(&data.0).to_repr());
        out.extend_from_slice(&Fp::from(&data.1).to_repr());
        out.extend_from_slice(&Fp::from(&data.2).to_repr());
        out.extend_from_slice(&u32::from(data.3.0).to_le_bytes());
        let pool_bytes: [u8; 32] = data.3.1.0.into();
        out.extend_from_slice(&pool_bytes);
        out
    }
}

/// Proves cm inclusion to bootstrap spendable status.
///
/// TODO: this should probably check a single block, instead of pool state.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableHeader;
    type Right = ();
    type Witness<'source> = (
        Note,
        ProofAuthorizingKey,
        DelegationTrapdoor,
        PoolSet<Multiset>,
        Anchor,
    );

    const INDEX: Index = Index::new(6);

    fn witness<'source>(
        &self,
        (note, pak, trap, pool, anchor): Self::Witness<'source>,
        (nf, epoch, delegation_id): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if u64::from(note.value) == 0 {
            return Err(mock_ragu::Error);
        }
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(mock_ragu::Error);
        }

        if delegation_id != pak.nk.derive_delegation_id(&note, trap) {
            return Err(mock_ragu::Error);
        }
        if epoch != anchor.0.epoch() {
            return Err(mock_ragu::Error);
        }

        if pool.0.commit() != anchor.1.0 {
            return Err(mock_ragu::Error);
        }

        let cm: Fp = Fp::from(&note.commitment());
        if pool.0.query(cm) != Fp::ZERO {
            return Err(mock_ragu::Error);
        }
        if pool.0.query(Fp::from(&nf)) == Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((delegation_id, nf, anchor), ()))
    }
}

/// Collects some prerequisites for epoch transition.
#[derive(Debug)]
pub struct SpendableRollover;

impl Step for SpendableRollover {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableRolloverHeader;
    type Right = NullifierHeader;
    type Witness<'source> = (PoolSet<Multiset>, Anchor);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        (pool, anchor): Self::Witness<'source>,
        (old_nf, old_epoch, old_delegation_id): <Self::Left as Header>::Data<'source>,
        (new_nf, new_epoch, new_delegation_id): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if old_delegation_id != new_delegation_id {
            return Err(mock_ragu::Error);
        }
        if new_epoch.0 != old_epoch.0 + 1 {
            return Err(mock_ragu::Error);
        }
        if new_epoch != anchor.0.epoch() {
            return Err(mock_ragu::Error);
        }

        if pool.0.commit() != anchor.1.0 {
            return Err(mock_ragu::Error);
        }
        if pool.0.query(Fp::from(&new_nf)) == Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((new_delegation_id, old_nf, new_nf, anchor), ()))
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
        (delegation_id, nf, old_anchor): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if old_pool.0.commit() != old_anchor.1.0 {
            return Err(mock_ragu::Error);
        }

        if to_anchor.0 <= old_anchor.0 || to_anchor.0.epoch() != old_anchor.0.epoch() {
            return Err(mock_ragu::Error);
        }

        let to_pool = old_pool.0.merge(&delta.0);
        if to_pool.commit() != to_anchor.1.0 {
            return Err(mock_ragu::Error);
        }

        if delta.0.query(Fp::from(&nf)) == Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((delegation_id, nf, to_anchor), ()))
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
        (old_delegation_id, old_nf, old_anchor): <Self::Left as Header>::Data<'source>,
        (rollover_delegation_id, rollover_old_nf, new_nf, new_anchor): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if old_delegation_id != rollover_delegation_id {
            return Err(mock_ragu::Error);
        }
        if old_nf != rollover_old_nf {
            return Err(mock_ragu::Error);
        }
        if !old_anchor.0.is_epoch_final() {
            return Err(mock_ragu::Error);
        }
        if new_anchor.0.epoch().0 != old_anchor.0.epoch().0 + 1 {
            return Err(mock_ragu::Error);
        }

        if pool.0.commit() != new_anchor.1.0 {
            return Err(mock_ragu::Error);
        }

        let seed = epoch_seed_hash(&old_anchor.1);
        if pool.0.query(seed) != Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((old_delegation_id, new_nf, new_anchor), ()))
    }
}
