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
    primitives::{Anchor, NoteId, PoolDelta, PoolSet, epoch_seed_hash},
};

fn encode_spendable(note_id: NoteId, nf: Nullifier, anchor: &Anchor) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32 + 4 + 32);
    out.extend_from_slice(&Fp::from(note_id).to_repr());
    out.extend_from_slice(&Fp::from(nf).to_repr());
    out.extend_from_slice(&u32::from(anchor.0).to_le_bytes());
    let pool_bytes: [u8; 32] = anchor.1.0.into();
    out.extend_from_slice(&pool_bytes);
    out
}

/// Marker type for PCD headers carrying spendable state.
#[derive(Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    type Data<'source> = (NoteId, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        encode_spendable(data.0, data.1, &data.2)
    }
}

/// Marker type for PCD headers carrying rollover state.
#[derive(Debug)]
pub struct SpendableRolloverHeader;

impl Header for SpendableRolloverHeader {
    type Data<'source> = (NoteId, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        encode_spendable(data.0, data.1, &data.2)
    }
}

/// Proves cm inclusion and bootstraps spendable status.
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableHeader;
    type Right = ();
    type Witness<'source> = (Note, ProofAuthorizingKey, PoolSet<Multiset>, Anchor);

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        (note, pak, right_pool, right_anchor): Self::Witness<'source>,
        (nf, left_epoch, left_note_id): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(mock_ragu::Error);
        }

        let note_id = note.id(pak.nk());
        if note_id != left_note_id {
            return Err(mock_ragu::Error);
        }
        if left_epoch != right_anchor.0.epoch() {
            return Err(mock_ragu::Error);
        }

        if right_pool.0.commit() != right_anchor.1.0 {
            return Err(mock_ragu::Error);
        }

        let cm: Fp = Fp::from(note.commitment());
        if right_pool.0.query(cm) != Fp::ZERO {
            return Err(mock_ragu::Error);
        }
        if right_pool.0.query(Fp::from(nf)) == Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((left_note_id, nf, right_anchor), ()))
    }
}

/// Bootstraps a fresh non-membership proof for a new epoch.
#[derive(Debug)]
pub struct SpendableRollover;

impl Step for SpendableRollover {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableRolloverHeader;
    type Right = ();
    type Witness<'source> = (PoolSet<Multiset>, Anchor);

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        (right_pool, right_anchor): Self::Witness<'source>,
        (nf, left_epoch, left_note_id): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_epoch != right_anchor.0.epoch() {
            return Err(mock_ragu::Error);
        }

        if right_pool.0.commit() != right_anchor.1.0 {
            return Err(mock_ragu::Error);
        }
        if right_pool.0.query(Fp::from(nf)) == Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((left_note_id, nf, right_anchor), ()))
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

    const INDEX: Index = Index::new(16);

    fn witness<'source>(
        &self,
        (old_pool, delta, to_anchor): Self::Witness<'source>,
        (note_id, nf, old_anchor): <Self::Left as Header>::Data<'source>,
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

        if delta.0.query(Fp::from(nf)) == Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((note_id, nf, to_anchor), ()))
    }
}

/// Epoch transition: fuses epoch-final spendable with a start-of-E+1 rollover.
#[derive(Debug)]
pub struct SpendableEpochLift;

impl Step for SpendableEpochLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = SpendableRolloverHeader;
    type Witness<'source> = (PoolSet<Multiset>,);

    const INDEX: Index = Index::new(17);

    fn witness<'source>(
        &self,
        (right_pool,): Self::Witness<'source>,
        (left_note_id, _left_nf, left_anchor): <Self::Left as Header>::Data<'source>,
        (right_note_id, right_nf, right_anchor): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_note_id != right_note_id {
            return Err(mock_ragu::Error);
        }
        if !left_anchor.0.is_epoch_final() {
            return Err(mock_ragu::Error);
        }
        if right_anchor.0.epoch().0 != left_anchor.0.epoch().0 + 1 {
            return Err(mock_ragu::Error);
        }

        if right_pool.0.commit() != right_anchor.1.0 {
            return Err(mock_ragu::Error);
        }

        let seed = epoch_seed_hash(&left_anchor.1);
        if right_pool.0.query(seed) != Fp::ZERO {
            return Err(mock_ragu::Error);
        }

        Ok(((right_note_id, right_nf, right_anchor), ()))
    }
}
