//! Spendable status headers and steps.
#![expect(
    clippy::module_name_repetitions,
    reason = "header/step names are intentional"
)]

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::{delegation::NullifierHeader, pool::PoolHeader};
use crate::{
    keys::NullifierKey,
    note::{Note, Nullifier},
    primitives::{Anchor, NoteId},
};

/// Marker type for PCD headers carrying spendable state.
#[derive(Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    // (note_id, nf, anchor)
    type Data<'source> = (NoteId, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(&(note_id, nf, anchor): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 2 + 4 + 32 * 4);
        out.extend_from_slice(&Fp::from(note_id).to_repr());
        out.extend_from_slice(&Fp::from(nf).to_repr());
        #[expect(clippy::little_endian_bytes, reason = "specified encoding")]
        out.extend_from_slice(&u32::from(anchor.block_height).to_le_bytes());
        out.extend_from_slice(&Fp::from(anchor.block_commit).to_repr());
        out.extend_from_slice(&Fp::from(anchor.pool_commit).to_repr());
        out.extend_from_slice(&Fp::from(anchor.block_chain).to_repr());
        out.extend_from_slice(&Fp::from(anchor.epoch_chain).to_repr());
        out
    }
}

/// Marker type for PCD headers carrying rollover state.
#[derive(Debug)]
pub struct SpendableRolloverHeader;

impl Header for SpendableRolloverHeader {
    // (note_id, nf, anchor)
    type Data<'source> = (NoteId, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(&(note_id, nf, anchor): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 2 + 4 + 32 * 4);
        out.extend_from_slice(&Fp::from(note_id).to_repr());
        out.extend_from_slice(&Fp::from(nf).to_repr());
        #[expect(clippy::little_endian_bytes, reason = "specified encoding")]
        out.extend_from_slice(&u32::from(anchor.block_height).to_le_bytes());
        out.extend_from_slice(&Fp::from(anchor.block_commit).to_repr());
        out.extend_from_slice(&Fp::from(anchor.pool_commit).to_repr());
        out.extend_from_slice(&Fp::from(anchor.block_chain).to_repr());
        out.extend_from_slice(&Fp::from(anchor.epoch_chain).to_repr());
        out
    }
}

/// Proves cm inclusion and bootstraps spendable status.
// TODO: inclusion_witness, non_membership_witness (requires pool accumulator)
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableHeader;
    type Right = PoolHeader;
    type Witness<'source> = (Note, NullifierKey);

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        (note, nk): Self::Witness<'source>,
        (nf, left_epoch, left_note_id): <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let note_id = note.id(&nk);

        if note_id != left_note_id {
            return Err(mock_ragu::Error);
        }
        if left_epoch != right.block_height.epoch() {
            return Err(mock_ragu::Error);
        }

        // TODO: inclusion_verify(cm, inclusion_witness, right.block_commit)
        todo!("inclusion verification against block_commit");

        // TODO: select which accumulator to use: pool_commit covers the full
        // epoch so far; but block_commit should also work (narrower scope, but
        // sufficient since the note was just created).
        todo!("non-membership verification against pool or block");

        Ok(((left_note_id, nf, right), ()))
    }
}

/// Bootstraps a fresh non-membership proof for a new epoch.
// TODO: non_membership_witness (requires pool accumulator)
#[derive(Debug)]
pub struct SpendableRollover;

impl Step for SpendableRollover {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableRolloverHeader;
    type Right = PoolHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (nf, left_epoch, left_note_id): <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_epoch != right.block_height.epoch() {
            return Err(mock_ragu::Error);
        }

        // TODO: non_membership_verify(nf, right.pool_commit, witness)
        todo!("non-membership verification against pool_commit");

        Ok(((left_note_id, nf, right), ()))
    }
}

/// Advances spendable status to a later block within the same epoch.
// TODO: delta_commit, non_membership_witness, intermediate_block_commits
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = PoolHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(16);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (note_id, nf, left_anchor): <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if right.block_height <= left_anchor.block_height {
            return Err(mock_ragu::Error);
        }
        if right.block_height.epoch() != left_anchor.block_height.epoch() {
            return Err(mock_ragu::Error);
        }
        if left_anchor.epoch_chain != right.epoch_chain {
            return Err(mock_ragu::Error);
        }

        // TODO: left_anchor.pool_commit + delta_commit == right.pool_commit
        todo!("pool_commit state diff verification");

        // TODO: block_chain continuity from left to right
        todo!("block_chain continuity verification");

        // TODO: non_membership_verify(nf, delta_commit, non_membership_witness)
        todo!("non-membership verification against delta_commit");

        Ok((
            (
                note_id,
                nf,
                Anchor {
                    epoch_chain: left_anchor.epoch_chain,
                    ..right
                },
            ),
            (),
        ))
    }
}

/// Epoch transition: fuses epoch-final spendable with rollover.
#[derive(Debug)]
pub struct SpendableEpochLift;

impl Step for SpendableEpochLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = SpendableRolloverHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(17);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_note_id, _left_nf, left_anchor): <Self::Left as Header>::Data<'source>,
        (right_note_id, right_nf, right): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_note_id != right_note_id {
            return Err(mock_ragu::Error);
        }
        if !left_anchor.block_height.is_epoch_final() {
            return Err(mock_ragu::Error);
        }
        if right.block_height.epoch().0 != left_anchor.block_height.epoch().0 + 1 {
            return Err(mock_ragu::Error);
        }

        let expected = left_anchor.epoch_chain.chain(left_anchor.pool_commit);
        if right.epoch_chain != expected {
            return Err(mock_ragu::Error);
        }

        Ok(((right_note_id, right_nf, right), ()))
    }
}
