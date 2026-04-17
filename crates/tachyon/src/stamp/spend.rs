//! Spend nullifier and action-binding headers and steps.
#![expect(
    clippy::module_name_repetitions,
    reason = "header/step names are intentional"
)]

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::delegation::NullifierHeader;
use crate::{
    entropy::ActionRandomizer,
    keys::ProofAuthorizingKey,
    note::{Note, Nullifier},
    primitives::{ActionDigest, Epoch, NoteId, effect},
    value,
};

/// Marker type for PCD headers carrying spend nullifier data.
#[derive(Debug)]
pub struct SpendNullifierHeader;

impl Header for SpendNullifierHeader {
    // (nf0, nf1, epoch, note_id)
    type Data<'source> = (Nullifier, Nullifier, Epoch, NoteId);

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 2 + 4 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        #[expect(clippy::little_endian_bytes, reason = "specified encoding")]
        out.extend_from_slice(&data.2.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
        out
    }
}

/// Marker type for PCD headers carrying spend data.
#[derive(Debug)]
pub struct SpendHeader;

impl Header for SpendHeader {
    // (action_digest, nullifiers, epoch, note_id)
    type Data<'source> = (Fp, [Nullifier; 2], Epoch, NoteId);

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 * 2 + 4 + 32);
        out.extend_from_slice(&data.0.to_repr());
        out.extend_from_slice(&Fp::from(data.1[0]).to_repr());
        out.extend_from_slice(&Fp::from(data.1[1]).to_repr());
        #[expect(clippy::little_endian_bytes, reason = "specified encoding")]
        out.extend_from_slice(&data.2.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
        out
    }
}

/// Derives two nullifiers (epoch E and E+1) via full GGM walk.
#[derive(Debug)]
pub struct SpendNullifier;

impl Step for SpendNullifier {
    type Aux<'source> = ();
    type Left = ();
    type Output = SpendNullifierHeader;
    type Right = ();
    type Witness<'source> = (Note, ProofAuthorizingKey, Epoch);

    const INDEX: Index = Index::new(3);

    fn witness<'source>(
        &self,
        (note, pak, target_epoch): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(mock_ragu::Error);
        }

        let note_id = note.id(pak.nk());
        let nf0 = note.nullifier(pak.nk(), target_epoch);
        let nf1 = note.nullifier(pak.nk(), Epoch(target_epoch.0 + 1));

        Ok(((nf0, nf1, target_epoch, note_id), ()))
    }
}

/// Fuses two NullifierHeaders (epoch E and E+1) into a SpendNullifierHeader.
/// Alternative to SpendNullifierSeed -- reuses sync service NullifierHeaders.
#[derive(Debug)]
pub struct SpendNullifierFuse;

impl Step for SpendNullifierFuse {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendNullifierHeader;
    type Right = NullifierHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(19);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_nf, left_epoch, left_note_id): <Self::Left as Header>::Data<'source>,
        (right_nf, right_epoch, right_note_id): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_note_id != right_note_id {
            return Err(mock_ragu::Error);
        }
        if right_epoch.0 != left_epoch.0 + 1 {
            return Err(mock_ragu::Error);
        }

        Ok(((left_nf, right_nf, left_epoch, left_note_id), ()))
    }
}

/// Binds nullifiers to action data with note_id verification.
#[derive(Debug)]
pub struct SpendBind;

impl Step for SpendBind {
    type Aux<'source> = ();
    type Left = SpendNullifierHeader;
    type Output = SpendHeader;
    type Right = ();
    type Witness<'source> = (
        value::CommitmentTrapdoor,
        ActionRandomizer<effect::Spend>,
        ProofAuthorizingKey,
        Note,
    );

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        (rcv, alpha, pak, note): Self::Witness<'source>,
        (nf0, nf1, epoch, left_note_id): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(mock_ragu::Error);
        }

        let note_id = note.id(pak.nk());
        if note_id != left_note_id {
            return Err(mock_ragu::Error);
        }

        let cv = rcv.commit(i64::from(note.value));
        let rk = pak.ak().derive_action_public(&alpha);
        let action_digest = ActionDigest::new(cv, rk).map_err(|_err| mock_ragu::Error)?;

        Ok((
            (Fp::from(action_digest), [nf0, nf1], epoch, left_note_id),
            (),
        ))
    }
}
