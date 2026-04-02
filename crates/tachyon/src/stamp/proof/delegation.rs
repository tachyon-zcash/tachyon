//! GGM delegation headers and steps.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use crate::{
    keys::{GGM_TREE_DEPTH, NotePrefixedKey, ProofAuthorizingKey},
    note::{Note, Nullifier},
    primitives::{EpochIndex, NoteId},
};

/// Marker type for PCD headers carrying delegation state.
#[derive(Debug)]
pub struct DelegationHeader;

impl Header for DelegationHeader {
    type Data<'source> = (NotePrefixedKey, NoteId);

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(&(key, id): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 4 + 32);
        out.extend_from_slice(&key.inner.to_repr());

        out.extend_from_slice(&key.depth.get().to_le_bytes());

        out.extend_from_slice(&key.index.to_le_bytes());
        out.extend_from_slice(&Fp::from(id).to_repr());
        out
    }
}

/// Marker type for PCD headers carrying nullifier data.
#[derive(Debug)]
pub struct NullifierHeader;

impl Header for NullifierHeader {
    // (nf, epoch, note_id)
    type Data<'source> = (Nullifier, EpochIndex, NoteId);

    const SUFFIX: Suffix = Suffix::new(4);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());

        out.extend_from_slice(&data.1.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out
    }
}

/// First GGM tree step from mk root.
#[derive(Debug)]
pub struct DelegationSeed;

impl Step for DelegationSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = DelegationHeader;
    type Right = ();
    type Witness<'source> = (Note, ProofAuthorizingKey, bool);

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        (note, pak, direction): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(mock_ragu::Error);
        }

        let mk = pak.nk().derive_note_private(&note.psi);
        Ok(((mk.step(direction), note.id(pak.nk())), ()))
    }
}

/// Recursive GGM tree walk step.
#[derive(Debug)]
pub struct DelegationStep;

impl Step for DelegationStep {
    type Aux<'source> = ();
    type Left = DelegationHeader;
    type Output = DelegationHeader;
    type Right = ();
    type Witness<'source> = (bool,);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        (direction,): Self::Witness<'source>,
        (key, note_id): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if key.depth.get() >= GGM_TREE_DEPTH {
            return Err(mock_ragu::Error);
        }

        Ok(((key.step(direction), note_id), ()))
    }
}

/// Final GGM step: leaf key becomes nullifier.
#[derive(Debug)]
pub struct NullifierStep;

impl Step for NullifierStep {
    type Aux<'source> = ();
    type Left = DelegationHeader;
    type Output = NullifierHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (key, note_id): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if key.depth.get() != GGM_TREE_DEPTH {
            return Err(mock_ragu::Error);
        }

        let epoch = EpochIndex(key.index);
        let nullifier = key.derive_nullifier(EpochIndex(key.index));

        Ok(((nullifier, epoch, note_id), ()))
    }
}
