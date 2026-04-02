//! GGM delegation headers and steps.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use crate::{
    keys::{GGM_TREE_DEPTH, NoteMasterKey, NotePrefixedKey, ProofAuthorizingKey},
    note::{Note, Nullifier},
    primitives::{DelegationId, DelegationTrapdoor, EpochIndex},
};

/// Header for the note master key.
#[derive(Clone, Debug)]
pub struct DelegationMasterHeader;

impl Header for DelegationMasterHeader {
    type Data<'source> = (NoteMasterKey, DelegationId);

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(&(mk, id): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&mk.0.to_repr());
        out.extend_from_slice(&Fp::from(&id).to_repr());
        out
    }
}

/// Header for a delegated prefix key at depth ≥ 1.
#[derive(Clone, Debug)]
pub struct DelegationHeader;

impl Header for DelegationHeader {
    type Data<'source> = (NotePrefixedKey, DelegationId);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(&(key, id): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 4 + 32);
        out.extend_from_slice(&key.inner.to_repr());

        out.extend_from_slice(&key.depth.get().to_le_bytes());

        out.extend_from_slice(&key.index.to_le_bytes());
        out.extend_from_slice(&Fp::from(&id).to_repr());
        out
    }
}

/// Header for a proven nullifier derivation at a specific epoch.
#[derive(Clone, Debug)]
pub struct NullifierHeader;

impl Header for NullifierHeader {
    // (nf, epoch, delegation_id)
    type Data<'source> = (Nullifier, EpochIndex, DelegationId);

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 32);
        out.extend_from_slice(&Fp::from(&data.0).to_repr());

        out.extend_from_slice(&data.1.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(&data.2).to_repr());
        out
    }
}

/// Derives the note master key from `(note, pak, trap)`.
///
/// Produces a `DelegationMasterHeader` at depth 0 — the GGM tree root.
/// Does not take a GGM step; stepping is `DelegationMasterStep`'s job.
#[derive(Debug)]
pub struct DelegationSeed;

impl Step for DelegationSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = DelegationMasterHeader;
    type Right = ();
    type Witness<'source> = (Note, ProofAuthorizingKey, DelegationTrapdoor);

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        (note, pak, trap): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if u64::from(note.value) == 0 {
            return Err(mock_ragu::Error);
        }
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(mock_ragu::Error);
        }

        let mk = pak.nk.derive_note_private(&note.psi);
        let delegation_id = pak.nk.derive_delegation_id(&note, trap);
        Ok(((mk, delegation_id), ()))
    }
}

/// First GGM tree step: master → depth-1 prefix.
#[derive(Debug)]
pub struct DelegationMasterStep;

impl Step for DelegationMasterStep {
    type Aux<'source> = ();
    type Left = DelegationMasterHeader;
    type Output = DelegationHeader;
    type Right = ();
    type Witness<'source> = (bool,);

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        (direction,): Self::Witness<'source>,
        (mk, delegation_id): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        Ok(((mk.step(direction), delegation_id), ()))
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

    const INDEX: Index = Index::new(3);

    fn witness<'source>(
        &self,
        (direction,): Self::Witness<'source>,
        (key, delegation_id): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if key.depth.get() >= GGM_TREE_DEPTH {
            return Err(mock_ragu::Error);
        }

        Ok(((key.step(direction), delegation_id), ()))
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

    const INDEX: Index = Index::new(4);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (key, delegation_id): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if key.depth.get() != GGM_TREE_DEPTH {
            return Err(mock_ragu::Error);
        }

        let epoch = EpochIndex(key.index);
        let nullifier = key.derive_nullifier(EpochIndex(key.index));

        Ok(((nullifier, epoch, delegation_id), ()))
    }
}
