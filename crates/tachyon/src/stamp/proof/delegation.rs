//! GGM delegation headers and steps.
//!
//! Two phases:
//!
//! 1. **Pre-blind** descent from the note master key down to some prefix key.
//!    Headers carry `(mk, cm)` lineage (no delegation identifier). Steps:
//!    [`NoteSeedStep`] → [`NoteMasterStep`] → [`NoteStep`] (recursive).
//! 2. **Post-blind** phase after [`DelegationBlindStep`] attaches a fresh
//!    `DelegationTrapdoor` to the `(mk, cm)` lineage, producing a
//!    [`DelegationHeader`]. Further descent uses [`DelegationStep`];
//!    [`NullifierStep`] emits a [`NullifierHeader`] at the leaf.
//!
//! Splitting the chain lets wallets cache pre-blind spine proofs (note-bound,
//! trap-independent) and reuse them across delegations by swapping in a fresh
//! `DelegationBlindStep` per delegation event.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
// TODO(#39): replace halo2_poseidon with Ragu Poseidon params
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use crate::{
    constants::{DELEGATION_ID_DOMAIN, GGM_TREE_DEPTH},
    keys::{ARITY, NoteMasterKey, NotePrefixedKey, ProofAuthorizingKey},
    note::{self, Note, Nullifier},
    primitives::{DelegationId, DelegationTrapdoor, EpochIndex},
};

// ── Pre-blind headers ──────────────────────────────────────────────────────

/// Pre-blind header for the note master key.
///
/// Carries the `(mk, cm)` lineage established at [`NoteSeedStep`]. No
/// delegation identifier — blinding happens later.
#[derive(Clone, Debug)]
pub struct NoteMasterHeader;

impl Header for NoteMasterHeader {
    type Data<'source> = (NoteMasterKey, note::Commitment);

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(&(mk, cm): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&mk.0.to_repr());
        out.extend_from_slice(&Fp::from(&cm).to_repr());
        out
    }
}

/// Pre-blind header for a GGM descendant at depth ≥ 1.
///
/// Lineage `(mk, cm)` is threaded unchanged through [`NoteMasterStep`] and
/// [`NoteStep`] so that [`DelegationBlindStep`] can derive the delegation
/// identifier from any depth.
#[derive(Clone, Debug)]
pub struct NoteStepHeader;

impl Header for NoteStepHeader {
    type Data<'source> = (NotePrefixedKey, NoteMasterKey, note::Commitment);

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(&(key, mk, cm): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 4 + 32 + 32);
        out.extend_from_slice(&key.inner.to_repr());
        out.extend_from_slice(&key.depth.get().to_le_bytes());
        out.extend_from_slice(&key.index.to_le_bytes());
        out.extend_from_slice(&mk.0.to_repr());
        out.extend_from_slice(&Fp::from(&cm).to_repr());
        out
    }
}

// ── Post-blind headers ─────────────────────────────────────────────────────

/// Post-blind header for a delegated prefix key at depth ≥ 1.
///
/// Emitted by [`DelegationBlindStep`] and threaded through [`DelegationStep`]
/// for post-blind descent toward a nullifier leaf.
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

// ── Pre-blind steps ────────────────────────────────────────────────────────

/// Seeds the GGM tree root from `(note, pak)`.
///
/// Verifies note ownership (`pak.derive_payment_key() == note.pk`), that the
/// note is well-formed (non-zero value), and emits the `(mk, cm)` lineage.
#[derive(Debug)]
pub struct NoteSeedStep;

impl Step for NoteSeedStep {
    type Aux<'source> = ();
    type Left = ();
    type Output = NoteMasterHeader;
    type Right = ();
    type Witness<'source> = (Note, ProofAuthorizingKey);

    const INDEX: Index = Index::new(0);

    fn witness<'source>(
        &self,
        (note, pak): Self::Witness<'source>,
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
        let cm = note.commitment();
        Ok(((mk, cm), ()))
    }
}

/// First GGM step: master → depth-1 prefix.
#[derive(Debug)]
pub struct NoteMasterStep;

impl Step for NoteMasterStep {
    type Aux<'source> = ();
    type Left = NoteMasterHeader;
    type Output = NoteStepHeader;
    type Right = ();
    type Witness<'source> = (u8,);

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        (chunk,): Self::Witness<'source>,
        (mk, cm): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if chunk >= ARITY {
            return Err(mock_ragu::Error);
        }
        Ok(((mk.step(chunk), mk, cm), ()))
    }
}

/// Recursive pre-blind GGM step.
#[derive(Debug)]
pub struct NoteStep;

impl Step for NoteStep {
    type Aux<'source> = ();
    type Left = NoteStepHeader;
    type Output = NoteStepHeader;
    type Right = ();
    type Witness<'source> = (u8,);

    const INDEX: Index = Index::new(3);

    fn witness<'source>(
        &self,
        (chunk,): Self::Witness<'source>,
        (key, mk, cm): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if key.depth.get() >= GGM_TREE_DEPTH {
            return Err(mock_ragu::Error);
        }
        if chunk >= ARITY {
            return Err(mock_ragu::Error);
        }
        Ok(((key.step(chunk), mk, cm), ()))
    }
}

// ── Blinding ────────────────────────────────────────────────────────────────

/// Attach a delegation identifier to a pre-blind prefix.
///
/// Consumes a [`NoteStepHeader`] carrying `(mk, cm)` lineage and a witnessed
/// [`DelegationTrapdoor`]; emits a [`DelegationHeader`] with
/// `delegation_id = Poseidon(domain, mk, cm, trap)`.
#[derive(Debug)]
pub struct DelegationBlindStep;

impl Step for DelegationBlindStep {
    type Aux<'source> = ();
    type Left = NoteStepHeader;
    type Output = DelegationHeader;
    type Right = ();
    type Witness<'source> = (DelegationTrapdoor,);

    const INDEX: Index = Index::new(13);

    fn witness<'source>(
        &self,
        (trap,): Self::Witness<'source>,
        (key, mk, cm): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let domain = Fp::from_u128(u128::from_le_bytes(*DELEGATION_ID_DOMAIN));
        let delegation_id = DelegationId::from(
            &Hash::<_, P128Pow5T3, ConstantLength<4>, 3, 2>::init().hash([
                domain,
                mk.0,
                Fp::from(&cm),
                Fp::from(&trap),
            ]),
        );
        Ok(((key, delegation_id), ()))
    }
}

// ── Post-blind steps ───────────────────────────────────────────────────────

/// Recursive post-blind GGM step.
#[derive(Debug)]
pub struct DelegationStep;

impl Step for DelegationStep {
    type Aux<'source> = ();
    type Left = DelegationHeader;
    type Output = DelegationHeader;
    type Right = ();
    type Witness<'source> = (u8,);

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        (chunk,): Self::Witness<'source>,
        (key, delegation_id): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if key.depth.get() >= GGM_TREE_DEPTH {
            return Err(mock_ragu::Error);
        }
        if chunk >= ARITY {
            return Err(mock_ragu::Error);
        }
        Ok(((key.step(chunk), delegation_id), ()))
    }
}

/// Final GGM step: post-blind leaf key becomes nullifier.
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
