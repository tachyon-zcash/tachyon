//! GGM delegation headers and steps.
//!
//! Two phases:
//!
//! 1. **Pre-blind** descent from the note master key down to some prefix key.
//!    Headers carry `(mk, cm)` lineage (no delegation identifier). Steps:
//!    [`NfMasterSeed`] → [`NfMasterStep`] → [`NfPrefixStep`] (recursive). The
//!    leaf is reached via [`NullifierStep`] which propagates `cm` onto a
//!    pre-blind [`NullifierHeader`].
//! 2. **Post-blind** phase after [`DelegationStep`] attaches a fresh
//!    `DelegationTrapdoor` to the `(mk, cm)` lineage, producing a
//!    [`DelegateNfPrefixHeader`]. Further descent uses
//!    [`DelegateNfPrefixStep`]; [`DelegateNullifierStep`] emits a
//!    [`DelegateNullifierHeader`] at the leaf.
//!
//! Splitting the chain lets wallets cache pre-blind spine proofs (note-bound,
//! trap-independent) and reuse them across delegations by swapping in a fresh
//! `DelegationStep` per delegation event. The pre-blind leaf is the
//! user-device path that retains `cm` for stamp-binding via cm-equality at
//! `SpendBind` and pool-membership at `SpendableInit`; the post-blind leaf is
//! the sync-service path that carries `delegation_id` for the cross-epoch
//! `SpendableRollover`.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use crate::{
    constants::NOTE_VALUE_MAX,
    digest::poseidon,
    keys::{GGM_TREE_ARITY, GGM_TREE_DEPTH, NoteMasterKey, NotePrefixedKey, ProofAuthorizingKey},
    note::{self, Note, Nullifier},
    primitives::{DelegationId, DelegationTrapdoor, EpochIndex, Tachygram},
};

/// Pre-blind header for the note master key.
///
/// Carries the `(mk, cm)` lineage established at [`NfMasterSeed`]. No
/// delegation identifier — blinding happens later.
#[derive(Clone, Debug)]
pub struct NfMasterHeader;

impl Header for NfMasterHeader {
    type Data<'source> = (NoteMasterKey, note::Commitment);

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(&(mk, cm): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&mk.0.to_repr());
        out.extend_from_slice(&Fp::from(cm).to_repr());
        out
    }
}

/// Pre-blind header for a GGM descendant at depth ≥ 1.
///
/// Lineage `(mk, cm)` is threaded unchanged through [`NfMasterStep`] and
/// [`NfPrefixStep`] so that [`DelegationStep`] can derive the delegation
/// identifier from any depth.
#[derive(Clone, Debug)]
pub struct NfPrefixHeader;

impl Header for NfPrefixHeader {
    type Data<'source> = (NotePrefixedKey, NoteMasterKey, note::Commitment);

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode(&(key, mk, cm): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 4 + 32 + 32);
        out.extend_from_slice(&key.inner.to_repr());
        out.extend_from_slice(&key.depth.get().to_le_bytes());
        out.extend_from_slice(&key.index.to_le_bytes());
        out.extend_from_slice(&mk.0.to_repr());
        out.extend_from_slice(&Fp::from(cm).to_repr());
        out
    }
}

/// Pre-blind GGM-leaf header.
///
/// Carries `(cm, nf, epoch)` — the wallet's private GGM-leaf state. `cm` is
/// available to downstream steps (`SpendBind`, `SpendableInit`) to bind
/// witnessed `Note` / pool-membership checks without a separate witness
/// re-derivation. User device only — `cm` is private.
#[derive(Clone, Debug)]
pub struct NullifierHeader;

impl Header for NullifierHeader {
    /// `(cm, nf, epoch)`.
    type Data<'source> = (Tachygram, Nullifier, EpochIndex);

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 4);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&data.2.0.to_le_bytes());
        out
    }
}

/// Post-blind header for a delegated prefix key at depth ≥ 1.
///
/// Emitted by [`DelegationStep`] and threaded through
/// [`DelegateNfPrefixStep`] for post-blind descent toward a nullifier leaf.
#[derive(Clone, Debug)]
pub struct DelegateNfPrefixHeader;

impl Header for DelegateNfPrefixHeader {
    type Data<'source> = (NotePrefixedKey, DelegationId);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(&(key, id): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 4 + 32);
        out.extend_from_slice(&key.inner.to_repr());
        out.extend_from_slice(&key.depth.get().to_le_bytes());
        out.extend_from_slice(&key.index.to_le_bytes());
        out.extend_from_slice(&id.0.to_repr());
        out
    }
}

/// Post-blind GGM-leaf header. Carries `(nf, epoch, delegation_id)` so the
/// sync-service-driven `SpendableRollover` can match same-wallet pairs by
/// `delegation_id`.
#[derive(Clone, Debug)]
pub struct DelegateNullifierHeader;

impl Header for DelegateNullifierHeader {
    /// `(nf, epoch, delegation_id)`.
    type Data<'source> = (Nullifier, EpochIndex, DelegationId);

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&data.1.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out
    }
}

/// Seeds the GGM tree root from `(note, pak)`.
///
/// Verifies note ownership (`pak.derive_payment_key() == note.pk`), that the
/// note is well-formed (non-zero value), and emits the `(mk, cm)` lineage.
#[derive(Debug)]
pub struct NfMasterSeed;

impl Step for NfMasterSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = NfMasterHeader;
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
            return Err(mock_ragu::Error("NfMasterSeed: zero-value note"));
        }
        if u64::from(note.value) > NOTE_VALUE_MAX {
            return Err(mock_ragu::Error("NfMasterSeed: note value exceeds maximum"));
        }
        if note.pk.0 != pak.derive_payment_key().0 {
            return Err(mock_ragu::Error("NfMasterSeed: pak not related to note"));
        }

        let mk = pak.nk.derive_note_private(&note.psi);
        let cm = note.commitment();
        Ok(((mk, cm), ()))
    }
}

/// First GGM step: master → depth-1 prefix.
#[derive(Debug)]
pub struct NfMasterStep;

impl Step for NfMasterStep {
    type Aux<'source> = ();
    type Left = NfMasterHeader;
    type Output = NfPrefixHeader;
    type Right = ();
    type Witness<'source> = (u8,);

    const INDEX: Index = Index::new(1);

    fn witness<'source>(
        &self,
        (chunk,): Self::Witness<'source>,
        (mk, cm): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if chunk >= GGM_TREE_ARITY {
            return Err(mock_ragu::Error("NfMasterStep: chunk exceeds GGM arity"));
        }
        Ok(((mk.step(chunk), mk, cm), ()))
    }
}

/// Recursive pre-blind GGM step.
#[derive(Debug)]
pub struct NfPrefixStep;

impl Step for NfPrefixStep {
    type Aux<'source> = ();
    type Left = NfPrefixHeader;
    type Output = NfPrefixHeader;
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
            return Err(mock_ragu::Error("NfPrefixStep: already at maximum depth"));
        }
        if chunk >= GGM_TREE_ARITY {
            return Err(mock_ragu::Error("NfPrefixStep: chunk exceeds GGM arity"));
        }
        Ok(((key.step(chunk), mk, cm), ()))
    }
}

/// Pre-blind GGM-leaf step.
///
/// Verifies leaf depth, derives `nf` from `key` (matching what
/// [`DelegateNullifierStep`] would derive for the same key), and propagates
/// `cm` from the lineage onto the output header. `mk` is dropped — no
/// consumer of `NullifierHeader` needs it.
#[derive(Debug)]
pub struct NullifierStep;

impl Step for NullifierStep {
    type Aux<'source> = ();
    type Left = NfPrefixHeader;
    type Output = NullifierHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(19);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (key, _mk, cm): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if key.depth.get() != GGM_TREE_DEPTH {
            return Err(mock_ragu::Error("NullifierStep: not at maximum depth"));
        }

        let epoch = EpochIndex(key.index);
        let nf = key.derive_nullifier(epoch);
        let cm_tg = Tachygram::from(cm);
        Ok(((cm_tg, nf, epoch), ()))
    }
}

/// Attach a delegation identifier to a pre-blind prefix.
///
/// Consumes a [`NfPrefixHeader`] carrying `(mk, cm)` lineage and a witnessed
/// [`DelegationTrapdoor`]; emits a [`DelegateNfPrefixHeader`] with
/// `delegation_id = Poseidon(domain, mk, cm, trap)`.
#[derive(Debug)]
pub struct DelegationStep;

impl Step for DelegationStep {
    type Aux<'source> = ();
    type Left = NfPrefixHeader;
    type Output = DelegateNfPrefixHeader;
    type Right = ();
    type Witness<'source> = (DelegationTrapdoor,);

    const INDEX: Index = Index::new(13);

    fn witness<'source>(
        &self,
        (trap,): Self::Witness<'source>,
        (key, mk, cm): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let delegation_id =
            DelegationId::from(poseidon::delegation_id(mk.0, Fp::from(cm), Fp::from(trap)));
        Ok(((key, delegation_id), ()))
    }
}

/// Recursive post-blind GGM step.
#[derive(Debug)]
pub struct DelegateNfPrefixStep;

impl Step for DelegateNfPrefixStep {
    type Aux<'source> = ();
    type Left = DelegateNfPrefixHeader;
    type Output = DelegateNfPrefixHeader;
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
            return Err(mock_ragu::Error(
                "DelegateNfPrefixStep: already at maximum depth",
            ));
        }
        if chunk >= GGM_TREE_ARITY {
            return Err(mock_ragu::Error(
                "DelegateNfPrefixStep: chunk exceeds GGM arity",
            ));
        }
        Ok(((key.step(chunk), delegation_id), ()))
    }
}

/// Post-blind GGM-leaf step. Derives `nf` from `key` and forwards
/// `delegation_id` for the sync-service-driven `SpendableRollover`.
#[derive(Debug)]
pub struct DelegateNullifierStep;

impl Step for DelegateNullifierStep {
    type Aux<'source> = ();
    type Left = DelegateNfPrefixHeader;
    type Output = DelegateNullifierHeader;
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
            return Err(mock_ragu::Error(
                "DelegateNullifierStep: not at maximum depth",
            ));
        }

        let epoch = EpochIndex(key.index);
        let nullifier = key.derive_nullifier(EpochIndex(key.index));

        Ok(((nullifier, epoch, delegation_id), ()))
    }
}
