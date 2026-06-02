//! GGM walk headers and steps.

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
    primitives::{DelegationId, DelegationTrapdoor, EpochIndex},
};

/// Private header for a master key at depth 0.
///
/// Carries the `(mk, cm)` lineage established at [`NfMasterSeed`]. No
/// delegation identifier — both leaf paths attach below this point.
#[derive(Clone, Debug)]
pub struct NfMasterHeader;

impl Header for NfMasterHeader {
    /// `(mk, cm)`. Both computed at [`NfMasterSeed`] from the
    /// `(note, pak)` witness, which the step constrains via
    /// `note.pk == pak.derive_payment_key()`.
    type Data<'source> = (NoteMasterKey, note::Commitment);

    const SUFFIX: Suffix = Suffix::new(0);

    fn encode(&(mk, cm): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&mk.0.to_repr());
        out.extend_from_slice(&Fp::from(cm).to_repr());
        out
    }
}

/// Private header for a prefix key at depth ≥ 1.
///
/// Lineage `(mk, cm)` is threaded unchanged through [`NfMasterStep`] and
/// [`NfPrefixStep`] so that either leaf path can attach at any depth —
/// [`NullifierStep`] for the user-device leaf, or [`DelegationStep`] for the
/// sync-service leaf.
#[derive(Clone, Debug)]
pub struct NfPrefixHeader;

impl Header for NfPrefixHeader {
    /// `(key, mk, cm)`. `key` advances via [`NfPrefixStep`] from a
    /// parent prefix or [`NfMasterStep`] from `mk`; `mk` and `cm`
    /// thread through unchanged.
    type Data<'source> = (NotePrefixedKey, NoteMasterKey, note::Commitment);

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode(&(key, mk, cm): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 1 + 4 + 32 + 32);
        out.extend_from_slice(&key.inner.to_repr());
        out.extend_from_slice(&key.depth.get().to_le_bytes());
        out.extend_from_slice(&key.index.to_le_bytes());
        out.extend_from_slice(&mk.0.to_repr());
        out.extend_from_slice(&Fp::from(cm).to_repr());
        out
    }
}

/// Private header after nullifier derivation.
///
/// Carries `(cm, nf, epoch)` — the wallet's private GGM-leaf state. `cm` is
/// required at [`SpendableInitRange`](super::spendable::SpendableInitRange) to bind
/// the spendable to the cm-stamp's anchor advance, and at
/// [`SpendBind`](super::spend::SpendBind) to bind the action to the note
/// via `note.commitment() == cm_tg`. User device only — `cm` is private.
#[derive(Clone, Debug)]
pub struct NullifierHeader;

impl Header for NullifierHeader {
    /// `(cm, nf, epoch)`. `nf` and `epoch` are computed at
    /// [`NullifierStep`] from the input [`NfPrefixHeader`]; `cm`
    /// threads through unchanged.
    type Data<'source> = (note::Commitment, Nullifier, EpochIndex);

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 4);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&data.2.0.to_le_bytes());
        out
    }
}

/// Blinded header for a prefix key at depth ≥ 1.
///
/// Replaces the `(mk, cm)` lineage carried by [`NfPrefixHeader`] with a
/// `delegation_id` opaque to the holder. After [`DelegationStep`] there
/// is no way to recover `cm` or `mk` from this header.
#[derive(Clone, Debug)]
pub struct DelegateNfPrefixHeader;

impl Header for DelegateNfPrefixHeader {
    /// `(key, delegation_id)`. Both computed at [`DelegationStep`]
    /// from the left [`NfPrefixHeader`] plus a trapdoor witness;
    /// `delegation_id` is the Poseidon binding of `(mk, cm, trapdoor)`
    /// and supplants the `(mk, cm)` lineage from then on.
    type Data<'source> = (NotePrefixedKey, DelegationId);

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode(&(key, id): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 1 + 4 + 32);
        out.extend_from_slice(&key.inner.to_repr());
        out.extend_from_slice(&key.depth.get().to_le_bytes());
        out.extend_from_slice(&key.index.to_le_bytes());
        out.extend_from_slice(&id.0.to_repr());
        out
    }
}

/// Blinded header after nullifier derivation.
///
/// Sync-service-visible leaf state. Consumed only by
/// [`DelegateRolloverFuse`](super::spendable::DelegateRolloverFuse),
/// which checks lineage equality on `delegation_id`.
#[derive(Clone, Debug)]
pub struct DelegateNullifierHeader;

impl Header for DelegateNullifierHeader {
    /// `(nf, epoch, delegation_id)`. `nf` and `epoch` are computed at
    /// [`DelegateNullifierStep`] from the GGM leaf; `delegation_id`
    /// threads unchanged from [`DelegateNfPrefixHeader`].
    type Data<'source> = (Nullifier, EpochIndex, DelegationId);

    const SUFFIX: Suffix = Suffix::new(4);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&data.1.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out
    }
}

/// Seeds the GGM tree root from `(note, pak)`.
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

/// Recursive private GGM step.
#[derive(Debug)]
pub struct NfPrefixStep;

impl Step for NfPrefixStep {
    type Aux<'source> = ();
    type Left = NfPrefixHeader;
    type Output = NfPrefixHeader;
    type Right = ();
    type Witness<'source> = (u8,);

    const INDEX: Index = Index::new(2);

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

/// Derives a nullifier from a private prefix key.
#[derive(Debug)]
pub struct NullifierStep;

impl Step for NullifierStep {
    type Aux<'source> = ();
    type Left = NfPrefixHeader;
    type Output = NullifierHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(3);

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
        Ok(((cm, nf, epoch), ()))
    }
}

/// Blinds a private prefix key with a delegation trapdoor.
#[derive(Debug)]
pub struct DelegationStep;

impl Step for DelegationStep {
    type Aux<'source> = ();
    type Left = NfPrefixHeader;
    type Output = DelegateNfPrefixHeader;
    type Right = ();
    type Witness<'source> = (DelegationTrapdoor,);

    const INDEX: Index = Index::new(4);

    fn witness<'source>(
        &self,
        (trap,): Self::Witness<'source>,
        (key, mk, cm): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let delegation_id =
            DelegationId::from(poseidon::delegation_id(mk.0, cm.into(), trap.into()));
        Ok(((key, delegation_id), ()))
    }
}

/// Recursive blinded GGM step.
///
/// Each directional chunk in the climb is freely witnessed, rather than bound
/// to some specific target epoch.
///
/// A delegate holding a depth-`d` prefix key holds the cryptographic material
/// to walk to any leaf in the covered subtree, regardless of the proof
/// constraints. Free-chunk descent lets them prove which leaf they walked to;
/// it does not extend the set of leaves they can reach.
#[derive(Debug)]
pub struct DelegateNfPrefixStep;

impl Step for DelegateNfPrefixStep {
    type Aux<'source> = ();
    type Left = DelegateNfPrefixHeader;
    type Output = DelegateNfPrefixHeader;
    type Right = ();
    type Witness<'source> = (u8,);

    const INDEX: Index = Index::new(5);

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

/// Derives a nullifier from a blinded prefix key.
#[derive(Debug)]
pub struct DelegateNullifierStep;

impl Step for DelegateNullifierStep {
    type Aux<'source> = ();
    type Left = DelegateNfPrefixHeader;
    type Output = DelegateNullifierHeader;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(6);

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
