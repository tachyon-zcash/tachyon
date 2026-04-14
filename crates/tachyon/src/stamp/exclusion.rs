//! Exclusion proof PCD steps.
//!
//! [`ExclusionHeader`] is produced per-block via a prefix-partitioned
//! coverage tree: bare [`CoverageLeaf`](super::coverage::CoverageLeaf)s
//! plus a single [`ExclusionLeaf`](super::coverage::ExclusionLeaf) at nf's
//! prefix, fused via [`CoverageFuse`](super::coverage::CoverageFuse),
//! finalized by [`ExclusionFinalize`](super::coverage::ExclusionFinalize).
//!
//! [`ExclusionFuse`] aggregates per-block `ExclusionHeader`s into a
//! pool-delta-level `ExclusionHeader`.
//!
//! [`NullifierExclusionFuse`] and [`SpendableExclusionFuse`] bind the final
//! `ExclusionHeader` to the delegation chain or spendable path.

extern crate alloc;

use alloc::vec::Vec;

use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::{EqAffine, Fp};

use super::{delegation::NullifierHeader, spendable::SpendableHeader};
use crate::{
    SetCommit,
    note::Nullifier,
    primitives::{Anchor, Epoch, NoteId},
};

// ---------------------------------------------------------------------------
// ExclusionHeader — proves nf ∉ a set of tachygrams
// ---------------------------------------------------------------------------

/// PCD header proving a nullifier is absent from tachygrams identified by
/// their polynomial commitment `scope`.
#[derive(Debug)]
pub struct ExclusionHeader;

impl Header for ExclusionHeader {
    /// `(nf, scope)`
    type Data<'source> = (Nullifier, SetCommit);

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode(&(nf, scope): &Self::Data<'_>) -> Vec<u8> {
        use ff::PrimeField as _;
        use pasta_curves::group::GroupEncoding as _;
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(nf).to_repr());
        out.extend_from_slice(&EqAffine::from(scope).to_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// ExclusionFuse — cross-block aggregation of per-block exclusion proofs
// ---------------------------------------------------------------------------

/// Merges two `ExclusionHeader`s for the same nullifier by summing their
/// scopes.
///
/// Used to aggregate per-block exclusion proofs (each produced by
/// [`ExclusionFinalize`](super::coverage::ExclusionFinalize)) into a
/// pool-delta-level exclusion proof. Witness-free.
#[derive(Debug)]
pub struct ExclusionFuse;

impl Step for ExclusionFuse {
    type Aux<'source> = ();
    type Left = ExclusionHeader;
    type Output = ExclusionHeader;
    type Right = ExclusionHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(23);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_nf, left_scope): <Self::Left as Header>::Data<'source>,
        (right_nf, right_scope): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_nf != right_nf {
            return Err(mock_ragu::Error);
        }
        let scope = left_scope + right_scope;
        Ok(((left_nf, scope), ()))
    }
}

// ---------------------------------------------------------------------------
// NullifierExclusionHeader / NullifierExclusionFuse
// ---------------------------------------------------------------------------

/// Binds a nullifier (from delegation chain) to its exclusion scope.
/// Consumed by `SpendableRollover`.
#[derive(Debug)]
pub struct NullifierExclusionHeader;

impl Header for NullifierExclusionHeader {
    /// `(nf, epoch, note_id, scope)`
    type Data<'source> = (Nullifier, Epoch, NoteId, SetCommit);

    const SUFFIX: Suffix = Suffix::new(13);

    fn encode(&(nf, epoch, note_id, scope): &Self::Data<'_>) -> Vec<u8> {
        use ff::PrimeField as _;
        use pasta_curves::group::GroupEncoding as _;
        let mut out = Vec::with_capacity(32 + 4 + 32 + 32);
        out.extend_from_slice(&Fp::from(nf).to_repr());
        #[expect(clippy::little_endian_bytes, reason = "specified encoding")]
        out.extend_from_slice(&epoch.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(note_id).to_repr());
        out.extend_from_slice(&EqAffine::from(scope).to_bytes());
        out
    }
}

/// Fuses NullifierHeader with ExclusionHeader. Witness-free.
#[derive(Debug)]
pub struct NullifierExclusionFuse;

impl Step for NullifierExclusionFuse {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = NullifierExclusionHeader;
    type Right = ExclusionHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(24);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_nf, left_epoch, left_note_id): <Self::Left as Header>::Data<'source>,
        (right_nf, right_scope): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_nf != right_nf {
            return Err(mock_ragu::Error);
        }
        Ok(((left_nf, left_epoch, left_note_id, right_scope), ()))
    }
}

// ---------------------------------------------------------------------------
// SpendableExclusionHeader / SpendableExclusionFuse
// ---------------------------------------------------------------------------

/// Binds spendable state to its exclusion scope.
/// Consumed by `SpendableLift`.
#[derive(Debug)]
pub struct SpendableExclusionHeader;

impl Header for SpendableExclusionHeader {
    /// `(note_id, nf, anchor, scope)`
    type Data<'source> = (NoteId, Nullifier, Anchor, SetCommit);

    const SUFFIX: Suffix = Suffix::new(14);

    fn encode(&(note_id, nf, anchor, scope): &Self::Data<'_>) -> Vec<u8> {
        use ff::PrimeField as _;
        use pasta_curves::group::GroupEncoding as _;
        let mut out = Vec::with_capacity(32 + 32 + 4 + 32 * 4 + 32);
        out.extend_from_slice(&Fp::from(note_id).to_repr());
        out.extend_from_slice(&Fp::from(nf).to_repr());
        out.extend_from_slice(&anchor.encode_for_header());
        out.extend_from_slice(&EqAffine::from(scope).to_bytes());
        out
    }
}

/// Fuses SpendableHeader with ExclusionHeader. Witness-free.
#[derive(Debug)]
pub struct SpendableExclusionFuse;

impl Step for SpendableExclusionFuse {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableExclusionHeader;
    type Right = ExclusionHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(25);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_note_id, left_nf, left_anchor): <Self::Left as Header>::Data<'source>,
        (right_nf, right_scope): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_nf != right_nf {
            return Err(mock_ragu::Error);
        }
        Ok(((left_note_id, left_nf, left_anchor, right_scope), ()))
    }
}
