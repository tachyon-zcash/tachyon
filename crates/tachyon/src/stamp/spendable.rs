//! Spendable status headers and steps.
//!
//! - [`SpendableInit`]: bootstraps spendable status at note creation (user).
//! - [`SpendableLift`]: within-epoch advancement via exclusion proof.
//! - [`SpendableRollover`]: epoch-transition via exclusion proof.
//! - [`SpendableEpochLift`]: fuses epoch-final spendable with rollover.
//!
//! `SpendableLift` and `SpendableRollover` consume binding headers from the
//! exclusion module (`SpendableExclusionHeader`, `NullifierExclusionHeader`).
//! They are witness-free — all non-membership verification happens in the
//! exclusion proof sub-tree.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::{
    block::BlockHeader,
    delegation::NullifierHeader,
    exclusion::{NullifierExclusionHeader, SpendableExclusionHeader},
    pool::PoolHeader,
};
use crate::{
    SetCommit,
    keys::NullifierKey,
    note::{Note, Nullifier},
    primitives::{Anchor, NoteId, Tachygram, polynomial},
};

/// Marker type for PCD headers carrying spendable state.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    // (note_id, nf, anchor)
    type Data<'source> = (NoteId, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(&(note_id, nf, anchor): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 2 + 4 + 32 * 4);
        out.extend_from_slice(&Fp::from(note_id).to_repr());
        out.extend_from_slice(&Fp::from(nf).to_repr());
        out.extend_from_slice(&anchor.encode_for_header());
        out
    }
}

/// Marker type for PCD headers carrying rollover state.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct SpendableRolloverHeader;

impl Header for SpendableRolloverHeader {
    // (note_id, nf, anchor)
    type Data<'source> = (NoteId, Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(&(note_id, nf, anchor): &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 2 + 4 + 32 * 4);
        out.extend_from_slice(&Fp::from(note_id).to_repr());
        out.extend_from_slice(&Fp::from(nf).to_repr());
        out.extend_from_slice(&anchor.encode_for_header());
        out
    }
}

/// Bootstraps spendable status from a creation block.
///
/// Left: `NullifierHeader` (nf + note_id + epoch from delegation chain).
/// Right: `BlockHeader(sum_others, anchor)` from the sibling-sub-block merge
/// tree bound via [`BlockBindPool`](super::block::BlockBindPool). `sum_others`
/// is the Pedersen-committed sum of every sub-block *except* the cm's,
/// PCD-attested by the merge tree. `anchor` comes from the pool chain (which
/// consensus produces via [`PoolStep`](super::pool::PoolStep)).
///
/// Witness: note, nk, the cm sub-block, and cm_index within it.
///
/// Verifies:
/// - `note_id == H(mk, cm)`
/// - epoch matches `anchor.block_height.epoch()`
/// - `pedersen(poly_from_roots(sub_block)) + sum_others == anchor.block_commit`
///   — closes the decomposition loop. Because `sum_others` is PCD-attested (not
///   a witness), the equation uniquely pins `sub_commit` to `block_commit −
///   sum_others`, and Pedersen binding forces the witness sub-block to be the
///   real cm sub-block.
/// - `cm ∈ sub_block` at `cm_index`
///
/// No exclusion check: consensus prevents simultaneous creation and spend,
/// and downstream lifts verify non-membership at every advance.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct SpendableInit<const N: usize>;

impl<const N: usize> Step for SpendableInit<N> {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableHeader;
    type Right = BlockHeader;
    type Witness<'source> = (Note, NullifierKey, &'source [Tachygram; N], usize);

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        (note, nk, sub_block, cm_index): Self::Witness<'source>,
        (nf, left_epoch, left_note_id): <Self::Left as Header>::Data<'source>,
        (sum_others, anchor): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let note_id = note.id(&nk);
        if note_id != left_note_id {
            return Err(mock_ragu::Error);
        }
        if left_epoch != anchor.block_height.epoch() {
            return Err(mock_ragu::Error);
        }

        // Close the block-commit decomposition: cm's sub-block commit plus
        // the PCD-attested sum of all other sub-blocks must equal the
        // pool-attested block_commit. Pedersen binding forces the witness
        // sub-block to be the real cm sub-block.
        let roots: Vec<Fp> = sub_block.iter().map(|tg| Fp::from(*tg)).collect();
        let coeffs = polynomial::poly_from_roots(&roots);
        let sub_commit = SetCommit::from(polynomial::pedersen_commit(&coeffs));
        if sub_commit + sum_others != anchor.block_commit.0 {
            return Err(mock_ragu::Error);
        }

        // cm inclusion at the specified index within the sub-block
        let cm = note.commitment();
        let cm_tg = Tachygram::from(Fp::from(cm));
        if sub_block.get(cm_index).is_none_or(|tg| *tg != cm_tg) {
            return Err(mock_ragu::Error);
        }

        Ok(((left_note_id, nf, anchor), ()))
    }
}

/// Advances spendable status to a later block within the same epoch.
///
/// Left: SpendableExclusionHeader (spendable + exclusion proof covering
/// the delta). Right: PoolHeader (later block, same epoch).
///
/// Witness-free. Checks:
/// - `right.block_height > left.anchor.block_height`
/// - Same epoch, same `epoch_chain`
/// - `left.anchor.pool_commit + left.scope == right.pool_commit` (subset/delta:
///   exclusion proof covers exactly the tachygrams added since the previous
///   anchor)
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableExclusionHeader;
    type Output = SpendableHeader;
    type Right = PoolHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(16);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (note_id, nf, left_anchor, scope): <Self::Left as Header>::Data<'source>,
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

        // Delta-scope exclusion: old_pool + scope == new_pool.
        if left_anchor.pool_commit.0 + scope != right.pool_commit.0 {
            return Err(mock_ragu::Error);
        }

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

/// Bootstraps a fresh exclusion proof for a new epoch.
///
/// Left: NullifierExclusionHeader (nullifier + exclusion proof covering
/// pool_commit). Right: PoolHeader (any block in the new epoch).
///
/// Witness-free. Checks:
/// - epoch match
/// - `scope == right.pool_commit` (full-epoch coverage)
///
/// note_id is PCD-attested from the delegation chain (DelegationSeed).
/// Re-verification is not possible here because the sync service does
/// not have the note or nullifier key.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct SpendableRollover;

impl Step for SpendableRollover {
    type Aux<'source> = ();
    type Left = NullifierExclusionHeader;
    type Output = SpendableRolloverHeader;
    type Right = PoolHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (nf, left_epoch, left_note_id, scope): <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_epoch != right.block_height.epoch() {
            return Err(mock_ragu::Error);
        }

        // Pool-scope exclusion: scope must equal pool_commit.
        if scope != right.pool_commit.0 {
            return Err(mock_ragu::Error);
        }

        Ok(((left_note_id, nf, right), ()))
    }
}

/// Epoch transition: fuses epoch-final spendable with rollover.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
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

        if right.epoch_chain != left_anchor.epoch_chain.chain(left_anchor.pool_commit) {
            return Err(mock_ragu::Error);
        }

        Ok(((right_note_id, right_nf, right), ()))
    }
}
