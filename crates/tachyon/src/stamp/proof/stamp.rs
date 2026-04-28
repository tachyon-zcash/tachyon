//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use mock_ragu::{Header, Index, Multiset, Polynomial, Step, Suffix};
use pasta_curves::Fp;

use super::{spend::SpendHeader, spendable::SpendableHeader};
use crate::{
    entropy::ActionRandomizer,
    keys::private,
    note::Note,
    primitives::{
        ActionAcc, ActionCommit, ActionDigest, ActionSet, Anchor, BlockHeight, BlockSet, Tachygram,
        TachygramAcc, TachygramCommit, TachygramSet, effect,
    },
    value,
};

/// Header for a stamp, representing either a single action or many
/// transactions.
///
/// Commitments to the action and tachygram sets should not be published, so
/// they must be reconstructed by validators.
#[derive(Debug)]
pub struct StampHeader;

impl Header for StampHeader {
    /// `(action_commit, tachygram_commit, anchor)` — all 32-byte commitment
    /// handles. Polynomials travel prover-side via `Witness`/`Aux` as
    /// `ActionAcc` / `TachygramAcc`. Per-block pool state travels through
    /// the spendable chain (it isn't on the stamp header).
    type Data<'source> = (ActionCommit, TachygramCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32);
        let action_bytes: [u8; 32] = data.0.0.into();
        let tachygram_bytes: [u8; 32] = data.1.0.into();
        out.extend_from_slice(&action_bytes);
        out.extend_from_slice(&tachygram_bytes);
        let chain_bytes: [u8; 32] = data.2.0.into();
        out.extend_from_slice(&chain_bytes);
        out
    }
}

/// Derives commitment, proves action, stamps an output.
#[derive(Debug)]
pub struct OutputStamp;

impl Step for OutputStamp {
    type Aux<'source> = (ActionAcc, TachygramAcc, Tachygram);
    type Left = ();
    type Output = StampHeader;
    type Right = ();
    type Witness<'source> = (
        value::CommitmentTrapdoor,
        ActionRandomizer<effect::Output>,
        Note,
        Anchor,
    );

    const INDEX: Index = Index::new(2);

    fn witness<'source>(
        &self,
        (rcv, alpha, note, anchor): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if u64::from(note.value) == 0 {
            return Err(mock_ragu::Error);
        }
        let cv = rcv.commit(-i64::from(note.value));
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        let action_digest = ActionDigest::new(cv, rk).map_err(|_err| mock_ragu::Error)?;

        let tachygram = Tachygram::from(&note.commitment());
        let action_acc = ActionAcc::from(&[action_digest][..]);
        let tachygram_acc = TachygramAcc::from(&[tachygram][..]);

        let data = (
            ActionCommit(action_acc.0.commit(Fp::ZERO)),
            TachygramCommit(tachygram_acc.0.commit(Fp::ZERO)),
            anchor,
        );
        Ok((data, (action_acc, tachygram_acc, tachygram)))
    }
}

/// Fuses spend with spendable chain into a stamp.
#[derive(Debug)]
pub struct SpendStamp;

impl Step for SpendStamp {
    type Aux<'source> = (ActionAcc, TachygramAcc);
    type Left = SpendHeader;
    type Output = StampHeader;
    type Right = SpendableHeader;
    /// Witness the right anchor's `prev_anchor` + block set + height, so the
    /// SpendStamp can prove that `epoch == height.epoch()`.
    type Witness<'source> = (Anchor, BlockSet<Multiset>, BlockHeight);

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        (prev_anchor, block, height): Self::Witness<'source>,
        (action_digest, nullifiers, epoch, delegation_id): <Self::Left as Header>::Data<'source>,
        (right_delegation_id, right_nf, right_anchor): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if delegation_id != right_delegation_id {
            return Err(mock_ragu::Error);
        }
        // Spendable must have been lifted to the present epoch E and tracks
        // nf_E; the stamp reveals nf_E (and pre-commits nf_{E+1}).
        if nullifiers[0] != right_nf {
            return Err(mock_ragu::Error);
        }

        // Bind the witnessed prev_anchor + block + height to the right anchor.
        if right_anchor != prev_anchor.next_set(&block, &height) {
            return Err(mock_ragu::Error);
        }
        if epoch != height.epoch() {
            return Err(mock_ragu::Error);
        }

        let action_acc = ActionAcc::from(&[action_digest][..]);
        let tachygram_acc = TachygramSet(Polynomial::from_roots(&[
            Fp::from(&nullifiers[0]),
            Fp::from(&nullifiers[1]),
        ]));

        let data = (
            ActionCommit(action_acc.0.commit(Fp::ZERO)),
            TachygramCommit(tachygram_acc.0.commit(Fp::ZERO)),
            right_anchor,
        );
        Ok((data, (action_acc, tachygram_acc)))
    }
}

/// Universal merge — transaction assembly and aggregation.
#[derive(Debug)]
pub struct MergeStamp;

impl Step for MergeStamp {
    type Aux<'source> = ();
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = StampHeader;
    type Witness<'source> = (
        ActionSet<Multiset>,
        ActionSet<Multiset>,
        TachygramSet<Multiset>,
        TachygramSet<Multiset>,
    );

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        (left_action, right_action, left_tachygram, right_tachygram): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, left_anchor): <Self::Left as Header>::Data<
            'source,
        >,
        (right_action_commit, right_tachygram_commit, right_anchor): <Self::Right as Header>::Data<
            'source,
        >,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Same-anchor constraint: both block_commit and chain hash must match.
        if left_anchor != right_anchor {
            return Err(mock_ragu::Error);
        }

        // Bind witness accumulators to the public commitments on Data.
        if left_action.0.commit() != left_action_commit.0
            || right_action.0.commit() != right_action_commit.0
            || left_tachygram.0.commit() != left_tachygram_commit.0
            || right_tachygram.0.commit() != right_tachygram_commit.0
        {
            return Err(mock_ragu::Error);
        }

        let merged_action = left_action.0.merge(&right_action.0);
        let merged_tachygram = left_tachygram.0.merge(&right_tachygram.0);

        let data = (
            ActionCommit(merged_action.commit()),
            TachygramCommit(merged_tachygram.commit()),
            left_anchor,
        );
        Ok((data, ()))
    }
}

/// Advances a stamp's anchor to the next block within the same epoch via a
/// single hash-chain step. Multi-block lifts chain through PCD recursion.
#[derive(Debug)]
pub struct StampLift;

impl Step for StampLift {
    type Aux<'source> = ();
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = ();
    type Witness<'source> = (
        ActionSet<Multiset>,
        TachygramSet<Multiset>,
        Anchor,
        BlockSet<Multiset>,
        BlockHeight,
        BlockSet<Multiset>,
        BlockHeight,
        Anchor,
    );

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        (
            left_action,
            left_tachygram,
            prev_anchor,
            old_block,
            old_height,
            new_block,
            new_height,
            new_anchor,
        ): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, old_anchor): <Self::Left as Header>::Data<
            'source,
        >,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Bind action/tachygram witnesses to the left header's commitments.
        if left_action.0.commit() != left_action_commit.0
            || left_tachygram.0.commit() != left_tachygram_commit.0
        {
            return Err(mock_ragu::Error);
        }

        // Bind prev_anchor + old_block to old_anchor.
        if old_anchor != prev_anchor.next_set(&old_block, &old_height) {
            return Err(mock_ragu::Error);
        }

        // Single chain step from old anchor to new anchor.
        if new_anchor != old_anchor.next_set(&new_block, &new_height) {
            return Err(mock_ragu::Error);
        }

        // Same epoch, step-by-one. Cross-epoch StampLift is rejected; the
        // stamp must be re-lifted via the spendable epoch path before
        // re-stamping in the new epoch.
        if new_height.0 != old_height.0 + 1 {
            return Err(mock_ragu::Error);
        }
        if new_height.epoch() != old_height.epoch() {
            return Err(mock_ragu::Error);
        }

        let data = (left_action_commit, left_tachygram_commit, new_anchor);
        Ok((data, ()))
    }
}
