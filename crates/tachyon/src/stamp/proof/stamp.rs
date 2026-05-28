//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use alloc::vec::Vec;

use mock_ragu::{Header, Index, Step, Suffix};

use super::{pool::AnchorChain, spend::SpendHeader, spendable::SpendableHeader};
use crate::{
    ActionSetGadget, TachygramSetGadget,
    constants::NOTE_VALUE_MAX,
    entropy::ActionRandomizer,
    keys::private,
    note::Note,
    primitives::{ActionDigest, ActionSetCommit, Anchor, Tachygram, TachygramSetCommit, effect},
    value,
};

/// Header for a stamp, representing either a single action or many
/// transactions.
///
/// `action_commit` and `stamp_tg_commit` are Pedersen commitments to
/// the action-digest and tachygram sets. Each producing step computes
/// them from the actions and tachygrams the step witnesses.
///
/// `anchor` is freely witnessed at [`OutputStamp`]; at [`SpendStamp`]
/// it threads from the right [`SpendableHeader`]; at [`MergeStamp`]
/// the step constrains `left.anchor == right.anchor`; at
/// [`StampLift`] it advances to the right [`AnchorChain`] segment's
/// `end` after constraining `segment.start == old_anchor`.
#[derive(Debug)]
pub struct StampHeader;

impl Header for StampHeader {
    /// `(action_commit, stamp_tg_commit, anchor)`. The two commitments
    /// are computed at each producing step from the actions and
    /// tachygrams that step witnesses. `anchor` is freely witnessed at
    /// [`OutputStamp`], threaded from the right [`SpendableHeader`] at
    /// [`SpendStamp`], equality-constrained at [`MergeStamp`], or
    /// advanced over an [`AnchorChain`] at [`StampLift`].
    type Data<'source> = (ActionSetCommit, TachygramSetCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        todo!("commitment encoding seems incorrect");
        let mut out = Vec::with_capacity(32 + 32 + 32);
        let action_bytes: [u8; 32] = data.0.0.into();
        let tachygram_bytes: [u8; 32] = data.1.0.into();
        let anchor_bytes: [u8; 32] = data.2.0.into();
        out.extend_from_slice(&action_bytes);
        out.extend_from_slice(&tachygram_bytes);
        out.extend_from_slice(&anchor_bytes);
        out
    }
}

/// Derives commitment, proves action, stamps an output.
#[derive(Debug)]
pub struct OutputStamp;

impl Step for OutputStamp {
    type Aux<'source> = ();
    type Left = ();
    type Output = StampHeader;
    type Right = ();
    type Witness<'source> = (
        value::CommitmentTrapdoor,
        ActionRandomizer<effect::Output>,
        Note,
        Anchor,
    );

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        (rcv, alpha, note, anchor): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if u64::from(note.value) == 0 {
            return Err(mock_ragu::Error("OutputStamp: zero-value note"));
        }
        if u64::from(note.value) > NOTE_VALUE_MAX {
            return Err(mock_ragu::Error("OutputStamp: note value exceeds maximum"));
        }
        let cv = rcv.commit(-i64::from(note.value));
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        let action_digest = ActionDigest::new(cv, rk)
            .map_err(|_err| mock_ragu::Error("OutputStamp: action digest construction failed"))?;
        let tachygram = Tachygram::from(note.commitment());

        let data = (
            ActionSetCommit::from([action_digest].as_slice()),
            TachygramSetCommit::from([tachygram].as_slice()),
            anchor,
        );
        Ok((data, ()))
    }
}

/// Fuses a [`SpendHeader`] with a [`SpendableHeader`] into a stamp.
///
/// The spend's first nullifier must equal the spendable's `nf`;
/// anchor-binding is implicit via `spendable.anchor` (already validated by
/// the spendable lineage). Epoch alignment is consumer-side.
///
/// `SpendStamp` derives `action_digest = Poseidon(cv, rk)` from the
/// `(cv, rk)` carried in `SpendHeader` before constructing the
/// `ActionSetCommit`.
#[derive(Debug)]
pub struct SpendStamp;

impl Step for SpendStamp {
    type Aux<'source> = ();
    type Left = SpendHeader;
    type Output = StampHeader;
    type Right = SpendableHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(20);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (cv, rk, (now_nf, next_nf)): <Self::Left as Header>::Data<'source>,
        (anchored_nf, anchor): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if now_nf != anchored_nf {
            return Err(mock_ragu::Error(
                "SpendStamp: spend's now_nf must equal spendable's nf",
            ));
        }

        let action_digest = ActionDigest::new(cv, rk)
            .map_err(|_err| mock_ragu::Error("SpendStamp: action digest construction failed"))?;

        let data = (
            ActionSetCommit::from([action_digest].as_slice()),
            TachygramSetCommit::from(
                [Tachygram::from(now_nf), Tachygram::from(next_nf)].as_slice(),
            ),
            anchor,
        );
        Ok((data, ()))
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
        ActionSetGadget,
        ActionSetGadget,
        TachygramSetGadget,
        TachygramSetGadget,
    );

    const INDEX: Index = Index::new(21);

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
        // Same-anchor constraint.
        if left_anchor != right_anchor {
            return Err(mock_ragu::Error("MergeStamp: anchors must match"));
        }

        // Bind witness accumulators to the public commitments on Data.
        if left_action.0.commit() != left_action_commit.0
            || right_action.0.commit() != right_action_commit.0
            || left_tachygram.0.commit() != left_tachygram_commit.0
            || right_tachygram.0.commit() != right_tachygram_commit.0
        {
            return Err(mock_ragu::Error(
                "MergeStamp: witness accumulators must commit to header commits",
            ));
        }

        let merged_action = ActionSetGadget(left_action.0.merge(&right_action.0));
        let merged_tachygram = TachygramSetGadget(left_tachygram.0.merge(&right_tachygram.0));

        let data = (
            ActionSetCommit::from(merged_action),
            TachygramSetCommit::from(merged_tachygram),
            left_anchor,
        );
        Ok((data, ()))
    }
}

/// Advance a stamp's anchor by absorbing an [`AnchorChain`]: the
/// segment's `start` must equal the stamp's `old_anchor`, and the new
/// anchor is the segment's `end`.
#[derive(Debug)]
pub struct StampLift;

impl Step for StampLift {
    type Aux<'source> = ();
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = AnchorChain;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(22);

    fn witness<'source>(
        &self,
        (): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, old_anchor): <Self::Left as Header>::Data<
            'source,
        >,
        (segment_start, segment_end): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // The anchor segment must root at the stamp's old anchor.
        if segment_start != old_anchor {
            return Err(mock_ragu::Error(
                "StampLift: segment start must equal stamp old_anchor",
            ));
        }

        let data = (left_action_commit, left_tachygram_commit, segment_end);
        Ok((data, ()))
    }
}
