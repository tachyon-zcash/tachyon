//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use alloc::vec::Vec;

use ff::PrimeField as _;
use pasta_curves::Fp;
use ragu::{Commitment, Header, Index, Polynomial, Step, StepCtx, Suffix, enforce_poly_product};

use super::{pool::AnchorChain, spend::SpendHeader};
use crate::{
    ActionSetPoly, TachygramSetPoly,
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
/// it threads from the left [`SpendHeader`]; at [`MergeStamp`]
/// the step constrains `left.anchor == right.anchor`; at
/// [`StampLift`] it advances to the right [`AnchorChain`] segment's
/// `end` after constraining `segment.start == old_anchor`.
#[derive(Debug)]
pub struct StampHeader;

impl Header for StampHeader {
    /// `(action_commit, stamp_tg_commit, anchor)`. The two commitments
    /// are computed at each producing step from the actions and
    /// tachygrams that step witnesses. `anchor` is freely witnessed at
    /// [`OutputStamp`], threaded from the left [`SpendHeader`] at
    /// [`SpendStamp`], equality-constrained at [`MergeStamp`], or
    /// advanced over an [`AnchorChain`] at [`StampLift`].
    type Data = (ActionSetCommit, TachygramSetCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 3);
        let action_bytes: [u8; 32] = Commitment::from(data.0).into();
        let tachygram_bytes: [u8; 32] = Commitment::from(data.1).into();
        out.extend_from_slice(&action_bytes);
        out.extend_from_slice(&tachygram_bytes);
        out.extend_from_slice(&Fp::from(data.2).to_repr());
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

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        (rcv, alpha, note, anchor): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if u64::from(note.value) == 0 {
            return Err(ragu::Error("OutputStamp: zero-value note"));
        }
        if u64::from(note.value) > NOTE_VALUE_MAX {
            return Err(ragu::Error("OutputStamp: note value exceeds maximum"));
        }
        let cv = rcv.commit(-i64::from(note.value));
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        let action_digest = ActionDigest::new(cv, rk)
            .map_err(|_err| ragu::Error("OutputStamp: action digest construction failed"))?;
        let tachygram = Tachygram::from(note.commitment());

        let data = (
            ActionSetCommit::from([action_digest].as_slice()),
            TachygramSetCommit::from([tachygram].as_slice()),
            anchor,
        );
        Ok((data, ()))
    }
}

/// Turns a [`SpendHeader`] into a stamp.
///
/// The spend's nullifier pair and pool anchor arrive together on the
/// [`SpendHeader`]. [`SpendBind`](super::spend::SpendBind) already joined the
/// spendable into the spend lineage (its `Left` is the `SpendableHeader`), so
/// there is no separate spendable input here. Anchor-binding is implicit via
/// the threaded `anchor` (validated by the spendable lineage that fed the
/// spend).
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
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (cv, rk, (now_nf, next_nf), anchor): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let action_digest = ActionDigest::new(cv, rk)
            .map_err(|_err| ragu::Error("SpendStamp: action digest construction failed"))?;

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
        ActionSetPoly,
        ActionSetPoly,
        TachygramSetPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        ctx: &mut StepCtx<'_>,
        (left_action, right_action, left_tachygram, right_tachygram): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, left_anchor): <Self::Left as Header>::Data,
        (right_action_commit, right_tachygram_commit, right_anchor): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Same-anchor constraint.
        if left_anchor != right_anchor {
            return Err(ragu::Error("MergeStamp: anchors must match"));
        }

        // Bind witness accumulators to the public commitments on Data.
        if left_action.commit() != left_action_commit
            || right_action.commit() != right_action_commit
            || left_tachygram.commit() != left_tachygram_commit
            || right_tachygram.commit() != right_tachygram_commit
        {
            return Err(ragu::Error(
                "MergeStamp: witness accumulators must commit to header commits",
            ));
        }

        // Merge each set via the product relation: the union is the product of
        // the two root polynomials. The prover constructs the union
        // out-of-circuit; `enforce_poly_product` confirms it against the
        // committed inputs.
        let merged_action_poly = {
            let left_poly = Polynomial::from(left_action);
            let right_poly = Polynomial::from(right_action);
            let merged_poly = left_poly.multiply(&right_poly);
            enforce_poly_product(ctx, &left_poly, &right_poly, &merged_poly)?;
            merged_poly
        };

        let merged_tachygram_poly = {
            let left_poly = Polynomial::from(left_tachygram);
            let right_poly = Polynomial::from(right_tachygram);
            let merged_poly = left_poly.multiply(&right_poly);
            enforce_poly_product(ctx, &left_poly, &right_poly, &merged_poly)?;
            merged_poly
        };

        let data = (
            ActionSetCommit::from(merged_action_poly.commit()),
            TachygramSetCommit::from(merged_tachygram_poly.commit()),
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

    const INDEX: Index = Index::new(13);

    fn witness<'source>(
        &self,
        _ctx: &mut StepCtx<'_>,
        (): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, old_anchor): <Self::Left as Header>::Data,
        (segment_start, segment_end): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // The anchor segment must root at the stamp's old anchor.
        if segment_start != old_anchor {
            return Err(ragu::Error(
                "StampLift: segment start must equal stamp old_anchor",
            ));
        }

        let data = (left_action_commit, left_tachygram_commit, segment_end);
        Ok((data, ()))
    }
}
