//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use group::{Curve as _, GroupEncoding as _};
use pasta_curves::{Eq, Fp};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Polynomial, Step, Suffix,
    enforce_poly_product,
};

use super::{delegation::NullifierHeader, pool::AnchorChain, spend::SpendHeader};
use crate::{
    ActionSetPoly, TachygramSetPoly,
    constants::NOTE_VALUE_MAX,
    entropy::ActionRandomizer,
    keys::private,
    note::{Note, Nullifier},
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
        let mut out = Vec::with_capacity(32 + 32 + 32);
        let action_bytes: [u8; 32] = Eq::from(data.0).to_affine().to_bytes();
        let tachygram_bytes: [u8; 32] = Eq::from(data.1).to_affine().to_bytes();
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

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
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

/// Composes a [`SpendHeader`] with the live two-leaf [`NullifierHeader`] range
/// and stamps the spend.
///
/// Witnesses `nf_next` and binds the published pair to the note's genuine
/// `GGM(mk, ·)` leaves: consumes the two-leaf range (`range.end == range.start +
/// 2`, `range.cm == cm`) and checks `[present_nf]G_0 + [nf_next]G_1 ==
/// range_commit`.
#[derive(Debug)]
pub struct SpendStamp;

impl Step for SpendStamp {
    type Aux<'source> = ();
    type Left = SpendHeader;
    type Output = StampHeader;
    type Right = NullifierHeader;
    /// `(nf_next,)`.
    type Witness<'source> = (Nullifier,);

    const INDEX: Index = Index::new(16);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (nf_next,): Self::Witness<'source>,
        (cv, rk, present_nf, anchor, cm): <Self::Left as Header>::Data,
        (range_commit, range_start, range_end, range_cm): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if range_end.0 != range_start.0 + 2 {
            return Err(ragu::Error("SpendStamp: live range must span two epochs"));
        }
        if range_cm != cm {
            return Err(ragu::Error("SpendStamp: derived range does not match note"));
        }

        // Bind the published pair to the genuine GGM leaf pair.
        let generators = Pasta::host_generators(Pasta::baked()).g();
        let (Some(g0), Some(g1)) = (generators.first(), generators.get(1)) else {
            return Err(ragu::Error("SpendStamp: insufficient generators"));
        };
        let nf_pair_ref: Eq = *g0 * Fp::from(present_nf) + *g1 * Fp::from(nf_next);
        if Eq::from(range_commit) != nf_pair_ref {
            return Err(ragu::Error(
                "SpendStamp: published scalars are not the derived leaf pair",
            ));
        }

        // A zero nullifier would collide with the note's own cm tachygram.
        if Fp::from(present_nf) == Fp::ZERO {
            return Err(ragu::Error("SpendStamp: present-epoch nullifier is zero"));
        }
        if Fp::from(nf_next) == Fp::ZERO {
            return Err(ragu::Error("SpendStamp: next-epoch nullifier is zero"));
        }

        let action_digest = ActionDigest::new(cv, rk)
            .map_err(|_err| ragu::Error("SpendStamp: action digest construction failed"))?;

        let data = (
            ActionSetCommit::from([action_digest].as_slice()),
            TachygramSetCommit::from(
                [Tachygram::from(present_nf), Tachygram::from(nf_next)].as_slice(),
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
    /// `(left_action, right_action, left_tachygram, right_tachygram)`. The
    /// merged sets are the polynomial products of the witnessed pairs;
    /// [`enforce_poly_product`] pins each union to its
    /// `multiplicand · multiplier`.
    type Witness<'source> = (
        ActionSetPoly,
        ActionSetPoly,
        TachygramSetPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(17);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_action, right_action, left_tachygram, right_tachygram): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, left_anchor): <Self::Left as Header>::Data,
        (right_action_commit, right_tachygram_commit, right_anchor): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Same-anchor constraint.
        if left_anchor != right_anchor {
            return Err(ragu::Error("MergeStamp: anchors must match"));
        }

        // Bind the witnessed input sets to the public commitments on Data.
        if left_action.commit() != left_action_commit
            || right_action.commit() != right_action_commit
            || left_tachygram.commit() != left_tachygram_commit
            || right_tachygram.commit() != right_tachygram_commit
        {
            return Err(ragu::Error(
                "MergeStamp: witness accumulators must commit to header commits",
            ));
        }

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

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
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
