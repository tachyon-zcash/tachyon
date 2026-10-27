//! Semantic headers for stamp steps.
use ragu::{
    Header, Suffix,
    pasta::{Eq, Fp},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe as _,
};
use ragu_primitives::{Element, allocator::Allocator};
use udon::curve::Projective as _;

use crate::{
    gadgets::{
        anchor::AnchorGadget,
        commitment::HostCommitment,
        sets::{ActionSetCommitGadget, TachygramSetCommitGadget},
    },
    primitives::{ActionSetCommit, Anchor, TachygramSetCommit},
};
/// Non-empty proven action content with no fee in its lineage.
///
/// `action_commit` and `stamp_tg_commit` are Pedersen commitments to
/// the action-digest and tachygram sets. Each leaf step
/// ([`OutputAction`](crate::stamp::proof::stamp::OutputAction),
/// [`SpendAction`](crate::stamp::proof::stamp::SpendAction)) witnesses both set
/// polynomials and enforces them against their roots at a Fiat-Shamir
/// challenge. The action set is enforced against the action the step derives,
/// the tachygram set against the pair bound on the left bind header.
/// [`ActionMerge`](crate::stamp::proof::stamp::ActionMerge) binds its witnessed
/// input sets to the child headers and enforces each output commitment as the
/// product of its inputs.
///
/// `anchor` is a free witness at
/// [`OutputAction`](crate::stamp::proof::stamp::OutputAction). At
/// [`SpendAction`](crate::stamp::proof::stamp::SpendAction) it comes
/// from the left [`SpendHeader`](crate::stamp::headers::spend::SpendHeader). At
/// [`ActionMerge`](crate::stamp::proof::stamp::ActionMerge) the step requires
/// `left.anchor == right.anchor`. At
/// [`ActionLift`](crate::stamp::proof::stamp::ActionLift) the step checks that
/// `anchor` is the right
/// [`AnchorSpan`](crate::stamp::headers::pool::AnchorSpan)'s `anchor_start` or
/// a member, and moves it to the span's `anchor_end`.
#[derive(Debug)]
pub struct Actions;

output_gadget!(ActionsOutput, "ActionsOutput(..)", {
    anchor: AnchorGadget,
    action_commit: ActionSetCommitGadget,
    stamp_tg_commit: TachygramSetCommitGadget,
});

impl Header for Actions {
    type Data = (ActionSetCommit, TachygramSetCommit, Anchor);
    type Output = Kind![Fp; ActionsOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(15);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(ActionsOutput {
            anchor: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?
            .into(),
            action_commit: HostCommitment::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Eq::from(fields.0).to_affine()),
            )?
            .into(),
            stamp_tg_commit: HostCommitment::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Eq::from(fields.1).to_affine()),
            )?
            .into(),
        })
    }
}

/// Header for one or more fee-bearing lineages.
///
/// `action_commit` and `stamp_tg_commit` are Pedersen commitments to
/// the action-digest and tachygram sets.
/// [`StampMerge`](crate::stamp::proof::stamp::StampMerge) binds its witnessed
/// input sets to the child headers and enforces each output commitment as the
/// product of its inputs.
///
/// [`FeeFuse`](crate::stamp::proof::stamp::FeeFuse) multiplies each set
/// polynomial by a fee singleton set polynomial.
/// [`FeeSeed`](crate::stamp::proof::stamp::FeeSeed) directly produces a stamp
/// with fee singleton sets.
///
/// `anchor` is a free witness at
/// [`FeeSeed`](crate::stamp::proof::stamp::FeeSeed). At
/// [`FeeFuse`](crate::stamp::proof::stamp::FeeFuse) it comes from
/// the left [`Actions`]. At
/// [`StampMerge`](crate::stamp::proof::stamp::StampMerge) the step requires
/// `left.anchor == right.anchor`. At
/// [`StampLift`](crate::stamp::proof::stamp::StampLift) the step checks that
/// `stamp.anchor` is the right
/// [`AnchorSpan`](crate::stamp::headers::pool::AnchorSpan)'s `anchor_start` or
/// a member, and moves it to the span's `anchor_end`.
#[derive(Debug)]
pub struct Stamp;

output_gadget!(StampOutput, "StampOutput(..)", {
    anchor: AnchorGadget,
    action_commit: ActionSetCommitGadget,
    stamp_tg_commit: TachygramSetCommitGadget,
});

impl Header for Stamp {
    type Data = (ActionSetCommit, TachygramSetCommit, Anchor);
    type Output = Kind![Fp; StampOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(StampOutput {
            anchor: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?
            .into(),
            action_commit: HostCommitment::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Eq::from(fields.0).to_affine()),
            )?
            .into(),
            stamp_tg_commit: HostCommitment::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Eq::from(fields.1).to_affine()),
            )?
            .into(),
        })
    }
}
