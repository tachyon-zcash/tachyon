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
/// ([`OutputAction`], [`SpendAction`]) witnesses both set polynomials
/// and enforces them against their roots at a Fiat-Shamir challenge.
/// The action set is enforced against the action the step derives,
/// the tachygram set against the pair bound on the left bind header.
/// [`ActionMerge`] binds its witnessed input sets to the child headers
/// and enforces each output commitment as the product of its inputs.
///
/// `anchor` is a free witness at [`OutputAction`]. At [`SpendAction`] it comes
/// from the left [`SpendHeader`]. At [`ActionMerge`] the step requires
/// `left.anchor == right.anchor`. At [`ActionLift`] the step checks that
/// `anchor` is the right [`AnchorSpan`]'s `anchor_start` or a member, and moves
/// it to the span's `anchor_end`.
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
        data: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(ActionsOutput {
            anchor: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.2)),
            )?
            .into(),
            action_commit: HostCommitment::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Eq::from(fields.0).to_affine()),
            )?
            .into(),
            stamp_tg_commit: HostCommitment::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Eq::from(fields.1).to_affine()),
            )?
            .into(),
        })
    }
}

/// Header for one or more fee-bearing lineages.
///
/// `action_commit` and `stamp_tg_commit` are Pedersen commitments to
/// the action-digest and tachygram sets.
/// [`StampMerge`] binds its witnessed input sets to the child headers
/// and enforces each output commitment as the product of its inputs.
///
/// [`FeeFuse`] multiplies each set polynomial by a fee singleton set
/// polynomial. [`FeeSeed`] directly produces a stamp with fee singleton sets.
///
/// `anchor` is a free witness at [`FeeSeed`]. At [`FeeFuse`] it comes from
/// the left [`Actions`]. At [`StampMerge`] the step requires
/// `left.anchor == right.anchor`. At [`StampLift`] the step checks that
/// `stamp.anchor` is the right [`AnchorSpan`]'s `anchor_start` or a member,
/// and moves it to the span's `anchor_end`.
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
        data: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(StampOutput {
            anchor: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.2)),
            )?
            .into(),
            action_commit: HostCommitment::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Eq::from(fields.0).to_affine()),
            )?
            .into(),
            stamp_tg_commit: HostCommitment::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Eq::from(fields.1).to_affine()),
            )?
            .into(),
        })
    }
}
