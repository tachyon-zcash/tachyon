//! Semantic headers for summary steps.
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
        anchor::AnchorGadget, commitment::HostCommitment, epoch::EpochIndexGadget,
        sets::TachygramSetCommitGadget,
    },
    primitives::{Anchor, EpochIndex, TachygramSetCommit},
};
/// One summarized run of an epoch's stamps.
///
/// `acc_commit` commits the root polynomial of every tachygram in the run,
/// which is exactly the set of stamps folded over the coverage extent
/// `(anchor_prev, anchor_end]`.
#[derive(Clone, Debug)]
pub struct Summary;

output_gadget!(SummaryOutput, "SummaryOutput(..)", {
    epoch: EpochIndexGadget,
    anchor_prev: AnchorGadget,
    anchor_end: AnchorGadget,
    acc_commit: TachygramSetCommitGadget,
});

impl Header for Summary {
    type Data = (EpochIndex, Anchor, Anchor, TachygramSetCommit);
    type Output = Kind![Fp; SummaryOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(SummaryOutput {
            epoch: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?
            .into(),
            anchor_prev: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?
            .into(),
            anchor_end: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?
            .into(),
            acc_commit: HostCommitment::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Eq::from(fields.3).to_affine()),
            )?
            .into(),
        })
    }
}
