//! Semantic headers for qr steps.
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
        epoch::EpochIndexGadget,
        profile::{QrDiscriminantGadget, QrProfileGadget},
        sets::TachygramSetCommitGadget,
    },
    primitives::{Anchor, EpochIndex, QrDiscriminant, QrProfile, TachygramSetCommit},
};
/// Tachygrams under routing. Every member of `contents` takes `profile`, and
/// a split classifies at `discriminant.at(profile.depth)`. A builder keeps its
/// intake headers unpublished until the epoch closes.
#[derive(Clone, Debug)]
pub struct QrIntake;

output_gadget!(QrIntakeOutput, "QrIntakeOutput(..)", {
    epoch: EpochIndexGadget,
    anchor_prev: AnchorGadget,
    anchor_end: AnchorGadget,
    discriminant: QrDiscriminantGadget,
    profile: QrProfileGadget,
    contents: TachygramSetCommitGadget,
});

impl Header for QrIntake {
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
    );
    type Output = Kind![Fp; QrIntakeOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(4);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        data: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(QrIntakeOutput {
            epoch: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.0)),
            )?
            .into(),
            anchor_prev: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.1)),
            )?
            .into(),
            anchor_end: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.2)),
            )?
            .into(),
            discriminant: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.3)),
            )?
            .into(),
            profile: QrProfileGadget {
                depth: Element::alloc(
                    dr,
                    allocator,
                    data.as_ref()
                        .map(|fields| Fp::from(u64::from(fields.4.depth))),
                )?,
                bits: Element::alloc(
                    dr,
                    allocator,
                    data.as_ref()
                        .map(|fields| Fp::from(u64::from(fields.4.bits))),
                )?,
            },
            contents: HostCommitment::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Eq::from(fields.5).to_affine()),
            )?
            .into(),
        })
    }
}

/// One intake's members partitioned at its discriminant. Extracting either
/// side attests the other.
#[derive(Clone, Debug)]
pub struct QrIntakeSides;

output_gadget!(QrIntakeSidesOutput, "QrIntakeSidesOutput(..)", {
    epoch: EpochIndexGadget,
    anchor_prev: AnchorGadget,
    anchor_end: AnchorGadget,
    discriminant: QrDiscriminantGadget,
    profile: QrProfileGadget,
    non_residue: TachygramSetCommitGadget,
    residue: TachygramSetCommitGadget,
});

impl Header for QrIntakeSides {
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
        TachygramSetCommit,
    );
    type Output = Kind![Fp; QrIntakeSidesOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        data: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(QrIntakeSidesOutput {
            epoch: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.0)),
            )?
            .into(),
            anchor_prev: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.1)),
            )?
            .into(),
            anchor_end: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.2)),
            )?
            .into(),
            discriminant: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.3)),
            )?
            .into(),
            profile: QrProfileGadget {
                depth: Element::alloc(
                    dr,
                    allocator,
                    data.as_ref()
                        .map(|fields| Fp::from(u64::from(fields.4.depth))),
                )?,
                bits: Element::alloc(
                    dr,
                    allocator,
                    data.as_ref()
                        .map(|fields| Fp::from(u64::from(fields.4.bits))),
                )?,
            },
            non_residue: HostCommitment::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Eq::from(fields.5).to_affine()),
            )?
            .into(),
            residue: HostCommitment::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Eq::from(fields.6).to_affine()),
            )?
            .into(),
        })
    }
}

/// One profile's members over a whole epoch.
///
/// The bucket covers `[anchor_start, anchor_next)`. Both bounds are boundary
/// digests. The range excludes `anchor_next`. In a bucket that a
/// consensus-accepted spend uses, `anchor_start` is the entry anchor of `epoch`
/// and `anchor_next` is the entry anchor of `epoch + 1`. [`QrBucketSeal`]
/// computes `anchor_next` from the intake's `anchor_end`.
#[derive(Clone, Debug)]
pub struct QrBucket;

output_gadget!(QrBucketOutput, "QrBucketOutput(..)", {
    epoch: EpochIndexGadget,
    anchor_start: AnchorGadget,
    anchor_next: AnchorGadget,
    discriminant: QrDiscriminantGadget,
    profile: QrProfileGadget,
    contents: TachygramSetCommitGadget,
});

impl Header for QrBucket {
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
    );
    type Output = Kind![Fp; QrBucketOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        data: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(QrBucketOutput {
            epoch: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.0)),
            )?
            .into(),
            anchor_start: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.1)),
            )?
            .into(),
            anchor_next: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.2)),
            )?
            .into(),
            discriminant: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.3)),
            )?
            .into(),
            profile: QrProfileGadget {
                depth: Element::alloc(
                    dr,
                    allocator,
                    data.as_ref()
                        .map(|fields| Fp::from(u64::from(fields.4.depth))),
                )?,
                bits: Element::alloc(
                    dr,
                    allocator,
                    data.as_ref()
                        .map(|fields| Fp::from(u64::from(fields.4.bits))),
                )?,
            },
            contents: HostCommitment::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Eq::from(fields.5).to_affine()),
            )?
            .into(),
        })
    }
}
