//! Semantic headers for evidence steps.
use ragu::{Header, Suffix, pasta::Fp};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe as _,
};
use ragu_primitives::{Element, allocator::Allocator};

use crate::{
    gadgets::{
        anchor::AnchorGadget, epoch::EpochIndexGadget, evidence::EvidenceTreeRootGadget,
        profile::QrDiscriminantGadget,
    },
    primitives::{Anchor, EpochIndex, EvidenceTreeRoot, QrDiscriminant},
};
/// A Poseidon Merkle root over one network's sealed buckets.
///
/// Every leaf under `root` is the [`poseidon::evidence_tree_leaf`] of a bucket
/// whose own `(epoch, anchor_start, anchor_next, discriminant)` are the four
/// this header carries. A one-leaf tree's root is that leaf's digest, and
/// [`EvidenceTreeDescend`] is what produces one.
///
/// The tree claims nothing about which buckets it holds. A tree holding one
/// bucket four times is as valid as a tree over a whole network, and a builder
/// that omits a bucket can only fail to answer for it. Each bucket's exclusion
/// claim already covers the whole epoch.
#[derive(Clone, Debug)]
pub struct EvidenceTree;

output_gadget!(EvidenceTreeOutput, "EvidenceTreeOutput(..)", {
    epoch: EpochIndexGadget,
    anchor_start: AnchorGadget,
    anchor_next: AnchorGadget,
    discriminant: QrDiscriminantGadget,
    root: EvidenceTreeRootGadget,
});

impl Header for EvidenceTree {
    type Data = (EpochIndex, Anchor, Anchor, QrDiscriminant, EvidenceTreeRoot);
    type Output = Kind![Fp; EvidenceTreeOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        data: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(EvidenceTreeOutput {
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
            root: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.4)),
            )?
            .into(),
        })
    }
}

/// Two sibling subtree roots of one network: half of a node.
///
/// A [`EVIDENCE_TREE_ARITY`]-child node reaches one hash through two steps,
/// since a [`Step`] takes at most two predecessor proofs. This header is a node
/// half-assembled: the left and right children of one side, under the four
/// network fields both already agree on.
#[derive(Clone, Debug)]
pub struct EvidenceTreePair;

output_gadget!(EvidenceTreePairOutput, "EvidenceTreePairOutput(..)", {
    epoch: EpochIndexGadget,
    anchor_start: AnchorGadget,
    anchor_next: AnchorGadget,
    discriminant: QrDiscriminantGadget,
    first: EvidenceTreeRootGadget,
    second: EvidenceTreeRootGadget,
});

impl Header for EvidenceTreePair {
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        EvidenceTreeRoot,
        EvidenceTreeRoot,
    );
    type Output = Kind![Fp; EvidenceTreePairOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(13);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        data: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(EvidenceTreePairOutput {
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
            first: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.4)),
            )?
            .into(),
            second: Element::alloc(
                dr,
                allocator,
                data.as_ref().map(|fields| Fp::from(fields.5)),
            )?
            .into(),
        })
    }
}
