//! Semantic headers for spend steps.
use ragu::{
    Header, Suffix,
    pasta::{EpAffine, Fp},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe as _,
};
use ragu_primitives::{Element, allocator::Allocator};

use crate::{
    gadgets::{
        anchor::AnchorGadget, keys::PaymentKeyGadget, note::NoteCommitmentGadget,
        nullifier::NullifierGadget, point::CurvePoint, value::ValueCommitmentGadget,
    },
    keys, note, nullifier,
    primitives::Anchor,
    value,
};
/// Header binding a spend to its lineage note, epoch nullifier pair and value
/// commitment.
///
/// Carries the note commitment `cm`, the lineage's nullifier and its
/// neighbour `(nf_current, nf_next)` derived from the note's master key, the
/// pool `anchor`, the note's payment key `pk` and the value commitment `cv`.
/// [`SpendAction`](crate::stamp::proof::stamp::SpendAction) publishes the pair
/// unordered, ties its `ak` to `pk`, and produces `rk`.
#[derive(Debug)]
pub struct SpendHeader;

output_gadget!(SpendHeaderOutput, "SpendHeaderOutput(..)", {
    cm: NoteCommitmentGadget,
    nf_current: NullifierGadget,
    nf_next: NullifierGadget,
    anchor: AnchorGadget,
    pk: PaymentKeyGadget,
    cv: ValueCommitmentGadget,
});

impl Header for SpendHeader {
    type Data = (
        note::Commitment,
        nullifier::Nullifier,
        nullifier::Nullifier,
        Anchor,
        keys::PaymentKey,
        value::Commitment,
    );
    type Output = Kind![Fp; SpendHeaderOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(SpendHeaderOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?
            .into(),
            nf_current: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?
            .into(),
            nf_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?
            .into(),
            anchor: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.3)),
            )?
            .into(),
            pk: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.4)),
            )?
            .into(),
            cv: CurvePoint::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| EpAffine::from(fields.5)),
            )?
            .into(),
        })
    }
}
