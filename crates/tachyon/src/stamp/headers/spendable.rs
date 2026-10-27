//! Semantic headers for spendable steps.
use ragu::{Header, Suffix};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Kind},
    maybe::Maybe as _,
};
use ragu_primitives::{Element, allocator::Allocator};
use udon::field::Fp;

use crate::{
    gadgets::{anchor::AnchorGadget, epoch::EpochIndexGadget, note::NoteCommitmentGadget},
    note, pasta,
    primitives::{Anchor, EpochIndex},
};
/// Wallet's spendable position, certified up to this point in every
/// coordinate.
///
/// `cm` keeps the spent value from drifting to a different same-`mk` note.
#[derive(Clone, Debug)]
pub struct NoteSpendable;

output_gadget!(NoteSpendableOutput, "NoteSpendableOutput(..)", {
    cm: NoteCommitmentGadget,
    epoch_current: EpochIndexGadget,
    anchor: AnchorGadget,
});

impl Header for NoteSpendable {
    type Data = (note::Commitment, EpochIndex, Anchor);
    type Output = Kind![pasta::Fp; NoteSpendableOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode<'dr, D: Driver<'dr, F = pasta::Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteSpendableOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Fp::from(fields.0).into_loose().into()),
            )?
            .into(),
            epoch_current: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Fp::from(fields.1).into_loose().into()),
            )?
            .into(),
            anchor: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Fp::from(fields.2).into_loose().into()),
            )?
            .into(),
        })
    }
}
