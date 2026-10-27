//! Semantic headers for output steps.
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
    gadgets::{point::CurvePoint, tachygram::TachygramGadget, value::ValueCommitmentGadget},
    primitives::Tachygram,
    value,
};
/// Header binding an output's tachygram pair and value to one note
/// (wallet-only).
///
/// Carries the note commitment `cm`, the padding tachygram `pad`, and the
/// value commitment `cv`, all derived from the same note. `rk` is produced
/// downstream at
/// [`OutputAction`](crate::stamp::proof::stamp::OutputAction).
#[derive(Debug)]
pub struct OutputHeader;

output_gadget!(OutputHeaderOutput, "OutputHeaderOutput(..)", {
    cm: TachygramGadget,
    pad: TachygramGadget,
    cv: ValueCommitmentGadget,
});

impl Header for OutputHeader {
    type Data = (Tachygram, Tachygram, value::Commitment);
    type Output = Kind![Fp; OutputHeaderOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(OutputHeaderOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?
            .into(),
            pad: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?
            .into(),
            cv: CurvePoint::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| EpAffine::from(fields.2)),
            )?
            .into(),
        })
    }
}
