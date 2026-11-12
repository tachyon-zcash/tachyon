//! Output tachygram-binding header and step.

extern crate alloc;

use ragu::{
    header::{Header, Suffix},
    step::{Encoded, Index, Oracles, Step},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::Pasta,
};
use ragu_primitives::{Element, Point, allocator::Allocator, io::Write};
use udon::curve::EndomorphismAffine;

use crate::{
    Tachygram,
    constants::MAX_MONEY,
    digest::poseidon,
    gadgets::{self, fixed_base},
    note::Note,
    pasta::{EpAffine, Fp, Fq},
    value,
};

/// Header binding an output's tachygram pair and value to one note
/// (wallet-only).
///
/// Carries the note commitment `cm`, the padding tachygram `pad`, and the
/// value commitment `cv`, all derived from the same note. `rk` is produced
/// downstream at [`OutputAction`](super::stamp::OutputAction).
#[derive(Debug)]
pub struct OutputHeader;

#[derive(Gadget, Write)]
pub struct OutputHeaderOutput<'dr, D: Driver<'dr>, C: EndomorphismAffine<Base = D::F>> {
    pub cm: Element<'dr, D>,
    pub pad: Element<'dr, D>,
    #[ragu(gadget)]
    pub cv: Point<'dr, D, C>,
}

impl Header<Fp> for OutputHeader {
    /// `(cm, pad, cv)`
    type Data = (Tachygram, Tachygram, value::Commitment);
    type Output = Kind![Fp; OutputHeaderOutput<'_, _, EpAffine>];

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
            )?,
            pad: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            cv: Point::alloc(dr, witness.as_ref().map(|fields| EpAffine::from(fields.2)))?,
        })
    }
}

/// Derives an output's tachygram pair from one note, and commits its negated
/// value as
/// $\mathsf{cv} = \[-v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}$.
///
/// Two permutations (`cm`, `pad`) and two scalar multiplications (`cv`).
#[derive(Debug)]
pub struct OutputBind;

impl Step<Pasta> for OutputBind {
    type Aux<'source> = ();
    type Left = ();
    type Output = OutputHeader;
    type Right = ();
    /// `(note, rcv)`.
    type Witness<'source> = (Note, value::Trapdoor);

    const INDEX: Index = Index::new(6);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left)?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let amount = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|data| Fp::from(u64::from(data.0.value))),
        )?;
        // With the 51-bit decomposition `mul_bounded` makes of the amount, this
        // bounds the amount by MAX_MONEY.
        let bound = Element::constant(dr, Fp::from(MAX_MONEY));
        let slack = bound.sub(dr, &amount);
        gadgets::range::enforce_width::<D, 51>(dr, &slack)?;
        let rcm = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.rcm)),
        )?;
        let pk = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.pk)),
        )?;
        let psi = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.psi)),
        )?;
        let cm = poseidon::circuit::note_commitment(dr, &rcm, &pk, &amount, &psi)?;
        let pad = poseidon::circuit::pad_tachygram(dr, &rcm, &pk, &amount, &psi)?;
        // Two zero tachygrams collide whatever they were meant to be, and a
        // zero root leaves the set polynomial factor `(X - tg)` trivial.
        cm.clone().enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("OutputBind: note commitment is zero".into())
        })?;
        pad.clone().enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("OutputBind: padding tachygram is zero".into())
        })?;
        let blind_point =
            fixed_base::R_TABLE.mul_free(dr, &witness.as_ref().map(|data| Fq::from(data.1)))?;
        let cv = fixed_base::NEG_V_TABLE.mul_bounded(dr, &amount, &blind_point)?;
        let output = D::just(|| {
            (
                Tachygram::from(*cm.value().take()),
                Tachygram::from(*pad.value().take()),
                value::Commitment::from(cv.value().take()),
            )
        });
        let fields = OutputHeaderOutput { cm, pad, cv };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}
