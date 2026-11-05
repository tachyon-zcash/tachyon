//! Output tachygram-binding header and step.

extern crate alloc;
use ragu::{Encoded, Header, Index, Oracles, Step, pasta::Pasta};
use ragu_core::{
    drivers::{Driver, DriverValue},
    maybe::Maybe as _,
};

pub use crate::stamp::headers::output::OutputHeader;
use crate::{
    Tachygram, constants::MAX_MONEY, digest::poseidon, note::Note, pasta::Fp,
    ragu_constraint::enforce_nonzero, value,
};

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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let (note, rcv) = witness.take();
            if u64::from(note.value) > MAX_MONEY {
                return Err(ragu_core::Error::InvalidWitness(
                    "OutputBind: note value exceeds maximum".into(),
                ));
            }

            let (cm, pad) = {
                let (rcm, pk, value, psi) = (
                    Fp::from(note.rcm),
                    Fp::from(note.pk),
                    u64::from(note.value),
                    Fp::from(note.psi),
                );
                (
                    Tachygram::from(poseidon::note_commitment(rcm, pk, value, psi)),
                    Tachygram::from(poseidon::pad_tachygram(rcm, pk, value, psi)),
                )
            };

            // Two zero tachygrams collide whatever they were meant to be, and a
            // zero root leaves the accumulator factor `(X - tg)` trivial.
            enforce_nonzero(Fp::from(cm), "OutputBind: note commitment is zero")?;
            enforce_nonzero(Fp::from(pad), "OutputBind: padding tachygram is zero")?;

            Ok(((cm, pad, rcv.commit(-note.value)), ()))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}
