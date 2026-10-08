//! Output tachygram-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use crate::{
    Tachygram, constants::MAX_MONEY, digest::poseidon, note::Note,
    ragu_constraint::enforce_nonzero, value,
};

/// Header binding an output's tachygram pair and value to one note
/// (wallet-only).
///
/// Carries the note commitment `cm`, the padding tachygram `pad`, and the
/// value commitment `cv`, all derived from the same note. `rk` is produced
/// downstream at [`OutputStamp`](super::stamp::OutputStamp).
#[derive(Debug)]
pub struct OutputHeader;

impl Header for OutputHeader {
    /// `(cm, pad, cv)`
    type Data = (Tachygram, Tachygram, value::Commitment);

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, pad, cv) = *data;
        (
            vec![Fp::from(cm), Fp::from(pad)],
            Vec::new(),
            vec![Ep::from(cv)],
            Vec::new(),
        )
    }
}

/// Derives an output's tachygram pair from one note, and commits its negated
/// value as
/// $\mathsf{cv} = \[-v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}$.
///
/// Four permutations (`cm`, `pad`) and two scalar multiplications (`cv`).
#[derive(Debug)]
pub struct OutputBind;

impl Step for OutputBind {
    type Aux<'source> = ();
    type Left = ();
    type Output = OutputHeader;
    type Right = ();
    /// `(note, rcv)`.
    type Witness<'source> = (Note, value::Trapdoor);

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note, rcv): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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
    }
}
