//! Output tachygram-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix, constraint::enforce_nonzero};

use crate::{Tachygram, digest::poseidon, note::Note};

/// Header binding an output's tachygram pair to one note.
///
/// Carries the note commitment `cm` and the padding tachygram `pad`, both
/// derived from the same note. The action pair `(cv, rk)` is produced
/// downstream at [`OutputStamp`](super::stamp::OutputStamp).
#[derive(Debug)]
pub struct OutputHeader;

impl Header for OutputHeader {
    /// `(cm, pad)`, the two tachygrams the output publishes.
    type Data = (Tachygram, Tachygram);

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, pad) = *data;
        (
            vec![Fp::from(cm), Fp::from(pad)],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Derives an output's tachygram pair from one note.
///
/// Later, [`super::stamp::OutputStamp`] re-witnesses the note and opens its
/// commitment, which ties the action to this pair.
#[derive(Debug)]
pub struct OutputBind;

impl Step for OutputBind {
    type Aux<'source> = ();
    type Left = ();
    type Output = OutputHeader;
    type Right = ();
    /// `(note,)`.
    type Witness<'source> = (Note,);

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note,): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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

        Ok(((cm, pad), ()))
    }
}
