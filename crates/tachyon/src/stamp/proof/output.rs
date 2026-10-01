//! Output tachygram-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use crate::{Tachygram, digest::poseidon, note::Note, ragu_constraint::enforce_nonzero, value};

/// Header binding an output's tachygram pair and value to one note
/// (wallet-only).
///
/// Carries the note commitment `cm`, the padding tachygram `pad` and the
/// note's `value`, all derived from the same note. The action pair
/// `(cv, rk)` is produced downstream at
/// [`OutputStamp`](super::stamp::OutputStamp).
#[derive(Debug)]
pub struct OutputHeader;

impl Header for OutputHeader {
    /// `(cm, pad, value)`
    type Data = (Tachygram, Tachygram, value::Positive);

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (cm, pad, value) = *data;
        (
            vec![Fp::from(cm), Fp::from(pad), Fp::from(u64::from(value))],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Derives an output's tachygram pair from one note, and carries its value
/// to [`OutputStamp`](super::stamp::OutputStamp).
#[derive(Debug)]
pub struct OutputBind;

impl Step for OutputBind {
    type Aux<'source> = ();
    type Left = ();
    type Output = OutputHeader;
    type Right = ();
    /// `(note,)`.
    type Witness<'source> = (Note,);

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note,): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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

        Ok(((cm, pad, note.value), ()))
    }
}
