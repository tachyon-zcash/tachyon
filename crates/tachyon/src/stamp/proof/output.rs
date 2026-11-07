//! Output tachygram-binding header and step.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ragu::{Header, Index, Step, Suffix};

use super::{
    super::super::{
        Tachygram,
        digest::poseidon,
        note::Note,
        pasta::{Ep, Eq, Fp, Fq},
        ragu_constraint::enforce_nonzero,
        value,
    },
    scale::{self, R, ScaleResult},
};

/// Header binding an output's tachygram pair and value to one note
/// (wallet-only).
///
/// Carries the note commitment `cm`, the padding tachygram `pad`, and the
/// value commitment `cv`, all derived from the same note. `rk` is produced
/// downstream at [`OutputAction`](super::stamp::OutputAction).
#[derive(Debug)]
pub struct OutputHeader;

impl Header for OutputHeader {
    /// `(cm, pad, cv)`
    type Data = (Tachygram, Tachygram, value::Commitment);

    const SUFFIX: Suffix = Suffix::new(7);

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
/// Consumes the private R certificate. Two permutations and 17 value windows;
/// no polynomials.
#[derive(Debug)]
pub struct OutputBind;

impl Step for OutputBind {
    type Aux<'source> = ();
    type Left = ScaleResult<R>;
    type Output = OutputHeader;
    type Right = ();
    /// `(note)`
    type Witness<'source> = (Note,);

    const INDEX: Index = Index::new(6);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (note,): Self::Witness<'source>,
        (_lo, _hi, point, identity): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let value_product = scale::value_product::<true>(note.value)?;
        let cv = scale::finite(value_product + scale::decode(point, identity)?)?;

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

        Ok(((cm, pad, value::Commitment::from(cv)), ()))
    }
}
