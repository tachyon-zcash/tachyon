//! Tachygram accumulators over consecutive stamps of one epoch.
//!
//! A summary folds each stamp's tachygram set into one set polynomial while
//! the anchor absorbs the same commitments. Consensus forbids republishing a
//! tachygram within two epochs, so the accumulator is square-free. Where a
//! summary starts and stops is prover-chosen: a consumer splices summaries by
//! anchor equality and passes through every stamp link regardless.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use crate::{
    primitives::{Anchor, EpochIndex, TachygramSetCommit, TachygramSetPoly},
    relations::{constraint::enforce_equal_point, enforce::enforce_poly_product},
};

/// One summarized run of an epoch's stamps. `acc_commit` commits the root
/// polynomial of every tachygram in the run; `anchor_prev` and `anchor_last`
/// bracket exactly those stamps' anchor links.
#[derive(Clone, Debug)]
pub struct Summary;

impl Header for Summary {
    /// `(epoch, anchor_prev, anchor_last, acc_commit)`. `anchor_prev` is an
    /// unbound seed witness, as [`AnchorChain`](super::pool::AnchorChain)'s
    /// `start`.
    type Data = (EpochIndex, Anchor, Anchor, TachygramSetCommit);

    const SUFFIX: Suffix = Suffix::new(14);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_prev, anchor_last, acc_commit) = *data;
        (
            vec![
                Fp::from(u64::from(epoch.0)),
                Fp::from(anchor_prev),
                Fp::from(anchor_last),
            ],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(acc_commit)],
        )
    }
}

/// Start a summary from one stamp: [`AnchorSeed`](super::pool::AnchorSeed)
/// with the stamp commitment carried on the header.
///
/// # Soundness
///
/// As at [`AnchorSeed`](super::pool::AnchorSeed).
#[derive(Debug)]
pub struct SummarySeed;

impl Step for SummarySeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Summary;
    type Right = ();
    /// `(anchor_prev, epoch, stamp_commit)`.
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetCommit);

    const INDEX: Index = Index::new(17);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, epoch, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let anchor_last = anchor_prev
            .next_stamp(epoch, &stamp_commit)
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
        Ok(((epoch, anchor_prev, anchor_last, stamp_commit), ()))
    }
}

/// Fold the next stamp into the accumulator while the anchor absorbs the same
/// commitment.
///
/// Committed polynomials: `acc`, `stamp`, `extended`; three oracles.
#[derive(Debug)]
pub struct SummaryAdvance;

impl Step for SummaryAdvance {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = Summary;
    type Right = ();
    /// `(acc, extended, stamp)`.
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (acc, extended, stamp): Self::Witness<'source>,
        (summary_epoch, summary_anchor_prev, summary_anchor_last, summary_acc_commit): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(acc.commit()),
            Eq::from(summary_acc_commit),
            "SummaryAdvance: accumulator does not match header",
        )?;
        enforce_poly_product(
            ctx,
            acc.as_ref(),
            stamp.as_ref(),
            extended.as_ref(),
            "SummaryAdvance: extended accumulator must fold the stamp",
        )?;
        let anchor_last = summary_anchor_last
            .next_stamp(summary_epoch, &stamp.commit())
            .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
        Ok((
            (
                summary_epoch,
                summary_anchor_prev,
                anchor_last,
                extended.commit(),
            ),
            (),
        ))
    }
}
