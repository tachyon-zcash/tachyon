//! Tachygram accumulators over consecutive stamps of one epoch.
//!
//! A summary folds each stamp's tachygram set into one set polynomial while
//! the anchor absorbs the same commitments. Consensus forbids republishing a
//! tachygram within two epochs. The accumulator is therefore square-free.
//! The prover chooses where a summary starts and stops. A consumer joins
//! summaries whose anchors are equal. The joined chain contains every stamp
//! absorption.

extern crate alloc;
use ragu::{
    Encoded, Header, Index, Step, StepCtx,
    pasta::{Eq, Fp},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use udon::curve::Projective as _;

pub use crate::stamp::headers::summary::Summary;
use crate::{
    primitives::{Anchor, EpochIndex, TachygramSetCommit, TachygramSetPoly},
    ragu_constraint::enforce_equal_point,
    relations::enforce::{bind_poly_handle, enforce_poly_product},
};

/// Start a summary from one stamp. The step performs the same fold as
/// [`AnchorSpanSeed`](super::pool::AnchorSpanSeed) and puts the stamp's
/// commitment on the header.
///
/// # Soundness
///
/// `epoch` is a free witness. Consensus computes each fold with the epoch of
/// the block that contains the stamp.
#[derive(Debug)]
pub struct SummarySeed;

impl Step for SummarySeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Summary;
    type Right = ();
    type Shared = ();
    /// `(anchor_prev, epoch, stamp_commit)`
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetCommit);

    const INDEX: Index = Index::new(13);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let (anchor_prev, epoch, stamp_commit) = witness.take();
            let anchor_end = anchor_prev
                .next_stamp(epoch, &stamp_commit)
                .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
            Ok(((epoch, anchor_prev, anchor_end, stamp_commit), ()))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
    }
}

/// Fold the next stamp into the accumulator while the anchor absorbs the same
/// commitment.
#[derive(Debug)]
pub struct SummaryAdvance;

impl Step for SummaryAdvance {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = Summary;
    type Right = ();
    type Shared = ();
    /// `(acc, extended, stamp)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(14);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let acc_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|polynomials| polynomials.0.as_ref().clone()),
        )?;
        let extended_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|polynomials| polynomials.1.as_ref().clone()),
        )?;
        let stamp_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|polynomials| polynomials.2.as_ref().clone()),
        )?;
        bind_poly_handle(
            ctx,
            &acc_handle,
            left.as_ref().map(|data| Eq::from(data.3).to_affine()),
            "SummaryAdvance: accumulator does not match header",
        )?;
        enforce_poly_product(
            ctx,
            &acc_handle,
            &stamp_handle,
            &extended_handle,
            "SummaryAdvance: extended accumulator must fold the stamp",
        )?;
        let output = D::try_just(|| {
            let (acc, extended, stamp) = witness.take();
            let (summary_epoch, summary_anchor_prev, summary_anchor_end, summary_acc_commit) =
                left.take();
            right.take();
            enforce_equal_point(
                Eq::from(acc.commit()),
                Eq::from(summary_acc_commit),
                "SummaryAdvance: accumulator does not match header",
            )?;
            let anchor_end = summary_anchor_end
                .next_stamp(summary_epoch, &stamp.commit())
                .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
            Ok((
                (
                    summary_epoch,
                    summary_anchor_prev,
                    anchor_end,
                    extended.commit(),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
    }
}
