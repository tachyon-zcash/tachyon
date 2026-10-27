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
use ragu_primitives::Element;
use udon::curve::Projective as _;

use crate::{
    primitives::{Anchor, EpochIndex, TachygramSetCommit, TachygramSetPoly},
    relations::enforce::{bind_poly_handle, enforce_poly_product, poly_handle_limbs},
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left)?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
        let previous = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0)),
        )?;
        let epoch_element = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.1)),
        )?;
        let limbs = crate::gadgets::commitment::HostCommitment::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Eq::from(data.2).to_affine()),
        )
        .map(|encoding| encoding.limbs)?;
        let anchor = crate::gadgets::anchor::AnchorGadget::from(previous.clone())
            .next_stamp(ctx.dr, epoch_element.clone(), limbs.clone())
            .map(|anchor| anchor.element)?;
        let output = D::just(|| {
            let (anchor_prev, epoch, stamp_commit) = witness.take();
            (
                epoch,
                anchor_prev,
                Anchor::from(*anchor.value().take()),
                stamp_commit,
            )
        });
        let fields = crate::stamp::headers::summary::SummaryOutput {
            epoch: (epoch_element).into(),
            anchor_prev: (previous).into(),
            anchor_end: (anchor).into(),
            acc_commit: (crate::gadgets::commitment::HostCommitment { limbs }).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
        ))
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
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
            &left_encoded.as_gadget().acc_commit.encoding.limbs,
            "SummaryAdvance: accumulator does not match header",
        )?;
        enforce_poly_product(
            ctx,
            &acc_handle,
            &stamp_handle,
            &extended_handle,
            "SummaryAdvance: extended accumulator must fold the stamp",
        )?;
        let previous = left_encoded.as_gadget().anchor_end.element.clone();
        let epoch_element = left_encoded.as_gadget().epoch.element.clone();
        let limbs = poly_handle_limbs(ctx.dr, &stamp_handle)?;
        let anchor = crate::gadgets::anchor::AnchorGadget::from(previous)
            .next_stamp(ctx.dr, epoch_element, limbs)
            .map(|anchor| anchor.element)?;
        let output = D::just(|| {
            let (_, extended, _) = witness.take();
            let (summary_epoch, summary_anchor_prev, ..) = left.take();
            (
                summary_epoch,
                summary_anchor_prev,
                Anchor::from(*anchor.value().take()),
                extended.commit(),
            )
        });
        let fields = crate::stamp::headers::summary::SummaryOutput {
            epoch: (left_encoded.as_gadget().epoch.element.clone()).into(),
            anchor_prev: (left_encoded.as_gadget().anchor_prev.element.clone()).into(),
            anchor_end: (anchor).into(),
            acc_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &extended_handle)?,
            })
            .into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
        ))
    }
}

pub use crate::stamp::headers::summary::Summary;
