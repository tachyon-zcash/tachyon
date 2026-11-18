//! Tachygram accumulators over consecutive stamps of one epoch.
//!
//! A summary folds each stamp's tachygram set into one set polynomial while
//! the anchor absorbs each stamp's bridge hash. Consensus forbids republishing
//! a tachygram within two epochs. The accumulator is therefore square-free.
//! The prover chooses where a summary starts and stops. A consumer joins
//! summaries whose anchors are equal. The joined chain contains every stamp
//! absorption.

extern crate alloc;

use alloc::vec::Vec;

use ragu::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, OnlinePoly, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
    primitives::{Element, GadgetExt as _, allocator::Allocator, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
};
use udon::field::Field as _;

use super::stamp::FoldedStamp;
use crate::{
    digest::poseidon,
    gadgets,
    pasta::Fp,
    primitives::{Anchor, EpochIndex, TachygramSetPoly},
};

/// The polynomial whose roots are every tachygram a summary has folded.
#[derive(Clone, Copy, Debug)]
pub struct TachygramAccumulator;

impl OnlinePoly for TachygramAccumulator {}

/// One summarized run of an epoch's stamps.
///
/// The [`TachygramAccumulator`] contains every tachygram from the stamps
/// folded over `(anchor_prev, anchor_end]`; the [`FoldedStamp`] is the last
/// folded stamp's.
#[derive(Clone, Debug)]
pub struct Summary;

#[derive(Gadget, Write)]
pub struct SummaryOutput<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub epoch: gadgets::epoch::EpochIndex<'dr, D>,
    pub anchor_prev: Element<'dr, D>,
    pub anchor_end: Element<'dr, D>,
}

impl Header<Fp> for Summary {
    /// `(epoch, anchor_prev, anchor_end)`
    type Data = (EpochIndex, Anchor, Anchor);
    type OnlinePolyCommit = (TachygramAccumulator, FoldedStamp);
    type Output = Kind![Fp; SummaryOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(SummaryOutput {
            epoch: gadgets::epoch::EpochIndex::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(epoch, ..)| epoch),
            )?,
            anchor_prev: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(_, anchor_prev, _)| Fp::from(anchor_prev)),
            )?,
            anchor_end: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(.., anchor_end)| Fp::from(anchor_end)),
            )?,
        })
    }
}

/// Start a summary from one stamp. The step performs the same fold as
/// [`AnchorSpanSeed`](super::pool::AnchorSpanSeed).
///
/// # Soundness
///
/// `anchor_prev` and `epoch` are free witnesses. Consensus computes each fold
/// with the epoch of the block that contains the stamp.
/// The accumulator and folded stamp carry the same stamp set and open once
/// each at the challenge.
#[derive(Debug)]
pub struct SummarySeed;

impl Step<Pasta> for SummarySeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Summary;
    type Right = ();
    /// `(anchor_prev, epoch, stamp)`
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetPoly);

    const INDEX: Index = Index::new(13);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let stamp = witness.2.as_ref().iter_coeffs().collect::<Vec<_>>();
        Ok(Prepared::new()
            .poly(TachygramAccumulator, stamp.clone())
            .poly(FoldedStamp, stamp))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let previous = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|&(anchor_prev, ..)| Fp::from(anchor_prev)),
        )?;
        let epoch_element = gadgets::epoch::EpochIndex::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(_, epoch, _)| epoch),
        )?;
        let z = oracles.zeta().clone();
        let accumulator_at_z = oracles.output(TachygramAccumulator).open(dr, &z)?;
        let stamp_at_z = oracles.output(FoldedStamp).open(dr, &z)?;
        accumulator_at_z.enforce_equal(dr, &stamp_at_z)?;
        // The empty set polynomial is the constant one, so a stamp whose
        // polynomial opens to one at zeta has no tachygrams.
        let one = Element::constant(dr, Fp::ONE);
        stamp_at_z.sub(dr, &one).enforce_nonzero(dr)?;
        let anchor = poseidon::circuit::anchor_next_stamp(
            dr,
            &previous,
            &epoch_element,
            &[
                oracles.bridge_hash().x().clone(),
                oracles.bridge_hash().y().clone(),
            ],
        )?;
        let output = D::just(|| {
            let (anchor_prev, epoch, _) = witness.take();
            (epoch, anchor_prev, Anchor::from(*anchor.value().take()))
        });
        let fields = SummaryOutput {
            epoch: epoch_element,
            anchor_prev: previous,
            anchor_end: anchor,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}

/// Fold the next stamp into the accumulator while the anchor absorbs the
/// stamp's bridge hash.
///
/// The left and output accumulators hold the accumulated sets; the output
/// folded stamp holds the stamp, each opened once.
#[derive(Debug)]
pub struct SummaryAdvance;

impl Step<Pasta> for SummaryAdvance {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = Summary;
    type Right = ();
    /// `(extended, stamp)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(14);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(
                TachygramAccumulator,
                witness.0.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .poly(
                FoldedStamp,
                witness.1.as_ref().iter_coeffs().collect::<Vec<_>>(),
            ))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let SummaryOutput {
            epoch,
            anchor_prev,
            anchor_end,
        } = left_encoded.as_gadget().clone();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let z = oracles.zeta().clone();
        let accumulator_at_z = oracles.left(TachygramAccumulator).open(dr, &z)?;
        let stamp_at_z = oracles.output(FoldedStamp).open(dr, &z)?;
        let extended_at_z = oracles.output(TachygramAccumulator).open(dr, &z)?;
        let folded = accumulator_at_z.mul(dr, &stamp_at_z)?;
        extended_at_z.enforce_equal(dr, &folded)?;
        // The empty set polynomial is the constant one, so a stamp whose
        // polynomial opens to one at zeta has no tachygrams.
        let one = Element::constant(dr, Fp::ONE);
        stamp_at_z.sub(dr, &one).enforce_nonzero(dr)?;
        // The epoch is in range: `SummarySeed` range-checks it and every
        // `SummaryAdvance` carries it unchanged.
        let anchor = poseidon::circuit::anchor_next_stamp(
            dr,
            &anchor_end,
            &epoch,
            &[
                oracles.bridge_hash().x().clone(),
                oracles.bridge_hash().y().clone(),
            ],
        )?;
        let output = D::just(|| {
            let (summary_epoch, summary_anchor_prev, ..) = left.take();
            (
                summary_epoch,
                summary_anchor_prev,
                Anchor::from(*anchor.value().take()),
            )
        });
        let fields = SummaryOutput {
            epoch,
            anchor_prev,
            anchor_end: anchor,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}
