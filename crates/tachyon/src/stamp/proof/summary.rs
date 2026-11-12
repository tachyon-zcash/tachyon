//! Tachygram accumulators over consecutive stamps of one epoch.
//!
//! A summary folds each stamp's tachygram set into one set polynomial while
//! the anchor absorbs the same commitments. Consensus forbids republishing a
//! tachygram within two epochs. The accumulator is therefore square-free.
//! The prover chooses where a summary starts and stops. A consumer joins
//! summaries whose anchors are equal. The joined chain contains every stamp
//! absorption.

extern crate alloc;

use alloc::vec::Vec;

use ragu::{
    header::{Header, Suffix},
    step::{Encoded, HeaderInput, Index, Oracles, Slot, Step},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::Pasta,
};
use ragu_primitives::{Element, allocator::Allocator, io::Write};

use crate::{
    digest::poseidon,
    gadgets,
    pasta::Fp,
    primitives::{Anchor, EpochIndex, TachygramSetPoly},
    relations::enforce::{enforce_poly_equal, enforce_poly_product},
};

/// One summarized run of an epoch's stamps.
///
/// The first output polynomial contains every tachygram from the stamps folded
/// over `(anchor_prev, anchor_end]`.
#[derive(Clone, Debug)]
pub struct Summary;

#[derive(Gadget, Write)]
pub struct SummaryOutput<'dr, D: Driver<'dr>> {
    pub epoch: Element<'dr, D>,
    pub anchor_prev: Element<'dr, D>,
    pub anchor_end: Element<'dr, D>,
}

impl Header<Fp> for Summary {
    /// `(epoch, anchor_prev, anchor_end)`
    type Data = (EpochIndex, Anchor, Anchor);
    type Output = Kind![Fp; SummaryOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(SummaryOutput {
            epoch: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            anchor_prev: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            anchor_end: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
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
/// O0/O1 carry the same stamp set and open once each at the challenge.
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

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.2.as_ref().iter_coeffs().collect(),
            witness.2.as_ref().iter_coeffs().collect(),
        ])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
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
        let previous = Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.0)))?;
        let epoch_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.1)))?;
        let [empty_x, empty_y] =
            super::EMPTY_STAMP_BRIDGE_HASH.map(|coordinate| Element::constant(dr, coordinate));
        let equal_x = oracles.bridge_hash()[0].is_equal(dr, &mut (), &empty_x)?;
        let equal_y = oracles.bridge_hash()[1].is_equal(dr, &mut (), &empty_y)?;
        equal_x
            .and(dr, &equal_y)?
            .element()
            .enforce_zero(dr)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "SummarySeed: the stamp's tachygram set is empty".into(),
                )
            })?;
        gadgets::epoch::EpochIndex::new(dr, &epoch_element)?;
        let anchor = poseidon::circuit::anchor_next_stamp(
            dr,
            &previous,
            &epoch_element,
            oracles.bridge_hash(),
        )?;
        enforce_poly_equal(dr, oracles, Slot::output(0), Slot::output(1))?;
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

/// Fold the next stamp into the accumulator while the anchor absorbs the same
/// commitment.
/// L0/O0 hold the accumulated sets; O1 holds the stamp, each opened once.
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

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.0.as_ref().iter_coeffs().collect(),
            witness.1.as_ref().iter_coeffs().collect(),
        ])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::output(1),
            &Slot::output(0),
            "SummaryAdvance: extended accumulator must fold the stamp",
        )?;
        let [empty_x, empty_y] =
            super::EMPTY_STAMP_BRIDGE_HASH.map(|coordinate| Element::constant(dr, coordinate));
        let equal_x = oracles.bridge_hash()[0].is_equal(dr, &mut (), &empty_x)?;
        let equal_y = oracles.bridge_hash()[1].is_equal(dr, &mut (), &empty_y)?;
        equal_x
            .and(dr, &equal_y)?
            .element()
            .enforce_zero(dr)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "SummaryAdvance: the stamp's tachygram set is empty".into(),
                )
            })?;
        // The epoch is in range: `SummarySeed` range-checks it and every
        // `SummaryAdvance` carries it unchanged.
        let anchor = poseidon::circuit::anchor_next_stamp(
            dr,
            &left_encoded.as_gadget().anchor_end,
            &left_encoded.as_gadget().epoch,
            oracles.bridge_hash(),
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
            epoch: left_encoded.as_gadget().epoch.clone(),
            anchor_prev: left_encoded.as_gadget().anchor_prev.clone(),
            anchor_end: anchor,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}
