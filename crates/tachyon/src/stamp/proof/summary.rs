//! Tachygram accumulators over consecutive stamps of one epoch.
//!
//! Each summary multiplies stamp tachygram polynomials into one polynomial
//! while advancing the anchor across each stamp's bridge hash. Provers choose
//! where summaries start and stop, and
//! [`QrIntakeMerge`](super::qr::QrIntakeMerge) joins intakes from summaries
//! with matching endpoint anchors.
//!
//! Because consensus rejects duplicate tachygrams within two epochs, the
//! accumulated polynomial of a summary on the published chain has no repeated
//! root.

use core::convert::Infallible;

use ragu::{
    Cycle,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Suffix},
    maybe::Maybe as _,
    primitives::{Element, GadgetExt as _, allocator::Allocator, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
    udon::field::Field as _,
};

use crate::{
    digest::poseidon,
    gadgets,
    pasta::Fp,
    primitives::{Anchor, EpochIndex, PolySlot, TachygramSetPoly},
};

/// One summarized run of an epoch's stamps.
///
/// Both polynomials are a [`TachygramSetPoly`]: [`Summary::ACCUMULATED`] and
/// [`Summary::LAST_STAMP`].
///
/// # Injectivity
///
/// [`SummarySeed`] and [`SummaryAdvance`] output this header. Every verified
/// `Summary` asserts `epoch <= EPOCH_MAX` as an integer and a prover-known
/// [stamp chain](super#chains-in-a-step) in `epoch` of $k \geq 1$ absorptions
/// from `anchor_prev` to `anchor_end` with polynomials $P_1, \dots, P_k$, where
/// [`Summary::ACCUMULATED`] equals $P_1 \cdots P_k$ and
/// [`Summary::LAST_STAMP`] equals $P_k$.
///
/// The prover chooses `anchor_prev` freely, and nothing constrains history
/// behind it. No $P_i$ equals the constant one, matching [`Anchor::next_stamp`]
/// rejecting the empty set in a pool history.
///
/// - `anchor_end` determines `epoch`, $P_k$ and every preceding absorption
///   ([`Anchor`]).
/// - [`Summary::ACCUMULATED`] has roots equal to the union of the $P_i$'s
///   roots, and equals the multiset-sum [set
///   polynomial](crate::collections::multiset) when every $P_i$ is a set
///   polynomial.
/// - [`Summary::LAST_STAMP`] occupies the last slot to supply the step's bridge
///   hash, and no consumer reads it.
#[derive(Clone, Debug)]
pub struct Summary;

/// The product of the polynomials of the stamps in
/// `(anchor_prev, anchor_end]`.
#[derive(Debug)]
pub struct Accumulated(Infallible);

/// The last stamp's polynomial. Its bridge hash enters `anchor_end`.
#[derive(Debug)]
pub struct LastStamp(Infallible);

impl Summary {
    /// The [`Accumulated`] polynomial.
    pub const ACCUMULATED: PolySlot<TachygramSetPoly, Accumulated> = PolySlot::new();
    /// The [`LastStamp`] polynomial.
    pub const LAST_STAMP: PolySlot<TachygramSetPoly, LastStamp> = PolySlot::new();
}

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
    type OnlinePolyCommit = (
        PolySlot<TachygramSetPoly, Accumulated>,
        PolySlot<TachygramSetPoly, LastStamp>,
    );
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

/// Start a summary from one stamp. The anchor absorbs the stamp's bridge
/// hash as in [`AnchorSpanSeed`](super::pool::AnchorSpanSeed).
///
/// # Soundness
///
/// The step [absorbs](super#chains-in-a-step) [`Summary::LAST_STAMP`] into
/// prover-chosen `anchor_prev` at `epoch`. Both output slots precede $\zeta$;
/// matching their openings there sets [`Summary::ACCUMULATED`] to that stamp.
/// Requiring the opening to differ from one permits other nonzero constants.
#[derive(Debug)]
pub struct SummarySeed;

impl<C: Cycle<CircuitField = Fp>> Step<C> for SummarySeed {
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
        let stamp = &witness.2;
        let prepared = Summary::ACCUMULATED.poly(Prepared::new(), stamp);
        Ok(Summary::LAST_STAMP.poly(prepared, stamp))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, C, Self>,
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
        let accumulated_at_z = oracles.output(Summary::ACCUMULATED).open(dr, &z)?;
        let stamp_at_z = oracles.output(Summary::LAST_STAMP).open(dr, &z)?;
        accumulated_at_z.enforce_equal(dr, &stamp_at_z)?;
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

/// Extend the accumulator with the next stamp while the anchor absorbs the
/// stamp's bridge hash.
///
/// The left and output [`Summary::ACCUMULATED`] and the output's
/// [`Summary::LAST_STAMP`] are opened once each.
///
/// # Soundness
///
/// The step keeps `epoch` and `anchor_prev` and
/// [absorbs](super#chains-in-a-step) the new stamp $P$ into `anchor_end`. Only
/// the accumulated product $A$ is read from the input slots. It and both output
/// polynomials precede $\zeta$, so checking $A'(\zeta)=A(\zeta)P(\zeta)$
/// extends the product by $P$. Requiring $P(\zeta)\ne1$ rules out the constant
/// one.
#[derive(Debug)]
pub struct SummaryAdvance;

impl<C: Cycle<CircuitField = Fp>> Step<C> for SummaryAdvance {
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
        let (extended, stamp) = (&witness.0, &witness.1);
        let prepared = Summary::ACCUMULATED.poly(Prepared::new(), extended);
        Ok(Summary::LAST_STAMP.poly(prepared, stamp))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, C, Self>,
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
        let accumulated_at_z = oracles.left(Summary::ACCUMULATED).open(dr, &z)?;
        let stamp_at_z = oracles.output(Summary::LAST_STAMP).open(dr, &z)?;
        let extended_at_z = oracles.output(Summary::ACCUMULATED).open(dr, &z)?;
        let folded = accumulated_at_z.mul(dr, &stamp_at_z)?;
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
