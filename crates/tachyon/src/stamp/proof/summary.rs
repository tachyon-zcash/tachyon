//! Tachygram accumulators over consecutive stamps of one epoch.
//!
//! A summary multiplies each stamp's tachygram polynomial into one polynomial
//! while the anchor absorbs each stamp's bridge hash. The prover chooses where
//! a summary starts and stops.
//! [`QrIntakeMerge`](super::qr::QrIntakeMerge) joins the intakes of summaries
//! whose anchors meet.
//!
//! Consensus rejects a tachygram published twice within two epochs. The
//! accumulated polynomial of a summary on the published chain therefore has
//! no repeated root.

use core::convert::Infallible;

use ragu::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
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
/// [`SummarySeed`] and [`SummaryAdvance`] output this header. A verified
/// `Summary` asserts that `epoch` is an integer at most `EPOCH_MAX`, and that
/// its prover knows a [stamp chain](Anchor#chains-in-a-step) in `epoch` of
/// $k \geq 1$ absorptions from `anchor_prev` to `anchor_end`, with
/// polynomials $P_1, \dots, P_k$, for which
///
/// - [`Summary::ACCUMULATED`] is the product $P_1 \cdots P_k$,
/// - [`Summary::LAST_STAMP`] is $P_k$.
///
/// No step relies on an absorption's polynomial differing from the constant
/// one.
///
/// Each field and each polynomial determines what it stands for.
///
/// - `epoch` stands for the epoch every absorption of the chain absorbs. It is
///   an integer at most `EPOCH_MAX`. Every way of building the
///   [`EpochIndex`](gadgets::epoch::EpochIndex) gadget holds its wire to that
///   range, so it is in range in every circuit that holds this header.
///   `anchor_end` determines it.
/// - `anchor_end` stands for the end of the chain. It is a stamp absorption, so
///   it determines the chain's last absorption, and each anchor of the chain
///   after the first determines the absorption behind it ([`Anchor`]).
/// - `anchor_prev` is where the chain starts. [`SummarySeed`] takes it from its
///   prover, so the assertion says nothing of what lies behind it.
/// - [`Summary::ACCUMULATED`] stands for the roots of the chain's polynomials.
///   It is their product and has no other factor, so a value is a root of it
///   exactly when it is a root of some $P_i$. Where each $P_i$ is a [set
///   polynomial](crate::collections::multiset), it is the set polynomial of the
///   multiset sum of the stamps' tachygrams.
/// - [`Summary::LAST_STAMP`] is the polynomial whose bridge hash the last
///   absorption absorbs, and `anchor_end` determines it. It sits in the last
///   slot because a step reads the bridge hash of that slot. No step reads it
///   from an input.
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
/// The step reads no input. `anchor_prev` and `epoch` are wires of the
/// prover's choice, and `epoch` is range-checked.
///
/// Both output polynomials are committed before the challenge. The circuit
/// equates their openings at $\zeta$, so they are one polynomial $P$. It
/// holds the opening away from one, so $P$ is not the constant one.
///
/// [`Summary::LAST_STAMP`] is the step's last output slot, so Ragu holds the
/// bridge hash wires to a [bridge hash](crate::TachygramSetBridge) $B$ of the
/// accumulator of $P$. `anchor_end` is the output of the
/// [`anchor_next_stamp`](poseidon::anchor_next_stamp) circuit on
/// `anchor_prev`, `epoch` and $B$. No identity at the challenge reads it.
///
/// These are a [stamp chain](Anchor#chains-in-a-step) of one absorption in
/// `epoch`
/// whose polynomial is both output polynomials, which is what [`Summary`]
/// asserts with $k = 1$.
///
/// [`Summary::ACCUMULATED`] and [`Summary::LAST_STAMP`] open once each at the
/// challenge.
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
        let stamp = &witness.2;
        let prepared = Summary::ACCUMULATED.poly(Prepared::new(), stamp);
        Ok(Summary::LAST_STAMP.poly(prepared, stamp))
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
/// The left and output [`Summary::ACCUMULATED`] hold the accumulated sets;
/// the output's [`Summary::LAST_STAMP`] holds the next stamp's tachygrams.
/// Each is opened once.
///
/// # Soundness
///
/// The left input is a verified [`Summary`]. It asserts a
/// [stamp chain](Anchor#chains-in-a-step) in its `epoch` from its
/// `anchor_prev` to its `anchor_end`, and its [`Summary::ACCUMULATED`] is the
/// product $A$ of the chain's polynomials.
///
/// $A$ is fixed in the input PCD, and both output polynomials are committed
/// before the challenge. The circuit equates the opening of the output's
/// [`Summary::ACCUMULATED`] at $\zeta$ with $A(\zeta) \cdot P(\zeta)$, for
/// $P$ the output's [`Summary::LAST_STAMP`]. The output's
/// [`Summary::ACCUMULATED`] is therefore $A \cdot P$. The circuit holds
/// $P(\zeta)$ away from one, so $P$ is not the constant one.
///
/// [`Summary::LAST_STAMP`] is the step's last output slot, so Ragu holds the
/// bridge hash wires to a [bridge hash](crate::TachygramSetBridge) $B$ of the
/// accumulator of $P$. The output `anchor_end` is the output of the
/// [`anchor_next_stamp`](poseidon::anchor_next_stamp) circuit on the input's
/// `anchor_end`, the input's `epoch` and $B$. No identity at the challenge
/// reads it. The step copies `epoch` and `anchor_prev` from the input.
///
/// The input's chain with this absorption is a stamp chain in `epoch` from
/// `anchor_prev` to the output `anchor_end`. Its polynomials multiply to the
/// output's [`Summary::ACCUMULATED`] and its last is $P$, which is what
/// [`Summary`] asserts. The step does not read the input's
/// [`Summary::LAST_STAMP`].
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
        let (extended, stamp) = (&witness.0, &witness.1);
        let prepared = Summary::ACCUMULATED.poly(Prepared::new(), extended);
        Ok(Summary::LAST_STAMP.poly(prepared, stamp))
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
