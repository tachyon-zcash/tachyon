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

use ragu::{Encoded, Header, HeaderInput, Index, Oracles, Slot, Step, Suffix};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::Pasta,
};
use ragu_primitives::{Element, GadgetExt as _, allocator::Allocator, io::Write};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use crate::{
    digest::poseidon,
    pasta::{Eq, Fp},
    primitives::{Anchor, EpochIndex, TachygramSetCommit, TachygramSetPoly},
    relations::enforce::{enforce_poly_equal, enforce_poly_product},
};

/// One summarized run of an epoch's stamps.
///
/// `acc_commit` commits the root polynomial of every tachygram in the run,
/// which is exactly the set of stamps folded over the coverage extent
/// `(anchor_prev, anchor_end]`.
#[derive(Clone, Debug)]
pub struct Summary;

/// `Summary` gadget.
#[derive(Gadget, Write, derive_more::Debug)]
#[debug("SummaryOutput(..)")]
pub struct SummaryOutput<'dr, D: Driver<'dr>> {
    /// `epoch`.
    pub epoch: Element<'dr, D>,
    /// `anchor_prev`.
    pub anchor_prev: Element<'dr, D>,
    /// `anchor_end`.
    pub anchor_end: Element<'dr, D>,
    /// `acc_commit`.
    pub acc_commit: [Element<'dr, D>; 2],
}

impl Header<Fp> for Summary {
    /// `(epoch, anchor_prev, anchor_end, acc_commit)`. `anchor_prev` is a free
    /// witness of the seed step, as `anchor_start` is for
    /// [`AnchorSpan`](super::pool::AnchorSpan).
    type Data = (EpochIndex, Anchor, Anchor, TachygramSetCommit);
    type Output = Kind![Fp; SummaryOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        #[expect(
            clippy::expect_used,
            reason = "compressed point limbs contain exactly 16 bytes"
        )]
        let limbs = D::try_just(|| {
            let point = Eq::from(witness.clone().take().3).to_affine();
            if point.is_identity() {
                return Err(ragu_core::Error::InvalidWitness(
                    "cannot encode the identity commitment".into(),
                ));
            }
            let bytes = point.to_bytes();
            let (low, high) = bytes.split_at(16);
            Ok([
                Fp::from_u128(u128::from_le_bytes(low.try_into().expect("16 byte limb"))),
                Fp::from_u128(u128::from_le_bytes(high.try_into().expect("16 byte limb"))),
            ])
        })?;
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
            acc_commit: [
                Element::alloc(dr, allocator, limbs.as_ref().map(|values| values[0]))?,
                Element::alloc(dr, allocator, limbs.as_ref().map(|values| values[1]))?,
            ],
        })
    }
}

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

impl Step<Pasta> for SummarySeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Summary;
    type Right = ();
    /// `(anchor_prev, epoch, stamp)`; `O0/O1` carry the same stamp polynomial.
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetPoly);

    const INDEX: Index = Index::new(13);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        let stamp = super::coefficients(witness.2.as_ref());
        Ok([stamp.clone(), stamp, alloc::vec![Fp::from(1)]])
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let (anchor_prev, epoch, stamp) = witness.take();
            let stamp_commit = stamp.commit();
            let anchor_end = anchor_prev
                .next_stamp(epoch, &stamp_commit)
                .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
            Ok(((epoch, anchor_prev, anchor_end, stamp_commit), ()))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        enforce_poly_equal(dr, oracles, Slot::output(0), Slot::output(1))?;
        let header = encoded.as_gadget();
        super::enforce_stamp_domain(dr, &header.epoch, oracles.bridge_hash())?;
        let anchor = poseidon::with_driver::anchor_next_stamp(
            dr,
            &header.anchor_prev,
            &header.epoch,
            oracles.bridge_hash(),
        )?;
        header.anchor_end.enforce_equal(dr, &anchor)?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Fold the next stamp into the accumulator while the anchor absorbs the same
/// commitment.
#[derive(Debug)]
pub struct SummaryAdvance;

impl Step<Pasta> for SummaryAdvance {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = Summary;
    type Right = ();
    /// `(acc, extended, stamp)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(14);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        Ok([
            super::coefficients(witness.1.as_ref()),
            super::coefficients(witness.2.as_ref()),
            alloc::vec![Fp::from(1)],
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let _precheck = D::try_just(|| {
            let (acc, ..) = witness.clone().take();
            let (_, _, _, acc_commit) = left.clone().take();
            if Eq::from(acc.commit()) != Eq::from(acc_commit) {
                return Err(ragu_core::Error::InvalidWitness(
                    "SummaryAdvance: accumulator does not match header".into(),
                ));
            }
            Ok(())
        })?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::output(1),
            &Slot::output(0),
            "SummaryAdvance: extended accumulator must fold the stamp",
        )?;
        let output = D::try_just(|| {
            let (acc, extended, stamp) = witness.take();
            let (summary_epoch, summary_anchor_prev, summary_anchor_end, summary_acc_commit) =
                left.take();
            right.take();
            if Eq::from(acc.commit()) != Eq::from(summary_acc_commit) {
                return Err(ragu_core::Error::InvalidWitness(
                    "SummaryAdvance: accumulator does not match header".into(),
                ));
            }
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
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        super::enforce_stamp_domain(dr, &left_encoded.as_gadget().epoch, oracles.bridge_hash())?;
        let anchor = poseidon::with_driver::anchor_next_stamp(
            dr,
            &left_encoded.as_gadget().anchor_end,
            &left_encoded.as_gadget().epoch,
            oracles.bridge_hash(),
        )?;
        let fields = SummaryOutput {
            epoch: left_encoded.as_gadget().epoch.clone(),
            anchor_prev: left_encoded.as_gadget().anchor_prev.clone(),
            anchor_end: anchor,
            acc_commit: encoded.as_gadget().acc_commit.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
    }
}
