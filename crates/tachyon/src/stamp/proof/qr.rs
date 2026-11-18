//! QR epoch evidence: one epoch's tachygrams partitioned by profile.
//!
//! Each depth classifies at a discriminant of the progression
//!
//! $$
//!   R_j = R_0 + j,
//! $$
//!
//! from a first discriminant $R_0$. Every header carries $R_0$, so depth $j$
//! classifies at $R_j$, and a value takes the residue side there iff $x + R_j$
//! is a square or zero.
//!
//! [`QrSummaryIntake`] starts a [`QrIntake`] from a [`Summary`],
//! [`QrStampIntakeSeed`] from one unsummarized stamp, and
//! [`QrEmptyIntakeSeed`] over an epoch with no stamps. [`QrIntakeSplit`]
//! partitions an intake at its discriminant into [`QrIntakeSides`],
//! [`QrSideSelect`] fixes hints and the exceptional-value assignment,
//! [`QrSideDescend`] carries one side down a level, and [`QrIntakeMerge`]
//! joins two same-profile intakes whose spans meet. [`QrBucketSeal`] admits a
//! routed intake as a [`QrBucket`], and [`QrUnspentInit`] tests a value's
//! profile against a bucket and opens the bucket at it.

extern crate alloc;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use ragu::{
    drivers::{Coeff, Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, OnlinePoly, Padding, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
    primitives::{Boolean, Element, GadgetExt as _, allocator::Allocator, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
};
use udon::{curve::Affine as _, field::Field as _};

use super::{
    delegation::NfSeq,
    pool::{ArbitraryUnspent, ArbitraryUnspentOutput},
    summary::{Summary, TachygramAccumulator},
};
pub use crate::collections::qr::classify;
use crate::{
    collections::qr::QUADRATIC_NON_RESIDUE,
    digest::poseidon,
    gadgets,
    pasta::{EpAffine, Fp},
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrInterpolantPoly, QrProfile,
        QrQuotientPoly, Tachygram, TachygramSetBridge, TachygramSetPoly,
    },
};

/// The polynomial whose roots are the tachygrams an intake routes or a bucket
/// holds.
#[derive(Clone, Copy, Debug)]
pub struct QrContents;

impl OnlinePoly for QrContents {}

/// The polynomial whose roots are a split's residue-side members.
#[derive(Clone, Copy, Debug)]
pub struct QrResidues;

impl OnlinePoly for QrResidues {}

/// The polynomial whose roots are a split's non-residue-side members.
#[derive(Clone, Copy, Debug)]
pub struct QrNonResidues;

impl OnlinePoly for QrNonResidues {}

/// A descent's interpolant hint.
#[derive(Clone, Copy, Debug)]
pub struct QrInterpolant;

impl OnlinePoly for QrInterpolant {}

/// A descent's quotient hint.
#[derive(Clone, Copy, Debug)]
pub struct QrQuotient;

impl OnlinePoly for QrQuotient {}

/// Tachygrams under routing, complete for `profile` over the covered span.
///
/// Covers stamp folds over `(anchor_prev, anchor_end]`.
/// A split classifies at `discriminant.at(profile.depth)`. A builder keeps its
/// intake headers unpublished until the epoch closes.
#[derive(Clone, Debug)]
pub struct QrIntake;

#[derive(Gadget, Write)]
pub struct QrIntakeOutput<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub epoch: gadgets::epoch::EpochIndex<'dr, D>,
    pub anchor_prev: Element<'dr, D>,
    pub anchor_end: Element<'dr, D>,
    pub discriminant: Element<'dr, D>,
    #[ragu(gadget)]
    pub profile: gadgets::qr::QrProfile<'dr, D>,
}

impl Header<Fp> for QrIntake {
    /// `(epoch, anchor_prev, anchor_end, discriminant, profile)`
    type Data = (EpochIndex, Anchor, Anchor, QrDiscriminant, QrProfile);
    type OnlinePolyCommit = (Padding, QrContents);
    type Output = Kind![Fp; QrIntakeOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(4);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(QrIntakeOutput {
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
                    .map(|&(_, anchor_prev, ..)| Fp::from(anchor_prev)),
            )?,
            anchor_end: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(_, _, anchor_end, ..)| Fp::from(anchor_end)),
            )?,
            discriminant: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(.., discriminant, _)| Fp::from(discriminant)),
            )?,
            profile: gadgets::qr::QrProfile::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(.., profile)| profile),
            )?,
        })
    }
}

/// A factorization of one intake's members. Selecting and extracting either
/// side attests the exceptional-value assignment and the other side's class.
///
/// The output polynomials are ordered residue, then non-residue.
#[derive(Clone, Debug)]
pub struct QrIntakeSides;

#[derive(Gadget, Write)]
pub struct QrIntakeSidesOutput<'dr, D: Driver<'dr>> {
    /// The intake being split.
    #[ragu(gadget)]
    pub intake: QrIntakeOutput<'dr, D>,
    /// Bridge hash of the split's non-residue polynomial.
    pub non_residue_hash: [Element<'dr, D>; 2],
}

impl Header<Fp> for QrIntakeSides {
    /// `(epoch, anchor_prev, anchor_end, discriminant, profile,
    /// non_residue_hash)`
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetBridge,
    );
    type OnlinePolyCommit = (QrResidues, QrNonResidues);
    type Output = Kind![Fp; QrIntakeSidesOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        #[expect(
            clippy::expect_used,
            reason = "a bridge hash is the identity only under a discrete-log relation between its generators"
        )]
        let non_residue_hash = witness.as_ref().map(|&(.., non_residue_hash)| {
            EpAffine::from(non_residue_hash)
                .coordinates()
                .expect("bridge hash is not the identity")
        });
        Ok(QrIntakeSidesOutput {
            intake: QrIntake::encode(
                dr,
                allocator,
                witness.as_ref().map(
                    |&(epoch, anchor_prev, anchor_end, discriminant, profile, _)| {
                        (epoch, anchor_prev, anchor_end, discriminant, profile)
                    },
                ),
            )?,
            non_residue_hash: [
                Element::alloc(
                    dr,
                    allocator,
                    non_residue_hash.as_ref().map(|coordinates| coordinates.0),
                )?,
                Element::alloc(
                    dr,
                    allocator,
                    non_residue_hash.as_ref().map(|coordinates| coordinates.1),
                )?,
            ],
        })
    }
}

/// A split statement and committed hints for a descent.
///
/// The output polynomials are the interpolant and quotient.
#[derive(Clone, Debug)]
pub struct QrSideSelection;

impl Header<Fp> for QrSideSelection {
    type Data = <QrIntakeSides as Header<Fp>>::Data;
    type OnlinePolyCommit = (QrInterpolant, QrQuotient);
    type Output = Kind![Fp; QrIntakeSidesOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(16);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        QrIntakeSides::encode(dr, allocator, witness)
    }
}

/// Start a root intake from a [`Summary`].
///
/// # Soundness
///
/// `discriminant` is a free witness; see [`QrDiscriminant`].
#[derive(Debug)]
pub struct QrSummaryIntake;

impl Step<Pasta> for QrSummaryIntake {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = QrIntake;
    type Right = ();
    /// `(discriminant)`
    type Witness<'source> = (QrDiscriminant,);

    const INDEX: Index = Index::new(15);

    fn prepare(
        &self,
        _: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new().poly(QrContents, left.polynomial(TachygramAccumulator)))
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let summary = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let discriminant_element = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|&(discriminant,)| Fp::from(discriminant)),
        )?;
        let data = D::just(|| {
            let (discriminant,) = witness.take();
            let (summary_epoch, summary_anchor_prev, summary_anchor_end) = left.take();
            let () = right.take();
            (
                summary_epoch,
                summary_anchor_prev,
                summary_anchor_end,
                discriminant,
                QrProfile::ROOT,
            )
        });
        let fields = QrIntakeOutput {
            epoch: summary.epoch.clone(),
            anchor_prev: summary.anchor_prev.clone(),
            anchor_end: summary.anchor_end.clone(),
            discriminant: discriminant_element,
            profile: gadgets::qr::QrProfile::root(dr),
        };
        let z = oracles.zeta().clone();
        let accumulator = oracles.left(TachygramAccumulator).open(dr, &z)?;
        let contents = oracles.output(QrContents).open(dr, &z)?;
        accumulator.enforce_equal(dr, &contents)?;
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

/// Start a root intake from one stamp:
/// [`SummarySeed`](super::summary::SummarySeed) with a [`QrIntake`] output.
///
/// # Soundness
///
/// `discriminant` is a free witness; see [`QrDiscriminant`]. The contents are
/// the stamp's tachygram set and open once; their bridge hash enters
/// `anchor_end`.
#[derive(Debug)]
pub struct QrStampIntakeSeed;

impl Step<Pasta> for QrStampIntakeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrIntake;
    type Right = ();
    /// `(anchor_prev, epoch, discriminant, stamp)`
    type Witness<'source> = (Anchor, EpochIndex, QrDiscriminant, TachygramSetPoly);

    const INDEX: Index = Index::new(21);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new().poly(
            QrContents,
            witness.3.as_ref().iter_coeffs().collect::<Vec<_>>(),
        ))
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let discriminant_element = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|&(_, _, discriminant, _)| Fp::from(discriminant)),
        )?;
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
            witness.as_ref().map(|&(_, epoch, ..)| epoch),
        )?;
        let z = oracles.zeta().clone();
        let stamp_at_z = oracles.output(QrContents).open(dr, &z)?;
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
        let data = D::just(|| {
            let (anchor_prev, epoch, discriminant, _) = witness.take();
            let () = left.take();
            let () = right.take();
            (
                epoch,
                anchor_prev,
                Anchor::from(*anchor.value().take()),
                discriminant,
                QrProfile::ROOT,
            )
        });
        let fields = QrIntakeOutput {
            epoch: epoch_element,
            anchor_prev: previous,
            anchor_end: anchor,
            discriminant: discriminant_element,
            profile: gadgets::qr::QrProfile::root(dr),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

/// Start a root intake over an epoch that published no stamp.
///
/// The intake runs from `anchor` to itself and holds nothing.
///
/// # Soundness
///
/// `anchor` and `epoch` are free witnesses. [`QrBucketSeal`] requires `anchor`
/// to be a boundary digest into `epoch`. [`QrBucketSeal`] computes the boundary
/// digest of `anchor` into `epoch + 1`. The sealed bucket ends on the published
/// entry anchor of `epoch + 1` only if `anchor` is both the entry anchor and
/// the final anchor of `epoch`. That holds only when the epoch published no
/// stamp. `discriminant` is a free witness. See [`QrDiscriminant`].
/// The contents open once at the challenge and are constrained to one.
#[derive(Debug)]
pub struct QrEmptyIntakeSeed;

impl Step<Pasta> for QrEmptyIntakeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrIntake;
    type Right = ();
    /// `(anchor, epoch, discriminant)`
    type Witness<'source> = (Anchor, EpochIndex, QrDiscriminant);

    const INDEX: Index = Index::new(23);

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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let zeta = oracles.zeta().clone();
        let contents = oracles.output(QrContents).open(dr, &zeta)?;
        let one = Element::constant(dr, Fp::ONE);
        contents.enforce_equal(dr, &one)?;
        let anchor_element = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(anchor, ..)| Fp::from(anchor)),
        )?;
        let discriminant_element = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|&(_, _, discriminant)| Fp::from(discriminant)),
        )?;
        let epoch_element = gadgets::epoch::EpochIndex::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(_, epoch, _)| epoch),
        )?;
        let data = D::just(|| {
            let (anchor, epoch, discriminant) = witness.take();
            let () = left.take();
            let () = right.take();
            (epoch, anchor, anchor, discriminant, QrProfile::ROOT)
        });
        let fields = QrIntakeOutput {
            epoch: epoch_element,
            anchor_prev: anchor_element.clone(),
            anchor_end: anchor_element,
            discriminant: discriminant_element,
            profile: gadgets::qr::QrProfile::root(dr),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

/// Join two same-profile intakes whose spans meet.
///
/// # Soundness
///
/// Consensus forbids republishing a tachygram within two epochs, so the sets
/// are disjoint and the product is the union's root polynomial.
#[derive(Debug)]
pub struct QrIntakeMerge;

impl Step<Pasta> for QrIntakeMerge {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrIntake;
    type Right = QrIntake;
    /// `(merged,)`
    type Witness<'source> = (TachygramSetPoly,);

    const INDEX: Index = Index::new(16);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new().poly(
            QrContents,
            witness.0.as_ref().iter_coeffs().collect::<Vec<_>>(),
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
        let left_intake = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let right_intake = right_encoded.as_gadget();
        let z = oracles.zeta().clone();
        let left_contents = oracles.left(QrContents).open(dr, &z)?;
        let right_contents = oracles.right(QrContents).open(dr, &z)?;
        let merged_contents = oracles.output(QrContents).open(dr, &z)?;
        let expected_contents = left_contents.mul(dr, &right_contents)?;
        merged_contents.enforce_equal(dr, &expected_contents)?;
        for (left_element, right_element) in [
            (&*left_intake.epoch, &*right_intake.epoch),
            (&left_intake.discriminant, &right_intake.discriminant),
            (&left_intake.profile.depth, &right_intake.profile.depth),
            (&left_intake.profile.bits, &right_intake.profile.bits),
            (&left_intake.anchor_end, &right_intake.anchor_prev),
        ] {
            left_element.enforce_equal(dr, right_element)?;
        }
        let data = D::just(|| {
            let (left_epoch, left_anchor_prev, _, left_discriminant, left_profile) = left.take();
            let (_, _, right_anchor_end, ..) = right.take();
            (
                left_epoch,
                left_anchor_prev,
                right_anchor_end,
                left_discriminant,
                left_profile,
            )
        });
        let fields = QrIntakeOutput {
            epoch: left_intake.epoch.clone(),
            anchor_prev: left_intake.anchor_prev.clone(),
            anchor_end: right_intake.anchor_end.clone(),
            discriminant: left_intake.discriminant.clone(),
            profile: left_intake.profile.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

/// Partition an intake's members at its own discriminant.
///
/// An empty intake is not split.
///
/// # Soundness
///
/// The product pins the two sides to a factorization of the contents.
/// [`QrSideSelect`] checks the exceptional-value assignment, and
/// [`QrSideDescend`] attests each child's sibling.
/// The contents and both sides open once each at the product challenge.
#[derive(Debug)]
pub struct QrIntakeSplit;

impl Step<Pasta> for QrIntakeSplit {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrIntakeSides;
    type Right = ();
    /// `(non_residue, residue)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(17);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(
                QrResidues,
                witness.1.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .poly(
                QrNonResidues,
                witness.0.as_ref().iter_coeffs().collect::<Vec<_>>(),
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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let z = oracles.zeta().clone();
        let residue_at_z = oracles.output(QrResidues).open(dr, &z)?;
        let non_residue_at_z = oracles.output(QrNonResidues).open(dr, &z)?;
        let contents_at_z = oracles.left(QrContents).open(dr, &z)?;
        let product = residue_at_z.mul(dr, &non_residue_at_z)?;
        contents_at_z.enforce_equal(dr, &product)?;
        // An empty intake's contents are the constant one.
        let one = Element::constant(dr, Fp::ONE);
        contents_at_z.sub(dr, &one).enforce_nonzero(dr)?;

        let non_residue_hash = [
            oracles.bridge_hash().x().clone(),
            oracles.bridge_hash().y().clone(),
        ];
        let [first, second] = non_residue_hash.each_ref().map(Element::value);
        let data = D::just(|| {
            let (epoch, anchor_prev, anchor_end, discriminant, profile) = left.take();
            let () = right.take();
            #[expect(clippy::expect_used, reason = "Ragu supplies commitment coordinates")]
            let bridge_hash = EpAffine::from_xy(*first.take(), *second.take())
                .map(TachygramSetBridge::from)
                .expect("bridge commitment lies on the curve");
            (
                epoch,
                anchor_prev,
                anchor_end,
                discriminant,
                profile,
                bridge_hash,
            )
        });
        let fields = QrIntakeSidesOutput {
            intake: left_encoded.as_gadget().clone(),
            non_residue_hash,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

/// Fix a split's hint commitments and check its exceptional-value assignment.
///
/// The non-residue contents open once at $-R$; the two hint polynomials supply
/// output commitments. [`QrSideDescend`] checks their class identity and
/// rejects a split whose two sides are the same set.
#[derive(Debug)]
pub struct QrSideSelect;

impl Step<Pasta> for QrSideSelect {
    type Aux<'source> = ();
    type Left = QrIntakeSides;
    type Output = QrSideSelection;
    type Right = ();
    /// `(interpolant, quotient)`
    type Witness<'source> = (QrInterpolantPoly, QrQuotientPoly);

    const INDEX: Index = Index::new(38);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(
                QrInterpolant,
                witness.0.as_ref().iter_coeffs().collect::<Vec<_>>(),
            )
            .poly(
                QrQuotient,
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
        let sides = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let exceptional_element = sides
            .intake
            .discriminant
            .add(dr, &sides.intake.profile.depth)
            .negate(dr);
        let value = oracles.left(QrNonResidues).open(dr, &exceptional_element)?;
        value.enforce_nonzero(dr)?;
        // The hints are checked by `QrSideDescend`; opening them here keeps
        // them committed rather than held to the constant one.
        let zeta = oracles.zeta().clone();
        oracles.output(QrInterpolant).open(dr, &zeta)?;
        oracles.output(QrQuotient).open(dr, &zeta)?;
        let encoded = Encoded::from_gadget(sides.clone());
        Ok(((left_encoded, right_encoded, encoded), left, D::unit()))
    }
}

/// Extract one side of a partition and carry it down one level, attesting
/// the other side's class.
///
/// With $s$ the sibling, $u$ its interpolant and $h$ the quotient,
///
/// $$
///   u(X)^2 - c \cdot (X + R) = s(X) \cdot h(X)
/// $$
///
/// at the sibling's class $c$ holds only if every root of $s$ takes that
/// side at $R$, since each root leaves $u(x)^2 = c \cdot (x + R)$. With the
/// split's product, every member of the extracted class is then in the
/// child. A split whose two sides are the same set is rejected.
///
/// # Soundness
///
/// The selection's metadata and non-residue bridge hash match the split.
/// The framework fixes both inputs' polynomials and the side bit before the
/// challenge. Every root of the sibling satisfies $u(x)^2 = c \cdot (x + R)$
/// at the sibling's class $c$, and the split's product places every member of
/// the other class in the child. The child may hold a stray member of the
/// sibling's class; consumers open it nonzero, so a stray member cannot pass a
/// value that is present. $R$ is read off the header, so a descent classifies
/// at the same $R_0$ as every other step of the network. The parent's depth is
/// checked below [`QrProfile::MAX_DEPTH`], so `bits` stays below $2^{32}$ and
/// one depth's paths have distinct profiles.
///
/// Opens both sides, the interpolant, the quotient and the selected output
/// once each at $\zeta$.
#[derive(Debug)]
pub struct QrSideDescend;

impl Step<Pasta> for QrSideDescend {
    type Aux<'source> = ();
    type Left = QrIntakeSides;
    type Output = QrIntake;
    type Right = QrSideSelection;
    /// `(bit,)`
    type Witness<'source> = (bool,);

    const INDEX: Index = Index::new(18);
    const NUM_STAGED: usize = 1;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let selected = if witness.0 {
            left.polynomial(QrResidues)
        } else {
            left.polynomial(QrNonResidues)
        };
        Ok(Prepared::new()
            .poly(QrContents, selected)
            .stage([Fp::from(u64::from(witness.0))]))
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let sides = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let selection = right_encoded.as_gadget();
        for (source, selected) in [
            (&*sides.intake.epoch, &*selection.intake.epoch),
            (&sides.intake.anchor_prev, &selection.intake.anchor_prev),
            (&sides.intake.anchor_end, &selection.intake.anchor_end),
            (&sides.intake.discriminant, &selection.intake.discriminant),
            (&sides.intake.profile.depth, &selection.intake.profile.depth),
            (&sides.intake.profile.bits, &selection.intake.profile.bits),
        ] {
            source.enforce_equal(dr, selected)?;
        }
        for (source, selected) in sides
            .non_residue_hash
            .iter()
            .zip(&selection.non_residue_hash)
        {
            source.enforce_equal(dr, selected)?;
        }
        let bit = Boolean::alloc(dr, &mut (), witness.as_ref().map(|&(bit,)| bit))?;
        let discriminant_element = sides
            .intake
            .discriminant
            .add(dr, &sides.intake.profile.depth);
        let one = Element::constant(dr, Fp::ONE);
        #[expect(
            clippy::indexing_slicing,
            reason = "the framework enforces NUM_STAGED = 1"
        )]
        bit.element().enforce_equal(dr, &oracles.staged()[0])?;
        let z = oracles.zeta().clone();
        let non_residue_at_z = oracles.left(QrNonResidues).open(dr, &z)?;
        let residue_at_z = oracles.left(QrResidues).open(dr, &z)?;
        let delta = non_residue_at_z.sub(dr, &residue_at_z);
        delta.clone().enforce_nonzero(dr)?;
        let selected_delta = bit.element().mul(dr, &delta)?;
        let sibling_at_z = residue_at_z.add(dr, &selected_delta);
        let selected_at_z = non_residue_at_z.sub(dr, &selected_delta);
        oracles
            .output(QrContents)
            .open(dr, &z)?
            .enforce_equal(dr, &selected_at_z)?;
        let interpolant_at_z = oracles.right(QrInterpolant).open(dr, &z)?;
        let quotient_at_z = oracles.right(QrQuotient).open(dr, &z)?;
        let shifted = z.add(dr, &discriminant_element);
        let sibling_product = sibling_at_z.mul(dr, &quotient_at_z)?;
        let interpolant_square = interpolant_at_z.square(dr)?;
        let class_residual = interpolant_square.sub(dr, &sibling_product);
        let scaled_bit = bit
            .element()
            .scale(dr, Coeff::Arbitrary(QUADRATIC_NON_RESIDUE - Fp::ONE));
        let sibling_multiplier = scaled_bit.add(dr, &one);
        let expected_class = sibling_multiplier.mul(dr, &shifted)?;
        class_residual.enforce_equal(dr, &expected_class)?;

        let fields = QrIntakeOutput {
            epoch: sides.intake.epoch.clone(),
            anchor_prev: sides.intake.anchor_prev.clone(),
            anchor_end: sides.intake.anchor_end.clone(),
            discriminant: sides.intake.discriminant.clone(),
            profile: sides.intake.profile.descend(dr, &bit)?,
        };
        let output = D::just(|| {
            let (epoch, anchor_prev, anchor_end, discriminant, profile, _) = left.take();
            (
                epoch,
                anchor_prev,
                anchor_end,
                discriminant,
                profile.descend(bit.value().take()),
            )
        });
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}

/// One profile's members over a whole epoch.
///
/// The bucket covers `[anchor_start, anchor_next)`. Both bounds are boundary
/// digests. The range excludes `anchor_next`. In a bucket that a
/// consensus-accepted spend uses, `anchor_start` is the entry anchor of `epoch`
/// and `anchor_next` is the entry anchor of `epoch + 1`. [`QrBucketSeal`]
/// computes `anchor_next` from the intake's `anchor_end`.
/// [`QrContents`] holds the contents. `contents_hash` is its certified bridge
/// hash.
#[derive(Clone, Debug)]
pub struct QrBucket;

#[derive(Gadget, Write)]
pub struct QrBucketOutput<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub epoch: gadgets::epoch::EpochIndex<'dr, D>,
    pub anchor_start: Element<'dr, D>,
    pub anchor_next: Element<'dr, D>,
    pub discriminant: Element<'dr, D>,
    #[ragu(gadget)]
    pub profile: gadgets::qr::QrProfile<'dr, D>,
    pub contents_hash: [Element<'dr, D>; 2],
}

impl Header<Fp> for QrBucket {
    /// `(epoch, anchor_start, anchor_next, discriminant, profile,
    /// contents_hash)`
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetBridge,
    );
    type OnlinePolyCommit = (Padding, QrContents);
    type Output = Kind![Fp; QrBucketOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        #[expect(
            clippy::expect_used,
            reason = "a bridge hash is the identity only under a discrete-log relation between its generators"
        )]
        let contents_hash = witness.as_ref().map(|&(.., contents_hash)| {
            EpAffine::from(contents_hash)
                .coordinates()
                .expect("bridge hash is not the identity")
        });
        Ok(QrBucketOutput {
            epoch: gadgets::epoch::EpochIndex::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(epoch, ..)| epoch),
            )?,
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(_, anchor_start, ..)| Fp::from(anchor_start)),
            )?,
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(_, _, anchor_next, ..)| Fp::from(anchor_next)),
            )?,
            discriminant: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(_, _, _, discriminant, ..)| Fp::from(discriminant)),
            )?,
            profile: gadgets::qr::QrProfile::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(.., profile, _)| profile),
            )?,
            contents_hash: [
                Element::alloc(
                    dr,
                    allocator,
                    contents_hash.as_ref().map(|coordinates| coordinates.0),
                )?,
                Element::alloc(
                    dr,
                    allocator,
                    contents_hash.as_ref().map(|coordinates| coordinates.1),
                )?,
            ],
        })
    }
}

/// Seal a routed [`QrIntake`] into a [`QrBucket`] that runs boundary to
/// boundary.
///
/// The intake's `anchor_prev` must be the boundary digest of
/// `anchor_final_prev` into `epoch`. It becomes the bucket's `anchor_start`.
/// The step computes the boundary digest of the intake's `anchor_end` into
/// `epoch + 1`, and outputs it as the bucket's `anchor_next`.
///
/// The intake covers stamp absorptions over `(anchor_prev, anchor_end]` within
/// `epoch`. The bucket covers `[anchor_start, anchor_next)`. This range also
/// contains `anchor_start`. `anchor_start` absorbs no tachygrams. Both bucket
/// bounds are boundary digests.
///
/// # Soundness
///
/// Only a boundary digest hashes under the epoch domain. The check shows that
/// `anchor_prev` absorbs `epoch`. This step does not check whether
/// `anchor_prev` is the published entry anchor of `epoch`. `anchor_final_prev`
/// is a free witness. Consensus membership of the consuming lineage's spend
/// anchor binds `anchor_final_prev`. [`Anchor::default`] is the entry anchor of
/// epoch zero. It is the boundary digest of zero into epoch zero.
///
/// The crossing makes a bucket used in a consensus-accepted spend cover the
/// whole epoch. In the accepted chain, the only boundary digest into
/// `epoch + 1` is the one computed from `final(epoch)`. This step outputs
/// `H_epoch(a, epoch + 1)` for the intake's own `a`. If `a` is not
/// `final(epoch)`, the result is outside the accepted chain. A later fold can
/// reach the accepted chain only by producing a Poseidon collision. A bucket
/// sealed before the final anchor cannot support a spend that consensus
/// accepts. Consensus acknowledges every end-of-block anchor. Membership of an
/// end-of-block anchor does not establish whole-epoch coverage.
///
/// `discriminant` is prover-chosen and unchecked here. See [`QrDiscriminant`].
/// The left and output contents open once each to preserve the contents and
/// certify their bridge hash.
///
/// # Caller contract
///
/// The caller confirms that the intake's epoch is before `EPOCH_MAX`, or it
/// risks producing a proof that is false.
#[derive(Debug)]
pub struct QrBucketSeal;

impl Step<Pasta> for QrBucketSeal {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrBucket;
    type Right = ();
    /// `(anchor_final_prev)`
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(20);

    fn prepare(
        &self,
        _: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new().poly(QrContents, left.polynomial(QrContents)))
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let intake = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let next = intake.epoch.next(dr)?;
        let previous = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|&(anchor_final_prev,)| Fp::from(anchor_final_prev)),
        )?;
        let boundary = poseidon::circuit::anchor_next_epoch(dr, &previous, &intake.epoch)?;
        intake.anchor_prev.enforce_equal(dr, &boundary)?;
        let crossing = poseidon::circuit::anchor_next_epoch(dr, &intake.anchor_end, &next)?;
        let fields = QrBucketOutput {
            epoch: intake.epoch.clone(),
            anchor_start: intake.anchor_prev.clone(),
            anchor_next: crossing,
            discriminant: intake.discriminant.clone(),
            profile: intake.profile.clone(),
            contents_hash: [
                oracles.bridge_hash().x().clone(),
                oracles.bridge_hash().y().clone(),
            ],
        };
        let [hash_x, hash_y] = fields.contents_hash.each_ref().map(Element::value);
        let data = D::just(|| {
            let (epoch, anchor_prev, _, discriminant, profile) = left.take();
            #[expect(clippy::expect_used, reason = "Ragu supplies commitment coordinates")]
            let contents_hash = EpAffine::from_xy(*hash_x.take(), *hash_y.take())
                .map(TachygramSetBridge::from)
                .expect("bridge commitment lies on the curve");
            (
                epoch,
                anchor_prev,
                Anchor::from(*fields.anchor_next.value().take()),
                discriminant,
                profile,
                contents_hash,
            )
        });
        let zeta = oracles.zeta().clone();
        let contents = oracles.left(QrContents).open(dr, &zeta)?;
        oracles
            .output(QrContents)
            .open(dr, &zeta)?
            .enforce_equal(dr, &contents)?;
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

/// Start an [`ArbitraryUnspent`] from a [`QrBucket`].
///
/// The step fixes the value's side at every discriminant of the epoch, matches
/// the bucket's profile against the first `depth` of them, and opens the
/// bucket at the value for nonzero. The `MAX_DEPTH` positions
/// $j = 0, 1, \dots$ index the progression, so position $j$
/// classifies at $R_j = R_0 + j$. With $x$ the value and $s_j = x +
/// R_0 + j$, each position witnesses a side $b_j$ and a root $r_j$ with
///
/// $$
///   r_j^2 = \bigl(c - (c - 1) \cdot b_j\bigr) \cdot s_j,
///   \qquad
///   b_j = 0 \implies s_j \neq 0.
/// $$
///
/// A mask $m_j$ selects the bucket's path through two sums and a fold,
///
/// $$
///   \sum_j m_j = \mathsf{depth},
///   \qquad
///   \sum_j j \cdot m_j = \frac{\mathsf{depth} \cdot (\mathsf{depth} - 1)}{2},
///   \qquad
///   a_{j+1} = a_j + m_j \cdot (a_j + b_j),
/// $$
///
/// with $a_0 = 0$; the fold ends at $\mathsf{bits}$ exactly when the
/// bucket's sides are the value's.
///
/// The emitted segment reads the value as a nullifier and takes the bucket's
/// extent, `[anchor_start, anchor_next)`, with epochs `[epoch, epoch + 1)`.
/// Its one member is the value at `epoch`. `anchor_next` is the entry anchor
/// of `epoch + 1`, excluded, so that epoch's nullifier is the next segment's
/// to test. Consecutive epochs' segments meet on that boundary and fuse
/// directly, or [`UnspentLift`](super::pool::UnspentLift) appends the next
/// epoch's bucket in one step.
///
/// # Soundness
///
/// $c$ is a non-residue, so for $s_j \neq 0$ exactly one of $s_j$, $c \cdot
/// s_j$ is a square and $b_j$ is the value's side. For $s_j = 0$ the nonzero
/// rule forces the residue side, where [`QrSideSelect`] files the exceptional
/// value. Among boolean vectors of weight `depth` only the leading positions
/// attain index sum $\mathsf{depth} \cdot (\mathsf{depth} - 1)/2$, so the mask
/// is that prefix and `depth` is at most [`QrProfile::MAX_DEPTH`]. The fold
/// then equals `bits` iff the bucket's sides are the value's first `depth`
/// sides. Positions past `depth` are tested but compared to nothing. $R_0$ is
/// the bucket's own `discriminant`, so the exclusion holds for the network
/// the bucket belongs to. `value` is a free witness. The challenge absorbs
/// it, so the sequence identity fixes the one member to it;
/// [`UnspentBind`](super::pool::UnspentBind) forces that member against the
/// note's genuine derivation.
///
/// [`QrBucketSeal`] performs the boundary digest, and so establishes
/// whole-epoch coverage. This step and every fuse and lift preserve it.
#[derive(Debug)]
pub struct QrUnspentInit;

impl Step<Pasta> for QrUnspentInit {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = ArbitraryUnspent;
    type Right = ();
    /// `(value, classes, mask, sequence)`
    type Witness<'source> = (
        Tachygram,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
    );

    const INDEX: Index = Index::new(19);
    const NUM_STAGED: usize = 1;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        Ok(Prepared::new()
            .poly(NfSeq, witness.3.as_ref().iter_coeffs().collect::<Vec<_>>())
            .stage([Fp::from(witness.0)]))
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let bucket = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let value_element = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(value, ..)| Fp::from(value)),
        )?;
        value_element.clone().enforce_nonzero(dr)?;
        bucket.profile.enforce_sides_of(
            dr,
            &value_element,
            &bucket.discriminant,
            witness.as_ref().map(|&(_, classes, ..)| classes),
            witness.as_ref().map(|&(_, _, mask, _)| mask),
        )?;
        let epoch_next_element = bucket.epoch.next(dr)?;
        #[expect(
            clippy::indexing_slicing,
            reason = "the framework enforces NUM_STAGED = 1"
        )]
        value_element.enforce_equal(dr, &oracles.staged()[0])?;
        let z = oracles.zeta().clone();
        let sequence_at_z = oracles.output(NfSeq).open(dr, &z)?;
        let expected_sequence = gadgets::indexed_multiset::Member {
            index: (*bucket.epoch).clone(),
            value: value_element.clone(),
        }
        .eval(dr, &z)?;
        sequence_at_z.enforce_equal(dr, &expected_sequence)?;
        let contents_at_value = oracles.left(QrContents).open(dr, &value_element)?;
        let nonzero_value = Element::promote(
            contents_at_value.wire().clone(),
            contents_at_value.value().map(|value| *value),
        );
        nonzero_value.enforce_nonzero(dr)?;

        let output = D::just(|| {
            let (bucket_epoch, bucket_anchor_start, bucket_anchor_next, ..) = left.take();
            #[expect(
                clippy::expect_used,
                reason = "QrBucketSeal rejects the final epoch, so only a bucket proof that \
                          doesn't verify carries it"
            )]
            let epoch_next = bucket_epoch.next().expect("bucket epoch has a successor");
            (
                bucket_anchor_start,
                bucket_epoch,
                epoch_next,
                bucket_anchor_next,
            )
        });
        let fields = ArbitraryUnspentOutput {
            anchor_start: bucket.anchor_start.clone(),
            epoch_start: bucket.epoch.clone(),
            epoch_next: epoch_next_element,
            anchor_next: bucket.anchor_next.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}
