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
use ragu_primitives::{Element, GadgetExt as _, allocator::Allocator, io::Write};
use udon::field::Field as _;

use super::{pool::ArbitraryUnspent, summary::Summary};
pub use crate::collections::qr::classify;
use crate::{
    collections::{indexed_multiset, qr::QUADRATIC_NON_RESIDUE},
    digest::poseidon,
    pasta::Fp,
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrInterpolantPoly, QrProfile,
        QrQuotientPoly, Tachygram, TachygramSetPoly,
    },
    ragu_constraint::{enforce_nonzero, enforce_zero},
    relations::enforce::{enforce_poly_equal, enforce_poly_product},
};

/// Tachygrams under routing, complete for `profile` over the covered span.
///
/// Covers stamp folds over `(anchor_prev, anchor_end]`.
/// A split classifies at `discriminant.at(profile.depth)`. A builder keeps its
/// intake headers unpublished until the epoch closes.
#[derive(Clone, Debug)]
pub struct QrIntake;

#[derive(Gadget, Write)]
pub struct QrIntakeOutput<'dr, D: Driver<'dr>> {
    pub epoch: Element<'dr, D>,
    pub anchor_prev: Element<'dr, D>,
    pub anchor_end: Element<'dr, D>,
    pub discriminant: Element<'dr, D>,
    pub depth: Element<'dr, D>,
    pub bits: Element<'dr, D>,
}

impl Header<Fp> for QrIntake {
    /// `(epoch, anchor_prev, anchor_end, discriminant, profile)`
    type Data = (EpochIndex, Anchor, Anchor, QrDiscriminant, QrProfile);
    type Output = Kind![Fp; QrIntakeOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(4);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(QrIntakeOutput {
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
            discriminant: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.3)),
            )?,
            depth: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Fp::from(u64::from(fields.4.depth))),
            )?,
            bits: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Fp::from(u64::from(fields.4.bits))),
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
    pub epoch: Element<'dr, D>,
    pub anchor_prev: Element<'dr, D>,
    pub anchor_end: Element<'dr, D>,
    pub discriminant: Element<'dr, D>,
    pub depth: Element<'dr, D>,
    pub bits: Element<'dr, D>,
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
        [Fp; 2],
    );
    type Output = Kind![Fp; QrIntakeSidesOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(QrIntakeSidesOutput {
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
            discriminant: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.3)),
            )?,
            depth: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Fp::from(u64::from(fields.4.depth))),
            )?,
            bits: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Fp::from(u64::from(fields.4.bits))),
            )?,
            non_residue_hash: [
                Element::alloc(dr, allocator, witness.as_ref().map(|fields| fields.5[0]))?,
                Element::alloc(dr, allocator, witness.as_ref().map(|fields| fields.5[1]))?,
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
    type Output = Kind![Fp; QrIntakeSidesOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(16);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
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
    /// `(discriminant,)`
    type Witness<'source> = (QrDiscriminant,);

    const INDEX: Index = Index::new(15);

    fn polynomials(
        &self,
        _: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([left.polynomials[0].clone(), alloc::vec![Fp::ONE]])
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
            let (discriminant,) = witness.take();
            let (summary_epoch, summary_anchor_prev, summary_anchor_end) = left.take();
            let () = right.take();
            Ok((
                (
                    summary_epoch,
                    summary_anchor_prev,
                    summary_anchor_end,
                    discriminant,
                    QrProfile::ROOT,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        enforce_poly_equal(dr, oracles, Slot::left(0), Slot::output(0))?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Start a root intake from one stamp:
/// [`SummarySeed`](super::summary::SummarySeed) with a [`QrIntake`] output.
///
/// # Soundness
///
/// `discriminant` is a free witness; see [`QrDiscriminant`]. `stamp_commit`
/// is folded into `anchor_end`.
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

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.3.as_ref().iter_coeffs().collect(),
            alloc::vec![Fp::ONE],
        ])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
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
            let (anchor_prev, epoch, discriminant, stamp) = witness.take();
            let stamp_commit = stamp.commit();
            let () = left.take();
            let () = right.take();
            let anchor_end = anchor_prev
                .next_stamp(epoch, &stamp_commit)
                .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
            Ok((
                (
                    epoch,
                    anchor_prev,
                    anchor_end,
                    discriminant,
                    QrProfile::ROOT,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
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
        _oracles: &mut Oracles<'_, 'dr, D>,
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
            let (anchor, epoch, discriminant) = witness.take();
            let () = left.take();
            let () = right.take();
            Ok(((epoch, anchor, anchor, discriminant, QrProfile::ROOT), ()))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
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

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.0.as_ref().iter_coeffs().collect(),
            alloc::vec![Fp::ONE],
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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::right(0),
            &Slot::output(0),
            "QrIntakeMerge: merged contents are not the union of the inputs",
        )?;
        let output = D::try_just(|| {
            let (left_epoch, left_anchor_prev, left_anchor_end, left_discriminant, left_profile) =
                left.take();
            let (
                right_epoch,
                right_anchor_prev,
                right_anchor_end,
                right_discriminant,
                right_profile,
            ) = right.take();
            enforce_zero(
                Fp::from(left_epoch) - Fp::from(right_epoch),
                "QrIntakeMerge: inputs cover different epochs",
            )?;
            enforce_zero(
                Fp::from(left_discriminant) - Fp::from(right_discriminant),
                "QrIntakeMerge: inputs derive from different discriminants",
            )?;
            enforce_zero(
                Fp::from(u64::from(left_profile.depth)) - Fp::from(u64::from(right_profile.depth)),
                "QrIntakeMerge: inputs sit at different depths",
            )?;
            enforce_zero(
                Fp::from(u64::from(left_profile.bits)) - Fp::from(u64::from(right_profile.bits)),
                "QrIntakeMerge: inputs sit at different profiles",
            )?;
            enforce_zero(
                Fp::from(left_anchor_end) - Fp::from(right_anchor_prev),
                "QrIntakeMerge: left.anchor_end must equal right.anchor_prev",
            )?;
            Ok((
                (
                    left_epoch,
                    left_anchor_prev,
                    right_anchor_end,
                    left_discriminant,
                    left_profile,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Partition an intake's members at its own discriminant.
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

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.1.as_ref().iter_coeffs().collect(),
            witness.0.as_ref().iter_coeffs().collect(),
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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::output(0),
            &Slot::output(1),
            &Slot::left(0),
            "QrIntakeSplit: the sides do not partition the contents",
        )?;

        let non_residue_hash = oracles.bridge_hash().each_ref().map(Element::value);
        let output = D::try_just(|| {
            let (epoch, anchor_prev, anchor_end, discriminant, profile) = left.take();
            let () = right.take();
            let [first, second] = non_residue_hash;
            Ok((
                (
                    epoch,
                    anchor_prev,
                    anchor_end,
                    discriminant,
                    profile,
                    [*first.take(), *second.take()],
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        for (output_hash, oracle_hash) in encoded
            .as_gadget()
            .non_residue_hash
            .iter()
            .zip(oracles.bridge_hash())
        {
            output_hash.enforce_equal(dr, oracle_hash)?;
        }
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Fix a split's hint commitments and check its exceptional-value assignment.
///
/// The non-residue contents open once at $-R$; the two hint polynomials supply
/// output commitments. [`QrSideDescend`] checks their class identity.
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
        let exceptional = left.as_ref().map(|data| -data.3.at(data.4.depth));
        let exceptional_element = Element::alloc(dr, &mut (), exceptional)?;
        let value = oracles.query(dr, Slot::left(1), &exceptional_element)?;
        value.enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrSideSelect: exceptional value claimed the non-residue class".into(),
            )
        })?;
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
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
/// child.
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

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        Ok(alloc::vec![Fp::from(u64::from(witness.0))])
    }

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        #[expect(
            clippy::indexing_slicing,
            reason = "a boolean selects index zero or one in a two-slot header"
        )]
        let selected = &left.polynomials[usize::from(!witness.0)];
        Ok([selected.clone(), alloc::vec![Fp::ONE]])
    }

    #[expect(
        clippy::too_many_lines,
        reason = "keep the single-use selection binding and descent identity together"
    )]
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
        // TODO: a real circuit needs a bit decomposition of `depth` here; mock
        // ragu accepts the native comparison.
        let witness_for_native = witness.clone();
        let native = D::try_just(|| {
            let (bit, ..) = witness_for_native.take();
            let source = left.take();
            let (epoch, anchor_prev, anchor_end, discriminant, profile, non_residue_hash) = source;
            let (
                selection_epoch,
                selection_prev,
                selection_end,
                selection_discriminant,
                selection_profile,
                selection_hash,
            ) = right.take();
            for (difference, error) in [
                (
                    Fp::from(epoch) - Fp::from(selection_epoch),
                    "QrSideDescend: selection epoch does not match sides",
                ),
                (
                    Fp::from(anchor_prev) - Fp::from(selection_prev),
                    "QrSideDescend: selection anchor_prev does not match sides",
                ),
                (
                    Fp::from(anchor_end) - Fp::from(selection_end),
                    "QrSideDescend: selection anchor_end does not match sides",
                ),
                (
                    Fp::from(discriminant) - Fp::from(selection_discriminant),
                    "QrSideDescend: selection discriminant does not match sides",
                ),
                (
                    Fp::from(u64::from(profile.depth))
                        - Fp::from(u64::from(selection_profile.depth)),
                    "QrSideDescend: selection depth does not match sides",
                ),
                (
                    Fp::from(u64::from(profile.bits)) - Fp::from(u64::from(selection_profile.bits)),
                    "QrSideDescend: selection profile does not match sides",
                ),
            ] {
                enforce_zero(difference, error)?;
            }
            for (left_hash, right_hash) in non_residue_hash.into_iter().zip(selection_hash) {
                enforce_zero(
                    left_hash - right_hash,
                    "QrSideDescend: selection non-residue hash does not match sides",
                )?;
            }
            if profile.depth >= u32::BITS {
                return Err(ragu_core::Error::InvalidWitness(
                    "QrSideDescend: profile has no bit left for another side".into(),
                ));
            }

            // TODO: a real circuit must constrain `bit` boolean; the type carries it
            // under mock ragu.
            let output = (
                epoch,
                anchor_prev,
                anchor_end,
                discriminant,
                profile.descend(bit),
            );
            Ok((output, bit, discriminant.at(profile.depth)))
        })?;
        let discriminant_element = Element::alloc(
            dr,
            &mut (),
            native
                .clone()
                .map(|(_, _, discriminant_at_depth)| discriminant_at_depth),
        )?;
        let z = oracles.zeta().clone();
        let residue_at_z = oracles.query(dr, Slot::left(0), &z)?;
        let non_residue_at_z = oracles.query(dr, Slot::left(1), &z)?;
        let interpolant_at_z = oracles.query(dr, Slot::right(0), &z)?;
        let quotient_at_z = oracles.query(dr, Slot::right(1), &z)?;
        let bit_element = Element::alloc(
            dr,
            &mut (),
            native.clone().map(|(_, bit, ..)| Fp::from(u64::from(bit))),
        )?;
        let shifted = z.add(dr, &discriminant_element);
        #[expect(
            clippy::indexing_slicing,
            reason = "the framework enforces NUM_STAGED = 1"
        )]
        bit_element.enforce_equal(dr, &oracles.staged()[0])?;
        let sibling_delta = non_residue_at_z.sub(dr, &residue_at_z);
        let selected_delta = bit_element.mul(dr, &sibling_delta)?;
        let sibling_at_z = residue_at_z.add(dr, &selected_delta);
        let selected_at_z = oracles.query(dr, Slot::output(0), &z)?;
        let selected_expected = non_residue_at_z.sub(dr, &selected_delta);
        selected_at_z.enforce_equal(dr, &selected_expected)?;
        let sibling_product = sibling_at_z.mul(dr, &quotient_at_z)?;
        let interpolant_square = interpolant_at_z.square(dr)?;
        let class_residual = interpolant_square.sub(dr, &sibling_product);
        let multiplier_delta = Element::constant(dr, QUADRATIC_NON_RESIDUE - Fp::ONE);
        let scaled_bit = bit_element.mul(dr, &multiplier_delta)?;
        let one = Element::constant(dr, Fp::ONE);
        let sibling_multiplier = scaled_bit.add(dr, &one);
        let expected_class = sibling_multiplier.mul(dr, &shifted)?;
        class_residual
            .enforce_equal(dr, &expected_class)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSideDescend: the sibling fails its class decomposition".into(),
                )
            })?;

        let output = native.map(|(output, ..)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), output.clone())?;
        Ok(((left_encoded, right_encoded, encoded), output, D::unit()))
    }
}

/// One profile's members over a whole epoch.
///
/// The bucket covers `[anchor_start, anchor_next)`. Both bounds are boundary
/// digests. The range excludes `anchor_next`. In a bucket that a
/// consensus-accepted spend uses, `anchor_start` is the entry anchor of `epoch`
/// and `anchor_next` is the entry anchor of `epoch + 1`. [`QrBucketSeal`]
/// computes `anchor_next` from the intake's `anchor_end`.
#[derive(Clone, Debug)]
pub struct QrBucket;

#[derive(Gadget, Write)]
pub struct QrBucketOutput<'dr, D: Driver<'dr>> {
    pub epoch: Element<'dr, D>,
    pub anchor_start: Element<'dr, D>,
    pub anchor_next: Element<'dr, D>,
    pub discriminant: Element<'dr, D>,
    pub depth: Element<'dr, D>,
    pub bits: Element<'dr, D>,
}

impl Header<Fp> for QrBucket {
    /// `(epoch, anchor_start, anchor_next, discriminant, profile)`
    type Data = (EpochIndex, Anchor, Anchor, QrDiscriminant, QrProfile);
    type Output = Kind![Fp; QrBucketOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(QrBucketOutput {
            epoch: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?,
            discriminant: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.3)),
            )?,
            depth: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Fp::from(u64::from(fields.4.depth))),
            )?,
            bits: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|fields| Fp::from(u64::from(fields.4.bits))),
            )?,
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
#[derive(Debug)]
pub struct QrBucketSeal;

impl Step<Pasta> for QrBucketSeal {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrBucket;
    type Right = ();
    /// `(anchor_final_prev,)`
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(20);

    fn polynomials(
        &self,
        _: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([left.polynomials[0].clone(), alloc::vec![Fp::ONE]])
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
            let (anchor_final_prev,) = witness.take();
            let (epoch, anchor_prev, anchor_end, discriminant, profile) = left.take();
            let () = right.take();
            enforce_zero(
                Fp::from(anchor_prev)
                    - poseidon::anchor_next_epoch(Fp::from(anchor_final_prev), Fp::from(epoch)),
                "QrBucketSeal: witnessed boundary digest does not match intake's first anchor",
            )?;
            let epoch_next = epoch.next().ok_or_else(|| {
                ragu_core::Error::InvalidWitness(
                    "QrBucketSeal: crossing past the final epoch".into(),
                )
            })?;
            let crossing = anchor_end
                .next_epoch(epoch_next)
                .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;

            Ok(((epoch, anchor_prev, crossing, discriminant, profile), ()))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        enforce_poly_equal(dr, oracles, Slot::left(0), Slot::output(0))?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Fix `value`'s side at every discriminant of the progression from
/// `discriminant`, and check `profile` is the value's first `depth` sides.
///
/// The relations and their soundness are on [`QrUnspentInit`].
/// [`UnspentLift`](super::pool::UnspentLift) runs the same checks.
pub(super) fn enforce_value_profile(
    value: Tachygram,
    discriminant: QrDiscriminant,
    profile: QrProfile,
    classes: &[QrClassRoot; QrProfile::MAX_DEPTH],
    mask: &[bool; QrProfile::MAX_DEPTH],
) -> ragu_core::Result<()> {
    // TODO: a real circuit must constrain every side and mask bit boolean;
    // the types carry it under mock ragu.
    let mut shifted = Fp::from(value) + Fp::from(discriminant);
    let mut position_fp = Fp::ZERO;
    let mut depth_acc = Fp::ZERO;
    let mut index_acc = Fp::ZERO;
    let mut bits_acc = Fp::ZERO;
    for (&QrClassRoot(side, root), &selected) in classes.iter().zip(mask) {
        let side_fp = Fp::from(u64::from(side));
        let multiplier = QUADRATIC_NON_RESIDUE - ((QUADRATIC_NON_RESIDUE - Fp::ONE) * side_fp);
        enforce_zero(
            root.square() - (multiplier * shifted),
            "QR profile: root does not square to the claimed class",
        )?;
        enforce_nonzero(
            (shifted * (Fp::ONE - side_fp)) + side_fp,
            "QR profile: exceptional discriminant claimed the non-residue class",
        )?;

        let selected_fp = Fp::from(u64::from(selected));
        depth_acc += selected_fp;
        index_acc += selected_fp * position_fp;
        bits_acc += selected_fp * (bits_acc + side_fp);
        shifted += Fp::ONE;
        position_fp += Fp::ONE;
    }
    enforce_zero(
        depth_acc - Fp::from(u64::from(profile.depth)),
        "QR profile: depth mask does not match the bucket's depth",
    )?;
    enforce_zero(
        index_acc.double() - (depth_acc * (depth_acc - Fp::ONE)),
        "QR profile: depth mask is not a prefix",
    )?;
    enforce_zero(
        bits_acc - Fp::from(u64::from(profile.bits)),
        "QR profile: value does not take the bucket's profile",
    )?;
    Ok(())
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

    fn staged(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<Vec<Fp>> {
        Ok(alloc::vec![Fp::from(witness.0)])
    }

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.3.as_ref().iter_coeffs().collect(),
            alloc::vec![Fp::ONE],
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
        let native = D::try_just(|| {
            let (value, classes, mask, _) = witness.take();
            let (bucket_epoch, bucket_anchor_start, bucket_anchor_next, discriminant, profile) =
                left.take();
            let () = right.take();
            enforce_nonzero(Fp::from(value), "QrUnspentInit: tested value is zero")?;
            enforce_value_profile(value, discriminant, profile, &classes, &mask)?;
            let epoch_next = bucket_epoch.next().ok_or_else(|| {
                ragu_core::Error::InvalidWitness("QrUnspentInit: bucket has no next epoch".into())
            })?;
            let output = (
                bucket_anchor_start,
                bucket_epoch,
                epoch_next,
                bucket_anchor_next,
            );
            Ok((value, bucket_epoch, output))
        })?;
        let value_element = Element::alloc(
            dr,
            &mut (),
            native.clone().map(|(value, ..)| Fp::from(value)),
        )?;
        #[expect(
            clippy::indexing_slicing,
            reason = "the framework enforces NUM_STAGED = 1"
        )]
        value_element.enforce_equal(dr, &oracles.staged()[0])?;
        let z = oracles.zeta().clone();
        let sequence_at_z = oracles.query(dr, Slot::output(0), &z)?;
        let challenge = z.value().map(|value| *value);
        let expected = D::try_just(|| {
            let (value, bucket_epoch, _) = native.clone().take();
            Ok(indexed_multiset::direct_eval(
                [(u64::from(bucket_epoch), Fp::from(value))],
                challenge.take(),
            ))
        })?;
        let expected_sequence = Element::alloc(dr, &mut (), expected)?;
        sequence_at_z
            .enforce_equal(dr, &expected_sequence)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrUnspentInit: sequence does not match the tested pair".into(),
                )
            })?;
        let contents_at_value = oracles.query(dr, Slot::left(0), &value_element)?;
        let nonzero_value = Element::promote(
            contents_at_value.wire().clone(),
            contents_at_value.value().map(|value| *value),
        );
        nonzero_value.enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("QrUnspentInit: found nullifier in the bucket".into())
        })?;

        let output = native.map(|(_, _, output)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), output.clone())?;
        Ok(((left_encoded, right_encoded, encoded), output, D::unit()))
    }
}
