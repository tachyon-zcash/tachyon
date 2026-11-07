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
    drivers::{Coeff, Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::Pasta,
};
use ragu_primitives::{Boolean, Element, GadgetExt as _, allocator::Allocator, io::Write};
use udon::field::Field as _;

use super::{
    pool::{ArbitraryUnspent, ArbitraryUnspentOutput},
    summary::Summary,
};
pub use crate::collections::qr::classify;
use crate::{
    collections::qr::QUADRATIC_NON_RESIDUE,
    constants::EPOCH_MAX,
    digest::poseidon,
    pasta::Fp,
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrInterpolantPoly, QrProfile,
        QrQuotientPoly, Tachygram, TachygramSetPoly,
    },
    relations::{
        arithmetic as circuit,
        enforce::{enforce_poly_equal, enforce_poly_product, indexed_member_factor},
    },
};

/// Tachygrams under routing, complete for `profile` over `(anchor_prev,
/// anchor_end]`.
///
/// A split classifies at `discriminant.at(profile.depth)`. A builder keeps its
/// intake headers unpublished until the epoch closes.
#[derive(Clone, Debug)]
pub struct QrIntake;

/// `QrIntake` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct QrIntakeOutput<'dr, D: Driver<'dr>> {
    /// `epoch`.
    pub epoch: Element<'dr, D>,
    /// `anchor_prev`.
    pub anchor_prev: Element<'dr, D>,
    /// `anchor_end`.
    pub anchor_end: Element<'dr, D>,
    /// `discriminant`.
    pub discriminant: Element<'dr, D>,
    /// `profile.depth`.
    pub depth: Element<'dr, D>,
    /// `profile.bits`.
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

/// A factorization of one intake's members. Selection checks the exceptional
/// value; descent checks the sibling's class.
///
/// Slots O0/O1 carry the residue/non-residue sides.
#[derive(Clone, Debug)]
pub struct QrIntakeSides;

/// `QrIntakeSides` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct QrIntakeSidesOutput<'dr, D: Driver<'dr>> {
    /// `epoch`.
    pub epoch: Element<'dr, D>,
    /// `anchor_prev`.
    pub anchor_prev: Element<'dr, D>,
    /// `anchor_end`.
    pub anchor_end: Element<'dr, D>,
    /// `discriminant`.
    pub discriminant: Element<'dr, D>,
    /// `profile.depth`.
    pub depth: Element<'dr, D>,
    /// `profile.bits`.
    pub bits: Element<'dr, D>,
    /// Bridge hash of the non-residue polynomial in O1.
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

/// Split metadata and committed hints for a descent.
///
/// Slots O0/O1 carry the interpolant and quotient. The source's bridge hash
/// binds its non-residue polynomial.
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
        let discriminant =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.0)))?;
        let zero = Element::constant(dr, Fp::ZERO);
        let output = D::try_just(|| {
            let (carrier_discriminant,) = witness.take();
            let (summary_epoch, summary_anchor_prev, summary_anchor_end) = left.take();
            let () = right.take();
            Ok((
                (
                    summary_epoch,
                    summary_anchor_prev,
                    summary_anchor_end,
                    carrier_discriminant,
                    QrProfile::ROOT,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let fields = QrIntakeOutput {
            epoch: left_encoded.as_gadget().epoch.clone(),
            anchor_prev: left_encoded.as_gadget().anchor_prev.clone(),
            anchor_end: left_encoded.as_gadget().anchor_end.clone(),
            discriminant,
            depth: zero.clone(),
            bits: zero,
        };
        enforce_poly_equal(dr, oracles, Slot::left(0), Slot::output(0))?;
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
    }
}

/// Start a root intake from one stamp:
/// [`SummarySeed`](super::summary::SummarySeed) with a [`QrIntake`] output.
///
/// # Soundness
///
/// `discriminant` is a free witness; see [`QrDiscriminant`]. `stamp_commit`
/// is folded into `anchor_end`.
/// `O0/O1` carry the stamp, with `O1` providing its bridge hash.
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
        let stamp = witness.3.as_ref().iter_coeffs().collect::<Vec<_>>();
        Ok([stamp.clone(), stamp])
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
        let discriminant_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.2)))?;
        let previous = Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.0)))?;
        let epoch_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.1)))?;
        enforce_poly_equal(dr, oracles, Slot::output(0), Slot::output(1))?;
        super::enforce_stamp_domain(dr, &epoch_element, oracles.bridge_hash())?;
        let anchor = poseidon::with_driver::anchor_next_stamp(
            dr,
            &previous,
            &epoch_element,
            oracles.bridge_hash(),
        )?;
        let output = D::try_just(|| {
            let (anchor_prev, epoch, discriminant, _) = witness.take();
            let () = left.take();
            let () = right.take();
            let anchor_end = Anchor::from(*anchor.value().take());
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
        let zero = Element::constant(dr, Fp::ZERO);
        let fields = QrIntakeOutput {
            epoch: epoch_element,
            anchor_prev: previous,
            anchor_end: anchor,
            discriminant: discriminant_element,
            depth: zero.clone(),
            bits: zero,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
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
///
/// `O0` is committed before ζ and opens to one there, so it is the constant
/// polynomial $1$: the intake holds no member.
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
        let one = Element::constant(dr, Fp::ONE);
        let z = oracles.zeta().clone();
        oracles
            .query(dr, Slot::output(0), &z)?
            .enforce_equal(dr, &one)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("QrEmptyIntakeSeed: intake is not empty".into())
            })?;
        let anchor_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.0)))?;
        let discriminant_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.2)))?;
        let epoch_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.1)))?;
        circuit::bounded::<D, 32>(dr, &epoch_element, u64::from(EPOCH_MAX))?;
        let output = D::try_just(|| {
            let (anchor, epoch, discriminant) = witness.take();
            let () = left.take();
            let () = right.take();
            Ok(((epoch, anchor, anchor, discriminant, QrProfile::ROOT), ()))
        })?;
        let (data, aux) = output.cast();
        let zero = Element::constant(dr, Fp::ZERO);
        let fields = QrIntakeOutput {
            epoch: epoch_element,
            anchor_prev: anchor_element.clone(),
            anchor_end: anchor_element,
            discriminant: discriminant_element,
            depth: zero.clone(),
            bits: zero,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
    }
}

/// Join two same-profile intakes whose spans meet.
///
/// # Soundness
///
/// Both contents are read from the child slots. Consensus
/// forbids republishing a tachygram within two epochs, so the sets are
/// disjoint and the product is the union's root polynomial.
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
        for (left_element, right_element, message) in [
            (
                left_encoded.as_gadget().epoch.clone(),
                right_encoded.as_gadget().epoch.clone(),
                "QrIntakeMerge: inputs cover different epochs",
            ),
            (
                left_encoded.as_gadget().discriminant.clone(),
                right_encoded.as_gadget().discriminant.clone(),
                "QrIntakeMerge: inputs derive from different discriminants",
            ),
            (
                left_encoded.as_gadget().depth.clone(),
                right_encoded.as_gadget().depth.clone(),
                "QrIntakeMerge: inputs sit at different depths",
            ),
            (
                left_encoded.as_gadget().bits.clone(),
                right_encoded.as_gadget().bits.clone(),
                "QrIntakeMerge: inputs sit at different profiles",
            ),
            (
                left_encoded.as_gadget().anchor_end.clone(),
                right_encoded.as_gadget().anchor_prev.clone(),
                "QrIntakeMerge: left.anchor_end must equal right.anchor_prev",
            ),
        ] {
            left_element
                .enforce_equal(dr, &right_element)
                .map_err(|_err| ragu_core::Error::InvalidWitness(message.into()))?;
        }
        let output = D::try_just(|| {
            let (left_epoch, left_anchor_prev, _, left_discriminant, left_profile) = left.take();
            let (_, _, right_anchor_end, ..) = right.take();
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
        let fields = QrIntakeOutput {
            epoch: left_encoded.as_gadget().epoch.clone(),
            anchor_prev: left_encoded.as_gadget().anchor_prev.clone(),
            anchor_end: right_encoded.as_gadget().anchor_end.clone(),
            discriminant: left_encoded.as_gadget().discriminant.clone(),
            depth: left_encoded.as_gadget().depth.clone(),
            bits: left_encoded.as_gadget().bits.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
    }
}

/// Partition an intake's members at its own discriminant.
///
/// # Soundness
///
/// The product pins the two sides to a factorization of the contents.
/// [`QrSideSelect`] checks the exceptional value; [`QrSideDescend`] checks the
/// sibling's class. `L0` is contents; `O0/O1` are residue/non-residue.
/// Each slot opens once at the product challenge.
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
        let fields = QrIntakeSidesOutput {
            epoch: left_encoded.as_gadget().epoch.clone(),
            anchor_prev: left_encoded.as_gadget().anchor_prev.clone(),
            anchor_end: left_encoded.as_gadget().anchor_end.clone(),
            discriminant: left_encoded.as_gadget().discriminant.clone(),
            depth: left_encoded.as_gadget().depth.clone(),
            bits: left_encoded.as_gadget().bits.clone(),
            non_residue_hash: oracles.bridge_hash().clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
    }
}

/// Fix hints in O0/O1 and check the exceptional-value assignment.
///
/// L1 is the non-residue side and opens once at -R. The hints are unopened;
/// descent checks their class identity.
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
        let discriminant = &left_encoded.as_gadget().discriminant;
        let depth = &left_encoded.as_gadget().depth;
        let exceptional_element = discriminant.add(dr, depth).negate(dr);
        let value = oracles.query(dr, Slot::left(1), &exceptional_element)?;
        value.enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrSideSelect: exceptional value claimed the non-residue class".into(),
            )
        })?;
        let fields = QrIntakeSidesOutput {
            epoch: left_encoded.as_gadget().epoch.clone(),
            anchor_prev: left_encoded.as_gadget().anchor_prev.clone(),
            anchor_end: left_encoded.as_gadget().anchor_end.clone(),
            discriminant: left_encoded.as_gadget().discriminant.clone(),
            depth: left_encoded.as_gadget().depth.clone(),
            bits: left_encoded.as_gadget().bits.clone(),
            non_residue_hash: left_encoded.as_gadget().non_residue_hash.clone(),
        };
        let encoded = Encoded::from_gadget(fields);
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
/// The sibling is the input's unselected side slot; the framework challenge
/// fixes both inputs' slots and metadata, and the side bit is staged. Every
/// root of the sibling then satisfies $u(x)^2 = c \cdot (x + R)$ at the
/// sibling's class $c$, and the split's product places every member of the
/// other class in the child. The child may hold a stray member of the
/// sibling's class; consumers open it nonzero, so a stray member cannot pass a
/// value that is present. $R$ is read off the header, so a descent classifies
/// at the same $R_0$ as every other step of the network. The parent's depth is
/// checked below [`QrProfile::MAX_DEPTH`], so `bits` stays below $2^{32}$ and
/// one depth's paths have distinct profiles.
///
/// Polynomial inventory: `L0/L1` are the sides; `R0/R1` are the interpolant
/// and quotient. These four slots and the selected output O0 open once each
/// at zeta, checking the `polynomials()` copy. Matching selection metadata and
/// the non-residue bridge hash binds the exceptional-value check to the same
/// q0.
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
            reason = "a boolean selects one of the two side slots"
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        for (source, selection, message) in [
            (
                &left_encoded.as_gadget().epoch,
                &right_encoded.as_gadget().epoch,
                "QrSideDescend: selection epoch does not match sides",
            ),
            (
                &left_encoded.as_gadget().anchor_prev,
                &right_encoded.as_gadget().anchor_prev,
                "QrSideDescend: selection anchor_prev does not match sides",
            ),
            (
                &left_encoded.as_gadget().anchor_end,
                &right_encoded.as_gadget().anchor_end,
                "QrSideDescend: selection anchor_end does not match sides",
            ),
            (
                &left_encoded.as_gadget().discriminant,
                &right_encoded.as_gadget().discriminant,
                "QrSideDescend: selection discriminant does not match sides",
            ),
            (
                &left_encoded.as_gadget().depth,
                &right_encoded.as_gadget().depth,
                "QrSideDescend: selection depth does not match sides",
            ),
            (
                &left_encoded.as_gadget().bits,
                &right_encoded.as_gadget().bits,
                "QrSideDescend: selection profile does not match sides",
            ),
        ] {
            source
                .enforce_equal(dr, selection)
                .map_err(|_err| ragu_core::Error::InvalidWitness(message.into()))?;
        }
        for (source, selection) in left_encoded
            .as_gadget()
            .non_residue_hash
            .iter()
            .zip(&right_encoded.as_gadget().non_residue_hash)
        {
            source.enforce_equal(dr, selection).map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSideDescend: selection non-residue hash does not match sides".into(),
                )
            })?;
        }
        let depth_element = left_encoded.as_gadget().depth.clone();
        let profile_bits = left_encoded.as_gadget().bits.clone();
        circuit::bounded::<D, 5>(dr, &depth_element, 31).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrSideDescend: profile has no bit left for another side".into(),
            )
        })?;
        let bit = Boolean::alloc(dr, &mut (), witness.as_ref().map(|data| data.0))?;
        let base_discriminant = left_encoded.as_gadget().discriminant.clone();
        let discriminant_element = base_discriminant.add(dr, &depth_element);
        let one = Element::constant(dr, Fp::ONE);
        let next_depth = depth_element.add(dr, &one);
        let next_bits = profile_bits.double(dr).add(dr, &bit.element());
        #[expect(
            clippy::indexing_slicing,
            reason = "the framework enforces NUM_STAGED = 1"
        )]
        bit.element().enforce_equal(dr, &oracles.staged()[0])?;
        let z = oracles.zeta().clone();
        let non_residue_at_z = oracles.query(dr, Slot::left(1), &z)?;
        let residue_at_z = oracles.query(dr, Slot::left(0), &z)?;
        let delta = non_residue_at_z.sub(dr, &residue_at_z);
        let selected_delta = bit.element().mul(dr, &delta)?;
        let sibling_at_z = residue_at_z.add(dr, &selected_delta);
        let selected_at_z = non_residue_at_z.sub(dr, &selected_delta);
        oracles
            .query(dr, Slot::output(0), &z)?
            .enforce_equal(dr, &selected_at_z)?;
        let interpolant_at_z = oracles.query(dr, Slot::right(0), &z)?;
        let quotient_at_z = oracles.query(dr, Slot::right(1), &z)?;
        let bit_element = bit.element();
        let shifted = z.add(dr, &discriminant_element);
        let sibling_product = sibling_at_z.mul(dr, &quotient_at_z)?;
        let interpolant_square = interpolant_at_z.square(dr)?;
        let class_residual = interpolant_square.sub(dr, &sibling_product);
        let scaled_bit = bit_element.scale(dr, Coeff::Arbitrary(QUADRATIC_NON_RESIDUE - Fp::ONE));
        let sibling_multiplier = scaled_bit.add(dr, &one);
        let expected_class = sibling_multiplier.mul(dr, &shifted)?;
        class_residual
            .enforce_equal(dr, &expected_class)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSideDescend: the sibling fails its class decomposition".into(),
                )
            })?;

        let output = D::just(|| {
            let (side, ..) = witness.take();
            let (epoch, anchor_prev, anchor_end, discriminant, profile, _) = left.take();
            (
                epoch,
                anchor_prev,
                anchor_end,
                discriminant,
                profile.descend(side),
            )
        });
        let fields = QrIntakeOutput {
            epoch: left_encoded.as_gadget().epoch.clone(),
            anchor_prev: left_encoded.as_gadget().anchor_prev.clone(),
            anchor_end: left_encoded.as_gadget().anchor_end.clone(),
            discriminant: left_encoded.as_gadget().discriminant.clone(),
            depth: next_depth,
            bits: next_bits,
        };
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
#[derive(Clone, Debug)]
pub struct QrBucket;

/// `QrBucket` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct QrBucketOutput<'dr, D: Driver<'dr>> {
    /// `epoch`.
    pub epoch: Element<'dr, D>,
    /// `anchor_start`.
    pub anchor_start: Element<'dr, D>,
    /// `anchor_next`.
    pub anchor_next: Element<'dr, D>,
    /// `discriminant`.
    pub discriminant: Element<'dr, D>,
    /// `profile.depth`.
    pub depth: Element<'dr, D>,
    /// `profile.bits`.
    pub bits: Element<'dr, D>,
    /// Contents double commitment, certified by the O1 oracle.
    pub contents_bridge_hash: [Element<'dr, D>; 2],
}

impl Header<Fp> for QrBucket {
    /// `(epoch, anchor_start, anchor_next, discriminant, profile,
    /// contents_double)`
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        [Fp; 2],
    );
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
            contents_bridge_hash: [
                Element::alloc(dr, allocator, witness.as_ref().map(|fields| fields.5[0]))?,
                Element::alloc(dr, allocator, witness.as_ref().map(|fields| fields.5[1]))?,
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
/// `L0` is copied to `O0/O1`; the header certifies O1's double commitment.
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
        Ok([left.polynomials[0].clone(), left.polynomials[0].clone()])
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let epoch_element = left_encoded.as_gadget().epoch.clone();
        let next = circuit::epoch_next(dr, &epoch_element).map_err(|_err| {
            ragu_core::Error::InvalidWitness("QrBucketSeal: crossing past the final epoch".into())
        })?;
        let previous = Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.0)))?;
        let start = left_encoded.as_gadget().anchor_prev.clone();
        let end = left_encoded.as_gadget().anchor_end.clone();
        let boundary = poseidon::with_driver::anchor_next_epoch(dr, &previous, &epoch_element)?;
        start.enforce_equal(dr, &boundary).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrBucketSeal: witnessed boundary digest does not match intake's first anchor"
                    .into(),
            )
        })?;
        let crossing = poseidon::with_driver::anchor_next_epoch(dr, &end, &next)?;
        let output = D::try_just(|| {
            let (epoch, anchor_prev, _, discriminant, profile) = left.take();

            Ok((
                (
                    epoch,
                    anchor_prev,
                    Anchor::from(*crossing.value().take()),
                    discriminant,
                    profile,
                    oracles
                        .bridge_hash()
                        .clone()
                        .map(|value| *value.value().take()),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let fields = QrBucketOutput {
            epoch: left_encoded.as_gadget().epoch.clone(),
            anchor_start: left_encoded.as_gadget().anchor_prev.clone(),
            anchor_next: crossing,
            discriminant: left_encoded.as_gadget().discriminant.clone(),
            depth: left_encoded.as_gadget().depth.clone(),
            bits: left_encoded.as_gadget().bits.clone(),
            contents_bridge_hash: oracles.bridge_hash().clone(),
        };
        let z = oracles.zeta().clone();
        let contents_at_z = oracles.query(dr, Slot::left(0), &z)?;
        let output_at_z = oracles.query(dr, Slot::output(0), &z)?;
        let bridge_at_z = oracles.query(dr, Slot::output(1), &z)?;
        contents_at_z.enforce_equal(dr, &output_at_z)?;
        contents_at_z.enforce_equal(dr, &bridge_at_z)?;
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
    }
}

/// Fix `value`'s side at every discriminant of the progression from
/// `discriminant`, and check `profile` is the value's first `depth` sides.
///
/// The relations and their soundness are on [`QrUnspentInit`].
/// [`UnspentLift`](super::pool::UnspentLift) runs the same checks.
#[expect(clippy::indexing_slicing, reason = "fixed 32-position profile arrays")]
pub(super) fn enforce_value_profile<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    value: &Element<'dr, D>,
    discriminant: &Element<'dr, D>,
    depth: &Element<'dr, D>,
    profile_bits: &Element<'dr, D>,
    classes: DriverValue<D, [QrClassRoot; QrProfile::MAX_DEPTH]>,
    mask: DriverValue<D, [bool; QrProfile::MAX_DEPTH]>,
) -> ragu_core::Result<()> {
    let mut shifted = value.add(dr, discriminant);
    let mut depth_acc = Element::constant(dr, Fp::ZERO);
    let mut index_acc = Element::constant(dr, Fp::ZERO);
    let mut bits_acc = Element::constant(dr, Fp::ZERO);
    let one = Element::constant(dr, Fp::ONE);
    let non_residue = Element::constant(dr, QUADRATIC_NON_RESIDUE);
    let mut position_element = Element::constant(dr, Fp::ZERO);
    for position in 0..QrProfile::MAX_DEPTH {
        let side = Boolean::alloc(
            dr,
            &mut (),
            classes.as_ref().map(|values| values[position].0),
        )?;
        let root = Element::alloc(
            dr,
            &mut (),
            classes.as_ref().map(|values| values[position].1),
        )?;
        let selected = Boolean::alloc(dr, &mut (), mask.as_ref().map(|values| values[position]))?;
        let multiplier = side.conditional_select(dr, &non_residue, &one)?;
        let expected_square = multiplier.mul(dr, &shifted)?;
        root.square(dr)?
            .enforce_equal(dr, &expected_square)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QR profile: root does not square to the claimed class".into(),
                )
            })?;
        side.conditional_select(dr, &shifted, &one)?
            .enforce_nonzero(dr)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QR profile: exceptional discriminant claimed the non-residue class".into(),
                )
            })?;
        depth_acc = depth_acc.add(dr, &selected.element());
        let index_term = selected.element().mul(dr, &position_element)?;
        index_acc = index_acc.add(dr, &index_term);
        let selected_term = bits_acc.add(dr, &side.element());
        let bits_term = selected.element().mul(dr, &selected_term)?;
        bits_acc = bits_acc.add(dr, &bits_term);
        shifted = shifted.add(dr, &one);
        position_element = position_element.add(dr, &one);
    }
    depth_acc.enforce_equal(dr, depth).map_err(|_err| {
        ragu_core::Error::InvalidWitness(
            "QR profile: depth mask does not match the bucket's depth".into(),
        )
    })?;
    let depth_minus_one = depth_acc.sub(dr, &one);
    let expected_index_sum = depth_acc.mul(dr, &depth_minus_one)?;
    index_acc
        .double(dr)
        .enforce_equal(dr, &expected_index_sum)
        .map_err(|_err| {
            ragu_core::Error::InvalidWitness("QR profile: depth mask is not a prefix".into())
        })?;
    bits_acc.enforce_equal(dr, profile_bits).map_err(|_err| {
        ragu_core::Error::InvalidWitness(
            "QR profile: value does not take the bucket's profile".into(),
        )
    })?;
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let value_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.0)))?;
        value_element.clone().enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("QrUnspentInit: tested value is zero".into())
        })?;
        let discriminant_element = left_encoded.as_gadget().discriminant.clone();
        enforce_value_profile(
            dr,
            &value_element,
            &discriminant_element,
            &left_encoded.as_gadget().depth,
            &left_encoded.as_gadget().bits,
            witness.as_ref().map(|data| data.1),
            witness.as_ref().map(|data| data.2),
        )?;
        let epoch_element = left_encoded.as_gadget().epoch.clone();
        let epoch_next = circuit::epoch_next(dr, &epoch_element).map_err(|_err| {
            ragu_core::Error::InvalidWitness("QrUnspentInit: bucket has no next epoch".into())
        })?;
        #[expect(
            clippy::indexing_slicing,
            reason = "the framework enforces NUM_STAGED = 1"
        )]
        value_element.enforce_equal(dr, &oracles.staged()[0])?;
        let z = oracles.zeta().clone();
        let sequence_at_z = oracles.query(dr, Slot::output(0), &z)?;
        let index_element = epoch_next.clone();
        let expected_sequence = indexed_member_factor(dr, &value_element, &index_element, &z)?;
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

        let output = D::just(|| {
            let (bucket_epoch, bucket_anchor_start, bucket_anchor_next, ..) = left.take();
            (
                bucket_anchor_start,
                bucket_epoch,
                circuit::epoch_value(&epoch_next).take(),
                bucket_anchor_next,
            )
        });
        let fields = ArbitraryUnspentOutput {
            anchor_start: left_encoded.as_gadget().anchor_start.clone(),
            epoch_start: left_encoded.as_gadget().epoch.clone(),
            epoch_next,
            anchor_next: left_encoded.as_gadget().anchor_next.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}
