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
//! [`QrSideDescend`] carries one side down a level, and [`QrIntakeMerge`]
//! joins two same-profile intakes whose spans meet. [`QrBucketSeal`] admits a
//! routed intake as a [`QrBucket`], and [`QrUnspentInit`] tests a value's
//! profile against a bucket and opens the bucket at it.

extern crate alloc;

pub(super) mod profile;

use alloc::vec::Vec;

use ragu::{Encoded, Header, HeaderInput, Index, Oracles, Slot, Step, Suffix};
use ragu_core::{
    Cycle as _, FixedGenerators as _, PoseidonPermutation as _,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::{Pasta, PoseidonFp},
};
use ragu_primitives::{
    Boolean, Element, GadgetExt as _,
    allocator::Allocator,
    io::Write,
    poseidon::{Sponge, SpongeState},
    vec::FixedVec,
};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use super::{
    pool::{ArbitraryUnspent, ArbitraryUnspentOutput},
    summary::Summary,
};
pub use crate::collections::qr::classify;
use crate::{
    constants::EPOCH_MAX,
    digest::poseidon,
    pasta,
    pasta::{Eq, EqAffine, Fp},
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrInterpolantPoly, QrProfile,
        QrQuotientPoly, Tachygram, TachygramSetCommit, TachygramSetPoly,
    },
    relations::{
        arithmetic as circuit,
        enforce::{enforce_poly_equal, enforce_poly_product, indexed_member_factor},
    },
};

/// Tachygrams under routing. Every member of `contents` takes `profile`, and
/// a split classifies at `discriminant.at(profile.depth)`. A builder keeps its
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
    /// `contents`.
    pub contents: [Element<'dr, D>; 2],
}

impl Header<Fp> for QrIntake {
    /// `(epoch, anchor_prev, anchor_end, discriminant, profile, contents)`.
    /// The contents were drawn from the folds the coverage extent
    /// `(anchor_prev, anchor_end]` certifies; `discriminant` is the network's
    /// $R_0$.
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
    );
    type Output = Kind![Fp; QrIntakeOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(4);

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
            let point = Eq::from(witness.clone().take().5).to_affine();
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
            contents: [
                Element::alloc(dr, allocator, limbs.as_ref().map(|values| values[0]))?,
                Element::alloc(dr, allocator, limbs.as_ref().map(|values| values[1]))?,
            ],
        })
    }
}

/// One intake's members partitioned at its discriminant. Extracting either
/// side attests the other.
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
    /// `non_residue`.
    pub non_residue: [Element<'dr, D>; 2],
    /// `residue`.
    pub residue: [Element<'dr, D>; 2],
}

impl Header<Fp> for QrIntakeSides {
    /// `(epoch, anchor_prev, anchor_end, discriminant, profile, non_residue,
    /// residue)`, the fields of the intake that was split with its two sides
    /// in place of its contents. The sides are ordered by the bit that selects
    /// them: `0 = NQR, 1 = QR`.
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
        TachygramSetCommit,
    );
    type Output = Kind![Fp; QrIntakeSidesOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(10);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        #[expect(
            clippy::expect_used,
            reason = "compressed point limbs contain exactly 16 bytes"
        )]
        let commitments = D::try_just(|| {
            let fields = witness.clone().take();
            let mut limbs = [[Fp::ZERO; 2]; 2];
            for (output, commitment) in limbs
                .iter_mut()
                .zip([Eq::from(fields.5), Eq::from(fields.6)])
            {
                let point = commitment.to_affine();
                if point.is_identity() {
                    return Err(ragu_core::Error::InvalidWitness(
                        "cannot encode the identity commitment".into(),
                    ));
                }
                let bytes = point.to_bytes();
                let (low, high) = bytes.split_at(16);
                *output = [
                    Fp::from_u128(u128::from_le_bytes(low.try_into().expect("16 byte limb"))),
                    Fp::from_u128(u128::from_le_bytes(high.try_into().expect("16 byte limb"))),
                ];
            }
            Ok(limbs)
        })?;
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
            non_residue: [
                Element::alloc(
                    dr,
                    allocator,
                    commitments.as_ref().map(|values| values[0][0]),
                )?,
                Element::alloc(
                    dr,
                    allocator,
                    commitments.as_ref().map(|values| values[0][1]),
                )?,
            ],
            residue: [
                Element::alloc(
                    dr,
                    allocator,
                    commitments.as_ref().map(|values| values[1][0]),
                )?,
                Element::alloc(
                    dr,
                    allocator,
                    commitments.as_ref().map(|values| values[1][1]),
                )?,
            ],
        })
    }
}

/// Start a root intake from a [`Summary`].
///
/// # Soundness
///
/// `discriminant` is a free witness; see [`QrDiscriminant`].
/// `L0` is copied into `O0`.
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

    fn polynomials(
        &self,
        _: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0].clone_from(&left.polynomials[0]);
        Ok(polynomials)
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
            let (summary_epoch, summary_anchor_prev, summary_anchor_end, summary_acc_commit) =
                left.take();
            let () = right.take();
            Ok((
                (
                    summary_epoch,
                    summary_anchor_prev,
                    summary_anchor_end,
                    carrier_discriminant,
                    QrProfile::ROOT,
                    summary_acc_commit,
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
            contents: left_encoded.as_gadget().acc_commit.clone(),
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
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        let stamp = super::coefficients(witness.3.as_ref());
        Ok([stamp.clone(), stamp, alloc::vec![Fp::ONE]])
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
            let (anchor_prev, epoch, discriminant, stamp_commit) = witness.take();
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
                    stamp_commit.commit(),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let zero = Element::constant(dr, Fp::ZERO);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        let fields = QrIntakeOutput {
            epoch: epoch_element,
            anchor_prev: previous,
            anchor_end: anchor,
            discriminant: discriminant_element,
            depth: zero.clone(),
            bits: zero,
            contents: encoded.as_gadget().contents.clone(),
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
        let anchor_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.0)))?;
        let discriminant_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.2)))?;
        let epoch_element =
            Element::alloc(dr, &mut (), witness.as_ref().map(|data| Fp::from(data.1)))?;
        circuit::bounded::<D, 32>(dr, &epoch_element, u64::from(EPOCH_MAX))?;
        let empty = *Pasta::host_generators(pasta::baked())
            .g()
            .first()
            .ok_or_else(|| {
                ragu_core::Error::InvalidWitness("fixed generator table is empty".into())
            })?;
        let output = D::try_just(|| {
            let (anchor, epoch, discriminant) = witness.take();
            let () = left.take();
            let () = right.take();
            Ok((
                (
                    epoch,
                    anchor,
                    anchor,
                    discriminant,
                    QrProfile::ROOT,
                    TachygramSetCommit::from(empty.to_projective()),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let bytes = empty.to_bytes();
        let (low, high) = bytes.split_at(16);
        let limbs = [
            Element::constant(
                dr,
                Fp::from_u128(u128::from_le_bytes(low.try_into().map_err(|_err| {
                    ragu_core::Error::InvalidWitness("fixed limb width".into())
                })?)),
            ),
            Element::constant(
                dr,
                Fp::from_u128(u128::from_le_bytes(high.try_into().map_err(|_err| {
                    ragu_core::Error::InvalidWitness("fixed limb width".into())
                })?)),
            ),
        ];
        let zero = Element::constant(dr, Fp::ZERO);
        let fields = QrIntakeOutput {
            epoch: epoch_element,
            anchor_prev: anchor_element.clone(),
            anchor_end: anchor_element,
            discriminant: discriminant_element,
            depth: zero.clone(),
            bits: zero,
            contents: limbs,
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
/// Both contents are pinned to their headers by commit-equality. Consensus
/// forbids republishing a tachygram within two epochs, so the sets are
/// disjoint and the product is the union's root polynomial.
/// `L0/R0` carry the inputs and `O0` their union.
#[derive(Debug)]
pub struct QrIntakeMerge;

impl Step<Pasta> for QrIntakeMerge {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrIntake;
    type Right = QrIntake;
    /// `(left_contents, right_contents, merged)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(16);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        right: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        super::check_polynomial(
            witness.0.as_ref(),
            &left.polynomials[0],
            "QrIntakeMerge: left contents do not match header",
        )?;
        super::check_polynomial(
            witness.1.as_ref(),
            &right.polynomials[0],
            "QrIntakeMerge: right contents do not match header",
        )?;
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.2.as_ref());
        Ok(polynomials)
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
            let (_, _, merged) = witness.take();
            let (left_epoch, left_anchor_prev, _, left_discriminant, left_profile, _) = left.take();
            let (_, _, right_anchor_end, ..) = right.take();
            Ok((
                (
                    left_epoch,
                    left_anchor_prev,
                    right_anchor_end,
                    left_discriminant,
                    left_profile,
                    merged.commit(),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        let fields = QrIntakeOutput {
            epoch: left_encoded.as_gadget().epoch.clone(),
            anchor_prev: left_encoded.as_gadget().anchor_prev.clone(),
            anchor_end: right_encoded.as_gadget().anchor_end.clone(),
            discriminant: left_encoded.as_gadget().discriminant.clone(),
            depth: left_encoded.as_gadget().depth.clone(),
            bits: left_encoded.as_gadget().bits.clone(),
            contents: encoded.as_gadget().contents.clone(),
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
/// The product pins the two sides to a factorization of the contents;
/// [`QrSideDescend`] attests each child's sibling. The exceptional value $-R$
/// has root $0$ under either class, so the non-residue side must open nonzero
/// there.
/// `L0` is contents; `O0/O1` are non-residue/residue, with `O0` opened twice.
#[derive(Debug)]
pub struct QrIntakeSplit;

impl Step<Pasta> for QrIntakeSplit {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrIntakeSides;
    type Right = ();
    /// `(contents, non_residue, residue)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(17);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        super::check_polynomial(
            witness.0.as_ref(),
            &left.polynomials[0],
            "QrIntakeSplit: contents do not match header",
        )?;
        Ok([
            super::coefficients(witness.1.as_ref()),
            super::coefficients(witness.2.as_ref()),
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
        enforce_poly_product(
            dr,
            oracles,
            &Slot::output(0),
            &Slot::output(1),
            &Slot::left(0),
            "QrIntakeSplit: the sides do not partition the contents",
        )?;

        let discriminant_element = left_encoded.as_gadget().discriminant.clone();
        let [depth_element, _bits_element] = profile::validate(
            dr,
            &left_encoded.as_gadget().depth,
            &left_encoded.as_gadget().bits,
        )?;
        let exceptional_element = discriminant_element.add(dr, &depth_element).negate(dr);
        let non_residue_at_exceptional =
            oracles.query(dr, Slot::output(0), &exceptional_element)?;
        let nonzero_value = Element::promote(
            non_residue_at_exceptional.wire().clone(),
            non_residue_at_exceptional.value().map(|value| *value),
        );
        nonzero_value.enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrIntakeSplit: exceptional value claimed the non-residue class".into(),
            )
        })?;

        let output = D::try_just(|| {
            let (_, non_residue, residue) = witness.take();
            let (epoch, anchor_prev, anchor_end, discriminant, profile, _) = left.take();
            let () = right.take();
            Ok((
                (
                    epoch,
                    anchor_prev,
                    anchor_end,
                    discriminant,
                    profile,
                    non_residue.commit(),
                    residue.commit(),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        let fields = QrIntakeSidesOutput {
            epoch: left_encoded.as_gadget().epoch.clone(),
            anchor_prev: left_encoded.as_gadget().anchor_prev.clone(),
            anchor_end: left_encoded.as_gadget().anchor_end.clone(),
            discriminant: left_encoded.as_gadget().discriminant.clone(),
            depth: left_encoded.as_gadget().depth.clone(),
            bits: left_encoded.as_gadget().bits.clone(),
            non_residue: encoded.as_gadget().non_residue.clone(),
            residue: encoded.as_gadget().residue.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
        ))
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
/// The sibling is pinned to its header commitment; the challenge absorbs the
/// sibling, interpolant and quotient commitments and $R$. $R$ is prover-chosen,
/// so without it a prover could solve the identity for $R$ after $z$. Every
/// root of the sibling then satisfies $u(x)^2 = c \cdot (x + R)$ at the
/// sibling's class $c$, and the split's product places every member of the
/// other class in the child. The child may hold a stray member of the
/// sibling's class; consumers open it nonzero, so a stray member cannot pass a
/// value that is present. $R$ is read off the header, so a descent classifies
/// at the same $R_0$ as every other step of the network. The parent's depth is
/// checked below [`QrProfile::MAX_DEPTH`], so `bits` stays below $2^{32}$ and
/// one depth's paths have distinct profiles.
/// `L0/L1` are the sides; `O0` is selected, `O1` the interpolant, and `O2`
/// the quotient. Five openings; the side bit is staged before ζ.
#[derive(Debug)]
pub struct QrSideDescend;

impl Step<Pasta> for QrSideDescend {
    type Aux<'source> = ();
    type Left = QrIntakeSides;
    type Output = QrIntake;
    type Right = ();
    /// `(bit, sibling_contents, interpolant, quotient)`
    type Witness<'source> = (bool, TachygramSetPoly, QrInterpolantPoly, QrQuotientPoly);

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
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        #[expect(
            clippy::indexing_slicing,
            reason = "a boolean selects one of three slots"
        )]
        let selected = &left.polynomials[usize::from(witness.0)];
        #[expect(
            clippy::indexing_slicing,
            reason = "the opposite boolean selects the sibling slot"
        )]
        super::check_polynomial(
            witness.1.as_ref(),
            &left.polynomials[usize::from(!witness.0)],
            "QrSideDescend: sibling does not match the header",
        )?;
        Ok([
            selected.clone(),
            super::coefficients(witness.2.as_ref()),
            super::coefficients(witness.3.as_ref()),
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
        let [depth_element, profile_bits] = profile::validate(
            dr,
            &left_encoded.as_gadget().depth,
            &left_encoded.as_gadget().bits,
        )?;
        circuit::bounded::<D, 5>(dr, &depth_element, 31).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrSideDescend: profile has no bit left for another side".into(),
            )
        })?;
        let bit = Boolean::alloc(dr, &mut (), witness.as_ref().map(|data| data.0))?;
        let [non_residue_lo, non_residue_hi] = left_encoded.as_gadget().non_residue.clone();
        let [residue_lo, residue_hi] = left_encoded.as_gadget().residue.clone();
        let selected_lo = bit.conditional_select(dr, &non_residue_lo, &residue_lo)?;
        let selected_hi = bit.conditional_select(dr, &non_residue_hi, &residue_hi)?;
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
        let non_residue_at_z = oracles.query_at_zeta(dr, Slot::left(0))?;
        let residue_at_z = oracles.query_at_zeta(dr, Slot::left(1))?;
        let delta = non_residue_at_z.sub(dr, &residue_at_z);
        let selected_delta = bit.element().mul(dr, &delta)?;
        let sibling_at_z = residue_at_z.add(dr, &selected_delta);
        let selected_at_z = non_residue_at_z.sub(dr, &selected_delta);
        oracles
            .query_at_zeta(dr, Slot::output(0))?
            .enforce_equal(dr, &selected_at_z)?;
        let interpolant_at_z = oracles.query_at_zeta(dr, Slot::output(1))?;
        let quotient_at_z = oracles.query_at_zeta(dr, Slot::output(2))?;
        let bit_element = bit.element();
        let shifted = z.add(dr, &discriminant_element);
        let sibling_product = sibling_at_z.mul(dr, &quotient_at_z)?;
        let interpolant_square = interpolant_at_z.square(dr)?;
        let class_residual = interpolant_square.sub(dr, &sibling_product);
        let multiplier_delta = Element::constant(dr, Fp::from(4));
        let scaled_bit = bit_element.mul(dr, &multiplier_delta)?;
        let sibling_multiplier = scaled_bit.add(dr, &one);
        let expected_class = sibling_multiplier.mul(dr, &shifted)?;
        class_residual
            .enforce_equal(dr, &expected_class)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSideDescend: the sibling fails its class decomposition".into(),
                )
            })?;

        let output = D::try_just(|| {
            let low_bytes = selected_lo.value().take().into_inner().to_bytes();
            let high_bytes = selected_hi.value().take().into_inner().to_bytes();
            let mut encoding = [0u8; 32];
            encoding[..16].copy_from_slice(&low_bytes[..16]);
            encoding[16..].copy_from_slice(&high_bytes[..16]);
            let selected = EqAffine::from_bytes(encoding).ok_or_else(|| {
                ragu_core::Error::InvalidWitness("invalid selected commitment encoding".into())
            })?;
            let [depth_first, depth_second, depth_third, depth_fourth, ..] =
                next_depth.value().take().into_inner().to_bytes();
            let [bits_first, bits_second, bits_third, bits_fourth, ..] =
                next_bits.value().take().into_inner().to_bytes();
            let (epoch, start, end, discriminant, ..) = left.take();
            let profile = QrProfile {
                depth: u32::from_le_bytes([depth_first, depth_second, depth_third, depth_fourth]),
                bits: u32::from_le_bytes([bits_first, bits_second, bits_third, bits_fourth]),
            };
            Ok((
                epoch,
                start,
                end,
                discriminant,
                profile,
                TachygramSetCommit::from(selected.to_projective()),
            ))
        })?;
        let fields = QrIntakeOutput {
            epoch: left_encoded.as_gadget().epoch.clone(),
            anchor_prev: left_encoded.as_gadget().anchor_prev.clone(),
            anchor_end: left_encoded.as_gadget().anchor_end.clone(),
            discriminant: left_encoded.as_gadget().discriminant.clone(),
            depth: next_depth,
            bits: next_bits,
            contents: [selected_lo, selected_hi],
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
    /// Contents bridge hash.
    pub contents_bridge_hash: [Element<'dr, D>; 2],
}

impl Header<Fp> for QrBucket {
    /// `(epoch, anchor_start, anchor_next, discriminant, profile, contents)`
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        QrProfile,
        TachygramSetCommit,
    );
    type Output = Kind![Fp; QrBucketOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        let bridge_hash = D::try_just(|| {
            let point = Eq::from(witness.clone().take().5).to_affine();
            if point.is_identity() {
                return Err(ragu_core::Error::InvalidWitness(
                    "cannot hash the identity commitment".into(),
                ));
            }
            Ok(<[Fp; 2]>::from(poseidon::bridge_hash(point)))
        })?;
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
                Element::alloc(dr, allocator, bridge_hash.as_ref().map(|values| values[0]))?,
                Element::alloc(dr, allocator, bridge_hash.as_ref().map(|values| values[1]))?,
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
/// `L0` is copied to `O0/O1`; the header certifies `O1`'s bridge hash.
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

    fn polynomials(
        &self,
        _: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        let contents = left.polynomials[0].clone();
        Ok([contents.clone(), contents, alloc::vec![Fp::ONE]])
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
        let mut boundary_sponge = Sponge::resume(
            SpongeState::from_elements(FixedVec::from_fn(|index| {
                Element::constant(
                    dr,
                    if index == PoseidonFp::RATE {
                        Fp::from_u128(u128::from_le_bytes(*b"Tachyon-AnchorEp"))
                    } else {
                        Fp::ZERO
                    },
                )
            })),
            Pasta::circuit_poseidon(pasta::baked()),
        );
        boundary_sponge.absorb(dr, &previous)?;
        boundary_sponge.absorb(dr, &epoch_element)?;
        let boundary = boundary_sponge.squeeze(dr)?;
        start.enforce_equal(dr, &boundary).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrBucketSeal: witnessed boundary digest does not match intake's first anchor"
                    .into(),
            )
        })?;
        let mut crossing_sponge = Sponge::resume(
            SpongeState::from_elements(FixedVec::from_fn(|index| {
                Element::constant(
                    dr,
                    if index == PoseidonFp::RATE {
                        Fp::from_u128(u128::from_le_bytes(*b"Tachyon-AnchorEp"))
                    } else {
                        Fp::ZERO
                    },
                )
            })),
            Pasta::circuit_poseidon(pasta::baked()),
        );
        crossing_sponge.absorb(dr, &end)?;
        crossing_sponge.absorb(dr, &next)?;
        let crossing = crossing_sponge.squeeze(dr)?;
        let output = D::try_just(|| {
            let (epoch, anchor_prev, _, discriminant, profile, contents) = left.take();

            Ok((
                (
                    epoch,
                    anchor_prev,
                    Anchor::from(*crossing.value().take()),
                    discriminant,
                    profile,
                    contents,
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
        enforce_poly_equal(dr, oracles, Slot::left(0), Slot::output(0))?;
        enforce_poly_equal(dr, oracles, Slot::output(0), Slot::output(1))?;
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            aux,
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
/// rule forces the residue side, where [`QrIntakeSplit`] files the exceptional
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
/// `L0` is bucket contents, `O0` the singleton sequence; `value` is staged.
#[derive(Debug)]
pub struct QrUnspentInit;

impl Step<Pasta> for QrUnspentInit {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = ArbitraryUnspent;
    type Right = ();
    /// `(value, classes, mask, sequence, contents)`
    type Witness<'source> = (
        Tachygram,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
        TachygramSetPoly,
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
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        super::check_polynomial(
            witness.4.as_ref(),
            &left.polynomials[0],
            "QrUnspentInit: contents do not match the bucket",
        )?;
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.3.as_ref());
        Ok(polynomials)
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
        profile::enforce_value(
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
        let native = D::try_just(|| {
            let (value, _, _, sequence, contents) = witness.clone().take();
            let (bucket_epoch, bucket_anchor_start, bucket_anchor_next, ..) = left.take();
            let output = (
                bucket_anchor_start,
                bucket_epoch,
                sequence.commit(),
                circuit::epoch_value(&epoch_next).take(),
                bucket_anchor_next,
            );
            Ok((sequence, contents, value, bucket_epoch, output))
        })?;
        #[expect(
            clippy::indexing_slicing,
            reason = "the framework enforces NUM_STAGED = 1"
        )]
        value_element.enforce_equal(dr, &oracles.staged()[0])?;
        let z = oracles.zeta().clone();
        let sequence_at_z = oracles.query_at_zeta(dr, Slot::output(0))?;
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

        let output = native.map(|(_, _, _, _, output)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), output.clone())?;
        let fields = ArbitraryUnspentOutput {
            anchor_start: left_encoded.as_gadget().anchor_start.clone(),
            epoch_start: left_encoded.as_gadget().epoch.clone(),
            epoch_next,
            anchor_next: left_encoded.as_gadget().anchor_next.clone(),
            elapsed: encoded.as_gadget().elapsed.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}
