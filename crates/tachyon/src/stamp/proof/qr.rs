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
use ragu::{
    Cycle as _, Encoded, FixedGenerators as _, Header, Index, PoseidonPermutation as _, Step,
    StepCtx,
    pasta::{Eq, EqAffine, Fp, Pasta, PoseidonFp},
};
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use ragu_pcd::pasta::baked;
use ragu_primitives::{
    Boolean, Element, GadgetExt as _,
    poseidon::{Sponge, SpongeState},
    vec::FixedVec,
};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use super::{pool::ArbitraryUnspent, summary::Summary};
pub use crate::{
    collections::qr::classify,
    stamp::headers::qr::{QrBucket, QrIntake, QrIntakeSides},
};
use crate::{
    constants::EPOCH_MAX,
    gadgets::arithmetic as circuit,
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrInterpolantPoly, QrProfile,
        QrQuotientPoly, Tachygram, TachygramSetCommit, TachygramSetPoly,
    },
    relations::enforce::{
        bind_poly_handle, enforce_constant_polynomial, enforce_poly_product, indexed_member_factor,
        poly_handle_limbs,
    },
};

#[cfg(test)]
const fn select_sibling_header_commitment(bit: bool, non_residue: Eq, residue: Eq) -> Eq {
    if bit { non_residue } else { residue }
}

/// Start a root intake from a [`Summary`].
///
/// # Soundness
///
/// `discriminant` is a free witness; see [`QrDiscriminant`].
#[derive(Debug)]
pub struct QrSummaryIntake;

impl Step for QrSummaryIntake {
    type Aux<'source> = ();
    type Left = Summary;
    type Output = QrIntake;
    type Right = ();
    type Shared = ();
    /// `(discriminant)`
    type Witness<'source> = (QrDiscriminant,);

    const INDEX: Index = Index::new(15);

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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let discriminant = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0)),
        )?;
        let zero = Element::constant(ctx.dr, Fp::ZERO);
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
        let fields = crate::stamp::headers::qr::QrIntakeOutput {
            epoch: (left_encoded.as_gadget().epoch.element.clone()).into(),
            anchor_prev: (left_encoded.as_gadget().anchor_prev.element.clone()).into(),
            anchor_end: (left_encoded.as_gadget().anchor_end.element.clone()).into(),
            discriminant: (discriminant).into(),
            profile: crate::gadgets::profile::QrProfileGadget {
                depth: zero.clone(),
                bits: zero,
            },
            contents: (left_encoded.as_gadget().acc_commit.encoding.clone()).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
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
#[derive(Debug)]
pub struct QrStampIntakeSeed;

impl Step for QrStampIntakeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrIntake;
    type Right = ();
    type Shared = ();
    /// `(anchor_prev, epoch, discriminant, stamp_commit)`
    type Witness<'source> = (Anchor, EpochIndex, QrDiscriminant, TachygramSetCommit);

    const INDEX: Index = Index::new(21);

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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let discriminant_element = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.2)),
        )?;
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
            witness.as_ref().map(|data| Eq::from(data.3).to_affine()),
        )
        .map(|encoding| encoding.limbs)?;
        let anchor = crate::gadgets::anchor::AnchorGadget::from(previous.clone())
            .next_stamp(ctx.dr, epoch_element.clone(), limbs.clone())
            .map(|anchor| anchor.element)?;
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
                    stamp_commit,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let zero = Element::constant(ctx.dr, Fp::ZERO);
        let fields = crate::stamp::headers::qr::QrIntakeOutput {
            epoch: (epoch_element).into(),
            anchor_prev: (previous).into(),
            anchor_end: (anchor).into(),
            discriminant: (discriminant_element).into(),
            profile: crate::gadgets::profile::QrProfileGadget {
                depth: zero.clone(),
                bits: zero,
            },
            contents: (crate::gadgets::commitment::HostCommitment { limbs }).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
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

impl Step for QrEmptyIntakeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = QrIntake;
    type Right = ();
    type Shared = ();
    /// `(anchor, epoch, discriminant)`
    type Witness<'source> = (Anchor, EpochIndex, QrDiscriminant);

    const INDEX: Index = Index::new(23);

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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let anchor_element = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0)),
        )?;
        let discriminant_element = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.2)),
        )?;
        let epoch_element = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.1)),
        )?;
        circuit::bounded::<D, 32>(ctx.dr, &epoch_element, u64::from(EPOCH_MAX))?;
        let empty = *Pasta::host_generators(baked()).g().first().ok_or_else(|| {
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
                ctx.dr,
                Fp::from_u128(u128::from_le_bytes(low.try_into().map_err(|_err| {
                    ragu_core::Error::InvalidWitness("fixed limb width".into())
                })?)),
            ),
            Element::constant(
                ctx.dr,
                Fp::from_u128(u128::from_le_bytes(high.try_into().map_err(|_err| {
                    ragu_core::Error::InvalidWitness("fixed limb width".into())
                })?)),
            ),
        ];
        let zero = Element::constant(ctx.dr, Fp::ZERO);
        let fields = crate::stamp::headers::qr::QrIntakeOutput {
            epoch: (epoch_element).into(),
            anchor_prev: (anchor_element.clone()).into(),
            anchor_end: (anchor_element).into(),
            discriminant: (discriminant_element).into(),
            profile: crate::gadgets::profile::QrProfileGadget {
                depth: zero.clone(),
                bits: zero,
            },
            contents: (crate::gadgets::commitment::HostCommitment { limbs }).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
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
#[derive(Debug)]
pub struct QrIntakeMerge;

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
impl Step for QrIntakeMerge {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrIntake;
    type Right = QrIntake;
    type Shared = ();
    /// `(left_contents, right_contents, merged)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(16);

    #[expect(
        clippy::too_many_lines,
        reason = "predicates and connected header wiring stay together"
    )]
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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let left_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(left_contents, ..)| left_contents.as_ref().clone()),
        )?;
        let right_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, right_contents, _)| right_contents.as_ref().clone()),
        )?;
        let merged_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, merged)| merged.as_ref().clone()),
        )?;
        bind_poly_handle(
            ctx,
            &left_handle,
            &left_encoded.as_gadget().contents.encoding.limbs,
            "QrIntakeMerge: left contents do not match header",
        )?;
        bind_poly_handle(
            ctx,
            &right_handle,
            &right_encoded.as_gadget().contents.encoding.limbs,
            "QrIntakeMerge: right contents do not match header",
        )?;
        enforce_poly_product(
            ctx,
            &left_handle,
            &right_handle,
            &merged_handle,
            "QrIntakeMerge: merged contents are not the union of the inputs",
        )?;
        for (left_element, right_element, message) in [
            (
                left_encoded.as_gadget().epoch.element.clone(),
                right_encoded.as_gadget().epoch.element.clone(),
                "QrIntakeMerge: inputs cover different epochs",
            ),
            (
                left_encoded.as_gadget().discriminant.element.clone(),
                right_encoded.as_gadget().discriminant.element.clone(),
                "QrIntakeMerge: inputs derive from different discriminants",
            ),
            (
                left_encoded.as_gadget().profile.depth.clone(),
                right_encoded.as_gadget().profile.depth.clone(),
                "QrIntakeMerge: inputs sit at different depths",
            ),
            (
                left_encoded.as_gadget().profile.bits.clone(),
                right_encoded.as_gadget().profile.bits.clone(),
                "QrIntakeMerge: inputs sit at different profiles",
            ),
            (
                left_encoded.as_gadget().anchor_end.element.clone(),
                right_encoded.as_gadget().anchor_prev.element.clone(),
                "QrIntakeMerge: left.anchor_end must equal right.anchor_prev",
            ),
        ] {
            left_element
                .enforce_equal(ctx.dr, &right_element)
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
        let fields = crate::stamp::headers::qr::QrIntakeOutput {
            epoch: (left_encoded.as_gadget().epoch.element.clone()).into(),
            anchor_prev: (left_encoded.as_gadget().anchor_prev.element.clone()).into(),
            anchor_end: (right_encoded.as_gadget().anchor_end.element.clone()).into(),
            discriminant: (left_encoded.as_gadget().discriminant.element.clone()).into(),
            profile: crate::gadgets::profile::QrProfileGadget {
                depth: left_encoded.as_gadget().profile.depth.clone(),
                bits: left_encoded.as_gadget().profile.bits.clone(),
            },
            contents: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &merged_handle)?,
            })
            .into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
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
#[derive(Debug)]
pub struct QrIntakeSplit;

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
impl Step for QrIntakeSplit {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrIntakeSides;
    type Right = ();
    type Shared = ();
    /// `(contents, non_residue, residue)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(17);

    #[expect(
        clippy::too_many_lines,
        reason = "the split keeps the polynomial bindings and computed header in one step"
    )]
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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let contents_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(contents, ..)| contents.as_ref().clone()),
        )?;
        let non_residue_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, non_residue, _)| non_residue.as_ref().clone()),
        )?;
        let residue_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, residue)| residue.as_ref().clone()),
        )?;
        bind_poly_handle(
            ctx,
            &contents_handle,
            &left_encoded.as_gadget().contents.encoding.limbs,
            "QrIntakeSplit: contents do not match header",
        )?;
        enforce_poly_product(
            ctx,
            &non_residue_handle,
            &residue_handle,
            &contents_handle,
            "QrIntakeSplit: the sides do not partition the contents",
        )?;

        let discriminant_element = left_encoded.as_gadget().discriminant.element.clone();
        let [depth_element, _bits_element] = crate::gadgets::profile::QrProfileGadget {
            depth: (left_encoded.as_gadget().profile.depth).clone(),
            bits: (left_encoded.as_gadget().profile.bits).clone(),
        }
        .validate(ctx.dr)?;
        let exceptional_element = discriminant_element
            .add(ctx.dr, &depth_element)
            .negate(ctx.dr);
        let non_residue_assignment = ctx.evaluate(
            &non_residue_handle,
            exceptional_element.value().map(|value| *value),
        )?;
        let non_residue_at_exceptional = Element::alloc(ctx.dr, &mut (), non_residue_assignment)?;
        let nonzero_value = Element::promote(
            non_residue_at_exceptional.wire().clone(),
            non_residue_at_exceptional.value().map(|value| *value),
        );
        nonzero_value.enforce_nonzero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrIntakeSplit: exceptional value claimed the non-residue class".into(),
            )
        })?;
        ctx.enforce_poly_query(
            &non_residue_handle,
            exceptional_element,
            non_residue_at_exceptional,
        )?;

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
        let fields = crate::stamp::headers::qr::QrIntakeSidesOutput {
            epoch: (left_encoded.as_gadget().epoch.element.clone()).into(),
            anchor_prev: (left_encoded.as_gadget().anchor_prev.element.clone()).into(),
            anchor_end: (left_encoded.as_gadget().anchor_end.element.clone()).into(),
            discriminant: (left_encoded.as_gadget().discriminant.element.clone()).into(),
            profile: crate::gadgets::profile::QrProfileGadget {
                depth: left_encoded.as_gadget().profile.depth.clone(),
                bits: left_encoded.as_gadget().profile.bits.clone(),
            },
            non_residue: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &non_residue_handle)?,
            })
            .into(),
            residue: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &residue_handle)?,
            })
            .into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
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
#[derive(Debug)]
pub struct QrSideDescend;

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
impl Step for QrSideDescend {
    type Aux<'source> = ();
    type Left = QrIntakeSides;
    type Output = QrIntake;
    type Right = ();
    type Shared = ();
    /// `(bit, sibling_contents, interpolant, quotient, discriminant_shim)`
    type Witness<'source> = (
        bool,
        TachygramSetPoly,
        QrInterpolantPoly,
        QrQuotientPoly,
        Polynomial<Fp, ProductionRank>,
    );

    const INDEX: Index = Index::new(18);

    #[expect(
        clippy::too_many_lines,
        reason = "the step binds three handles, checks the fixed class identity, and returns the selected header"
    )]
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
        let [depth_element, profile_bits] = crate::gadgets::profile::QrProfileGadget {
            depth: (left_encoded.as_gadget().profile.depth).clone(),
            bits: (left_encoded.as_gadget().profile.bits).clone(),
        }
        .validate(ctx.dr)?;
        circuit::bounded::<D, 5>(ctx.dr, &depth_element, 31).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrSideDescend: profile has no bit left for another side".into(),
            )
        })?;
        let bit = Boolean::alloc(ctx.dr, &mut (), witness.as_ref().map(|data| data.0))?;
        let [non_residue_lo, non_residue_hi] =
            left_encoded.as_gadget().non_residue.encoding.limbs.clone();
        let [residue_lo, residue_hi] = left_encoded.as_gadget().residue.encoding.limbs.clone();
        let sibling_expected_lo = bit.conditional_select(ctx.dr, &residue_lo, &non_residue_lo)?;
        let sibling_expected_hi = bit.conditional_select(ctx.dr, &residue_hi, &non_residue_hi)?;
        let selected_lo = bit.conditional_select(ctx.dr, &non_residue_lo, &residue_lo)?;
        let selected_hi = bit.conditional_select(ctx.dr, &non_residue_hi, &residue_hi)?;
        let base_discriminant = left_encoded.as_gadget().discriminant.element.clone();
        let discriminant_element = base_discriminant.add(ctx.dr, &depth_element);
        let one = Element::constant(ctx.dr, Fp::ONE);
        let next_depth = depth_element.add(ctx.dr, &one);
        let next_bits = profile_bits.double(ctx.dr).add(ctx.dr, &bit.element());
        let sibling_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, sibling, ..)| sibling.as_ref().clone()),
        )?;
        let interpolant_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, interpolant, ..)| interpolant.as_ref().clone()),
        )?;
        let quotient_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, _, quotient, _)| quotient.as_ref().clone()),
        )?;
        let [sibling_lo, sibling_hi] = poly_handle_limbs(ctx.dr, &sibling_handle)?;
        sibling_lo
            .enforce_equal(ctx.dr, &sibling_expected_lo)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSideDescend: sibling does not match the header".into(),
                )
            })?;
        sibling_hi
            .enforce_equal(ctx.dr, &sibling_expected_hi)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSideDescend: sibling does not match the header".into(),
                )
            })?;
        let [interpolant_lo, interpolant_hi] = poly_handle_limbs(ctx.dr, &interpolant_handle)?;
        let [quotient_lo, quotient_hi] = poly_handle_limbs(ctx.dr, &quotient_handle)?;
        let shim_handle = ctx.witness_polynomial(witness.as_ref().map(|data| data.4.clone()))?;
        enforce_constant_polynomial(
            ctx,
            &shim_handle,
            &discriminant_element,
            "QrSideDescend: discriminant shim is not constant",
        )?;
        let [shim_lo, shim_hi] = poly_handle_limbs(ctx.dr, &shim_handle)?;
        let z = ctx.derive_challenge(&(
            [sibling_lo, sibling_hi],
            (
                [interpolant_lo, interpolant_hi],
                [quotient_lo, quotient_hi, shim_lo, shim_hi],
            ),
        ))?;
        let sibling_assignment =
            ctx.evaluate(&sibling_handle, z.value().map(|challenge| *challenge))?;
        let interpolant_assignment =
            ctx.evaluate(&interpolant_handle, z.value().map(|challenge| *challenge))?;
        let quotient_assignment =
            ctx.evaluate(&quotient_handle, z.value().map(|challenge| *challenge))?;
        let sibling_at_z = Element::alloc(ctx.dr, &mut (), sibling_assignment)?;
        let interpolant_at_z = Element::alloc(ctx.dr, &mut (), interpolant_assignment)?;
        let quotient_at_z = Element::alloc(ctx.dr, &mut (), quotient_assignment)?;
        let bit_element = bit.element();
        let shifted = z.add(ctx.dr, &discriminant_element);
        let sibling_product = sibling_at_z.mul(ctx.dr, &quotient_at_z)?;
        let interpolant_square = interpolant_at_z.square(ctx.dr)?;
        let class_residual = interpolant_square.sub(ctx.dr, &sibling_product);
        let multiplier_delta = Element::constant(ctx.dr, Fp::from(4));
        let scaled_bit = bit_element.mul(ctx.dr, &multiplier_delta)?;
        let sibling_multiplier = scaled_bit.add(ctx.dr, &one);
        let expected_class = sibling_multiplier.mul(ctx.dr, &shifted)?;
        class_residual
            .enforce_equal(ctx.dr, &expected_class)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrSideDescend: the sibling fails its class decomposition".into(),
                )
            })?;
        ctx.enforce_poly_query(
            &sibling_handle,
            Element::promote(z.wire().clone(), z.value().map(|challenge| *challenge)),
            sibling_at_z,
        )?;
        ctx.enforce_poly_query(
            &interpolant_handle,
            Element::promote(z.wire().clone(), z.value().map(|challenge| *challenge)),
            interpolant_at_z,
        )?;
        ctx.enforce_poly_query(&quotient_handle, z, quotient_at_z)?;

        let output = D::try_just(|| {
            let low_bytes = selected_lo.value().take().to_bytes();
            let high_bytes = selected_hi.value().take().to_bytes();
            let mut encoding = [0u8; 32];
            encoding[..16].copy_from_slice(&low_bytes[..16]);
            encoding[16..].copy_from_slice(&high_bytes[..16]);
            let selected = EqAffine::from_bytes(encoding).ok_or_else(|| {
                ragu_core::Error::InvalidWitness("invalid selected commitment encoding".into())
            })?;
            let [depth_first, depth_second, depth_third, depth_fourth, ..] =
                next_depth.value().take().to_bytes();
            let [bits_first, bits_second, bits_third, bits_fourth, ..] =
                next_bits.value().take().to_bytes();
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
        let fields = crate::stamp::headers::qr::QrIntakeOutput {
            epoch: (left_encoded.as_gadget().epoch.element.clone()).into(),
            anchor_prev: (left_encoded.as_gadget().anchor_prev.element.clone()).into(),
            anchor_end: (left_encoded.as_gadget().anchor_end.element.clone()).into(),
            discriminant: (left_encoded.as_gadget().discriminant.element.clone()).into(),
            profile: crate::gadgets::profile::QrProfileGadget {
                depth: next_depth,
                bits: next_bits,
            },
            contents: (crate::gadgets::commitment::HostCommitment {
                limbs: [selected_lo, selected_hi],
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

impl Step for QrBucketSeal {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrBucket;
    type Right = ();
    type Shared = ();
    /// `(anchor_final_prev)`
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(20);

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
        let epoch_element = left_encoded.as_gadget().epoch.element.clone();
        let next = crate::gadgets::epoch::EpochIndexGadget::from((epoch_element).clone())
            .next(ctx.dr)
            .map(|epoch| epoch.element)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrBucketSeal: crossing past the final epoch".into(),
                )
            })?;
        let previous = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0)),
        )?;
        let start = left_encoded.as_gadget().anchor_prev.element.clone();
        let end = left_encoded.as_gadget().anchor_end.element.clone();
        let mut boundary_sponge = Sponge::resume(
            SpongeState::from_elements(FixedVec::from_fn(|index| {
                Element::constant(
                    ctx.dr,
                    if index == PoseidonFp::RATE {
                        Fp::from_u128(u128::from_le_bytes(*b"Tachyon-AnchorEp"))
                    } else {
                        Fp::ZERO
                    },
                )
            })),
            Pasta::circuit_poseidon(baked()),
        );
        boundary_sponge.absorb(ctx.dr, &previous)?;
        boundary_sponge.absorb(ctx.dr, &epoch_element)?;
        let boundary = boundary_sponge.squeeze(ctx.dr)?;
        start.enforce_equal(ctx.dr, &boundary).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QrBucketSeal: witnessed boundary digest does not match intake's first anchor"
                    .into(),
            )
        })?;
        let mut crossing_sponge = Sponge::resume(
            SpongeState::from_elements(FixedVec::from_fn(|index| {
                Element::constant(
                    ctx.dr,
                    if index == PoseidonFp::RATE {
                        Fp::from_u128(u128::from_le_bytes(*b"Tachyon-AnchorEp"))
                    } else {
                        Fp::ZERO
                    },
                )
            })),
            Pasta::circuit_poseidon(baked()),
        );
        crossing_sponge.absorb(ctx.dr, &end)?;
        crossing_sponge.absorb(ctx.dr, &next)?;
        let crossing = crossing_sponge.squeeze(ctx.dr)?;
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
        let fields = crate::stamp::headers::qr::QrBucketOutput {
            epoch: (left_encoded.as_gadget().epoch.element.clone()).into(),
            anchor_start: (left_encoded.as_gadget().anchor_prev.element.clone()).into(),
            anchor_next: (crossing).into(),
            discriminant: (left_encoded.as_gadget().discriminant.element.clone()).into(),
            profile: crate::gadgets::profile::QrProfileGadget {
                depth: left_encoded.as_gadget().profile.depth.clone(),
                bits: left_encoded.as_gadget().profile.bits.clone(),
            },
            contents: (left_encoded.as_gadget().contents.encoding.clone()).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
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
#[derive(Debug)]
pub struct QrUnspentInit;

impl Step for QrUnspentInit {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = ArbitraryUnspent;
    type Right = ();
    type Shared = ();
    /// `(value, classes, mask, sequence, contents, value_shim)`
    type Witness<'source> = (
        Tachygram,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
        TachygramSetPoly,
        Polynomial<Fp, ProductionRank>,
    );

    const INDEX: Index = Index::new(19);

    #[expect(
        clippy::too_many_lines,
        reason = "predicates and connected header wiring stay together"
    )]
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
        let value_element = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0)),
        )?;
        value_element
            .clone()
            .enforce_nonzero(ctx.dr)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("QrUnspentInit: tested value is zero".into())
            })?;
        let discriminant_element = left_encoded.as_gadget().discriminant.element.clone();
        crate::gadgets::profile::QrProfileGadget {
            depth: (&[
                left_encoded.as_gadget().profile.depth.clone(),
                left_encoded.as_gadget().profile.bits.clone(),
            ])[0]
                .clone(),
            bits: (&[
                left_encoded.as_gadget().profile.depth.clone(),
                left_encoded.as_gadget().profile.bits.clone(),
            ])[1]
                .clone(),
        }
        .enforce_value(
            ctx.dr,
            &value_element,
            &discriminant_element,
            witness.as_ref().map(|data| data.1),
            witness.as_ref().map(|data| data.2),
        )?;
        let epoch_element = left_encoded.as_gadget().epoch.element.clone();
        let epoch_next = crate::gadgets::epoch::EpochIndexGadget::from((epoch_element).clone())
            .next(ctx.dr)
            .map(|epoch| epoch.element)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("QrUnspentInit: bucket has no next epoch".into())
            })?;
        let native = D::try_just(|| {
            let (value, _, _, sequence, contents, _) = witness.clone().take();
            let (bucket_epoch, bucket_anchor_start, bucket_anchor_next, ..) = left.take();
            let output = (
                bucket_anchor_start,
                bucket_epoch,
                sequence.commit(),
                crate::gadgets::epoch::EpochIndexGadget::from((epoch_next).clone())
                    .value()
                    .take(),
                bucket_anchor_next,
            );
            Ok((sequence, contents, value, bucket_epoch, output))
        })?;
        let sequence_handle = ctx.witness_polynomial(
            native
                .clone()
                .map(|(sequence, ..)| sequence.as_ref().clone()),
        )?;
        let contents_handle = ctx.witness_polynomial(
            native
                .clone()
                .map(|(_, contents, ..)| contents.as_ref().clone()),
        )?;
        bind_poly_handle(
            ctx,
            &contents_handle,
            &left_encoded.as_gadget().contents.encoding.limbs,
            "QrUnspentInit: contents do not match the bucket",
        )?;

        let [sequence_lo, sequence_hi] = poly_handle_limbs(ctx.dr, &sequence_handle)?;
        let shim_handle = ctx.witness_polynomial(witness.as_ref().map(|data| data.5.clone()))?;
        enforce_constant_polynomial(
            ctx,
            &shim_handle,
            &value_element,
            "QrUnspentInit: value shim is not constant",
        )?;
        let [shim_lo, shim_hi] = poly_handle_limbs(ctx.dr, &shim_handle)?;
        let z = ctx.derive_challenge(&([sequence_lo, sequence_hi], [shim_lo, shim_hi]))?;
        let sequence_assignment =
            ctx.evaluate(&sequence_handle, z.value().map(|challenge| *challenge))?;
        let sequence_at_z = Element::alloc(ctx.dr, &mut (), sequence_assignment)?;
        let index_element = epoch_next.clone();
        let expected_sequence = indexed_member_factor(ctx.dr, &value_element, &index_element, &z)?;
        sequence_at_z
            .enforce_equal(ctx.dr, &expected_sequence)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QrUnspentInit: sequence does not match the tested pair".into(),
                )
            })?;
        ctx.enforce_poly_query(&sequence_handle, z, sequence_at_z)?;

        let contents_assignment =
            ctx.evaluate(&contents_handle, value_element.value().map(|value| *value))?;
        let contents_at_value = Element::alloc(ctx.dr, &mut (), contents_assignment)?;
        let nonzero_value = Element::promote(
            contents_at_value.wire().clone(),
            contents_at_value.value().map(|value| *value),
        );
        nonzero_value.enforce_nonzero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("QrUnspentInit: found nullifier in the bucket".into())
        })?;
        ctx.enforce_poly_query(&contents_handle, value_element, contents_at_value)?;

        let output = native.map(|(_, _, _, _, output)| output);
        let fields = crate::stamp::headers::pool::ArbitraryUnspentOutput {
            anchor_start: (left_encoded.as_gadget().anchor_start.element.clone()).into(),
            epoch_start: (left_encoded.as_gadget().epoch.element.clone()).into(),
            epoch_next: (epoch_next).into(),
            anchor_next: (left_encoded.as_gadget().anchor_next.element.clone()).into(),
            elapsed: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &sequence_handle)?,
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

#[cfg(test)]
mod tests {
    use ragu::pasta::Eq;
    use udon::curve::Projective as _;

    use super::select_sibling_header_commitment;

    #[test]
    fn sibling_binding_selects_the_header_side_named_by_the_bit() {
        let non_residue = Eq::generator();
        let residue = non_residue.double();
        assert_ne!(non_residue, residue);
        assert_eq!(
            select_sibling_header_commitment(true, non_residue, residue),
            non_residue
        );
        assert_eq!(
            select_sibling_header_commitment(false, non_residue, residue),
            residue
        );
    }
}
