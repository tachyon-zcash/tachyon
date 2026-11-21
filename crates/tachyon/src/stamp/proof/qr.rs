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

#[cfg(test)]
mod tests;

use core::convert::Infallible;

use ragu::{
    drivers::{Coeff, Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Padding, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
    primitives::{Boolean, Element, GadgetExt as _, allocator::Allocator, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
    udon::{curve::Affine as _, field::Field as _},
};

use super::{
    pool::{ArbitraryUnspent, ArbitraryUnspentOutput},
    summary::Summary,
};
pub use crate::collections::qr::classify;
use crate::{
    collections::qr::QUADRATIC_NON_RESIDUE,
    digest::poseidon,
    gadgets,
    pasta::{EpAffine, Fp},
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, PolySlot, QrClassRoot, QrDiscriminant, QrInterpolantPoly,
        QrProfile, QrQuotientPoly, Tachygram, TachygramSetBridge, TachygramSetPoly,
    },
};

/// Tachygrams under routing, complete for `profile` over the covered span.
///
/// Covers stamp folds over `(anchor_prev, anchor_end]`.
/// A split classifies at `discriminant.at(profile.depth)`. A builder keeps its
/// intake headers unpublished until the epoch closes.
///
/// # Injectivity
///
/// [`QrSummaryIntake`], [`QrStampIntakeSeed`], [`QrEmptyIntakeSeed`],
/// [`QrIntakeMerge`] and [`QrSideDescend`] output this header. A verified
/// `QrIntake` with contents $C$ asserts that `epoch` is an integer at most
/// `EPOCH_MAX`, that `profile` is a [path](QrProfile#injectivity), and that
/// its prover knows a [stamp chain](Anchor#chains-in-a-step) in `epoch` from
/// `anchor_prev` to `anchor_end` for which, with $P$ the product of the
/// chain's polynomials,
///
/// - $C$ divides $P$,
/// - every root of $P$ in the [class](QrDiscriminant#injectivity) of `profile`
///   at `discriminant` is a root of $C$.
///
/// $P$ is the constant one for a chain of no absorptions.
///
/// The assertion is of some chain between the two anchors. The header does
/// not carry the number of absorptions, and nothing here shows that the two
/// anchors have one chain only. [`QrBucket`] shows that of a sealed intake.
///
/// - `anchor_prev` and `anchor_end` are the two ends of the chain.
/// - `epoch` is the epoch that every absorption of the chain absorbs. The
///   `EpochIndex` gadget range-checks the wire where a step allocates it and
///   where a step reads it from an input header. In a chain of no absorptions
///   no digest absorbs `epoch`, and the field is any integer in range.
///   [`QrBucketSeal`] absorbs it into both boundary digests.
/// - `discriminant` and `profile` stand for a class of values. The class is a
///   function of the two fields.
/// - $C$ stands for the roots of $P$ in that class. It has every one of them
///   and no root that $P$ lacks. It may have roots of $P$ outside the class.
///
/// The assertion is about roots because no constraint makes an absorption's
/// polynomial a [set polynomial](crate::collections::multiset). Where each
/// polynomial of the chain is one, a root of $P$ is a tachygram of one of the
/// chain's stamps.
///
/// The first slot is padding. No producer opens it.
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
    type OnlinePolyCommit = (Padding, PolySlot<TachygramSetPoly>);
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
/// Both polynomials are a [`TachygramSetPoly`]: [`QrIntakeSides::RESIDUE`],
/// then [`QrIntakeSides::NON_RESIDUE`].
///
/// # Injectivity
///
/// [`QrIntakeSplit`] outputs this header. Write $\mathsf{Res}$ and
/// $\mathsf{Non}$ for its two polynomials. A verified `QrIntakeSides` asserts
/// that
///
/// - what [`QrIntake`] asserts holds of `intake` with $\mathsf{Res} \cdot
///   \mathsf{Non}$ as the contents,
/// - $\mathsf{Res} \cdot \mathsf{Non}$ is not the constant one,
/// - `non_residue_hash` is a [bridge hash](TachygramSetBridge) of the
///   accumulator of $\mathsf{Non}$.
///
/// No step relies on the second of these. The header asserts nothing about
/// the side of any root, and either polynomial may have roots of either side.
///
/// - `intake` stands for what it stands for in [`QrIntake`].
/// - `non_residue_hash` stands for $\mathsf{Non}$. A bridge hash determines its
///   accumulator and the accumulator's polynomial, so two verified
///   `QrIntakeSides` with one `non_residue_hash` have one $\mathsf{Non}$. This
///   is how a [`QrSideSelection`] speaks about this header's $\mathsf{Non}$.
/// - No field stands for $\mathsf{Res}$. A step reads it from this PCD's slot.
#[derive(Clone, Debug)]
pub struct QrIntakeSides;

/// The members a split files on the residue side.
#[derive(Debug)]
pub struct ResidueSide(Infallible);

/// The members a split files on the non-residue side. Its bridge hash is the
/// header's `non_residue_hash`.
#[derive(Debug)]
pub struct NonResidueSide(Infallible);

impl QrIntakeSides {
    /// The [`NonResidueSide`] polynomial.
    pub const NON_RESIDUE: PolySlot<TachygramSetPoly, NonResidueSide> = PolySlot::new();
    /// The [`ResidueSide`] polynomial.
    pub const RESIDUE: PolySlot<TachygramSetPoly, ResidueSide> = PolySlot::new();
}

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
    type OnlinePolyCommit = (
        PolySlot<TachygramSetPoly, ResidueSide>,
        PolySlot<TachygramSetPoly, NonResidueSide>,
    );
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
///
/// # Injectivity
///
/// [`QrSideSelect`] outputs this header. A verified `QrSideSelection`
/// asserts that a verified [`QrIntakeSides`] has the same eight header
/// elements, and that its non-residue polynomial $\mathsf{Non}$ has
///
/// $$
///   \mathsf{Non}(-(R_0 + d)) \neq 0
/// $$
///
/// for $R_0$ the `discriminant` and $d$ the profile's `depth`.
///
/// The assertion is about a polynomial that is not in this header's slots.
/// `non_residue_hash` stands for it. Every verified [`QrIntakeSides`] with
/// this `non_residue_hash` has this $\mathsf{Non}$, so the assertion holds of
/// each of them. $R_0$ and $d$ stand for the point, which is the one value
/// whose side a root under the non-residue multiplier
/// [does not show](crate::collections::qr#class-decomposition).
///
/// The two slots hold the hints, a [`QrInterpolantPoly`] and a
/// [`QrQuotientPoly`]. The header asserts nothing about them. They sit in a
/// PCD's slots so that they are fixed before the challenge of the step that
/// reads them.
///
/// `Data` is the `Data` of [`QrIntakeSides`] and encodes the same way. The
/// suffix tells the two headers apart.
#[derive(Clone, Debug)]
pub struct QrSideSelection;

impl Header<Fp> for QrSideSelection {
    type Data = <QrIntakeSides as Header<Fp>>::Data;
    type OnlinePolyCommit = (PolySlot<QrInterpolantPoly>, PolySlot<QrQuotientPoly>);
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
/// The input is a verified [`Summary`]. Its prover knows a stamp chain in
/// `epoch` from `anchor_prev` to `anchor_end`, and its
/// [`Summary::ACCUMULATED`] polynomial is the product $P$ of that chain's
/// polynomials.
///
/// The output's contents are committed before the challenge and the
/// accumulated polynomial is in an input's slot. The circuit equates their
/// openings at $\zeta$, so the contents are $P$.
///
/// The output copies `epoch` and both anchors, so the summary's chain is a
/// chain between the output's anchors, and the prover knows it. The output's
/// profile is the constant path of no sides, whose class is every value.
/// $P$ divides itself and has all of its own roots, which is what
/// [`QrIntake`] asserts. `discriminant` is a wire from `Step::Witness`, and
/// any element is a valid [`QrDiscriminant`].
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
        Ok(TachygramSetPoly::SLOT.copy_from(Prepared::new(), &left, Summary::ACCUMULATED))
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
        let accumulated = oracles.left(Summary::ACCUMULATED).open(dr, &z)?;
        let contents = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
        accumulated.enforce_equal(dr, &contents)?;
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
/// The step reads no input. `anchor_prev`, `epoch` and `discriminant` are
/// wires from `Step::Witness`, and `epoch` is range-checked.
///
/// The circuit opens the output's contents $C$ at $\zeta$ and holds the
/// opening different from one. The constant one opens to one at every point,
/// so $C$ is not the constant one.
///
/// `anchor_end` is the [stamp absorption](poseidon::anchor_next_stamp) of
/// `anchor_prev`, `epoch` and the bridge hash of the step's last output slot,
/// which is the slot of $C$. That one absorption is a stamp chain from
/// `anchor_prev` to `anchor_end` that the prover knows, and $P = C$. The
/// profile is the constant path of no sides, so [`QrIntake`]'s assertion holds
/// as it does in [`QrSummaryIntake`].
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
        let stamp = &witness.3;
        Ok(TachygramSetPoly::SLOT.poly(Prepared::new(), stamp))
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
        let stamp_at_z = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
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
/// The step reads no input. `anchor`, `epoch` and `discriminant` are wires
/// from `Step::Witness`, and `epoch` is range-checked.
///
/// The output's contents are committed before the challenge. The circuit
/// holds their opening at $\zeta$ equal to one, so the contents are the
/// constant one.
///
/// The output has `anchor` at both ends, which is a stamp chain of no
/// absorptions with $P = 1$. The constant one divides it, and $P$ has no root.
/// [`QrIntake`]'s assertion holds for any `anchor` and any `epoch`. The step
/// does not show that `epoch` has no stamp or that `anchor` belongs to it.
/// [`QrBucketSeal`] absorbs both into its boundary digests.
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
        let contents = oracles.output(TachygramSetPoly::SLOT).open(dr, &zeta)?;
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
/// Both inputs are verified [`QrIntake`]s. Write $C_L$ and $C_R$ for their
/// contents, and $P_L$ and $P_R$ for the products of the chains their provers
/// know. The circuit holds `epoch`, `discriminant` and both elements of
/// `profile` equal across the inputs, and holds the left `anchor_end` equal to
/// the right `anchor_prev`. The left chain followed by the right chain is a
/// stamp chain in `epoch` from the left `anchor_prev` to the right
/// `anchor_end`, with product $P_L \cdot P_R$, and the prover knows it.
///
/// The two input contents and the output contents are fixed before the
/// challenge. The circuit equates the output's opening at $\zeta$ with the
/// product of the inputs' openings, so the output contents are $C_L \cdot
/// C_R$.
///
/// $C_L \cdot C_R$ divides $P_L \cdot P_R$. A root of $P_L \cdot P_R$ is a
/// root of $P_L$ or of $P_R$. When it is in the class of the shared profile at
/// the shared discriminant, it is a root of $C_L$ or of $C_R$, and so of the
/// product. This is what [`QrIntake`] asserts of the output. The argument does
/// not need the two chains to have different roots.
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
        let merged = &witness.0;
        Ok(TachygramSetPoly::SLOT.poly(Prepared::new(), merged))
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
        let left_contents = oracles.left(TachygramSetPoly::SLOT).open(dr, &z)?;
        let right_contents = oracles.right(TachygramSetPoly::SLOT).open(dr, &z)?;
        let merged_contents = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
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
/// The input is a verified [`QrIntake`] with contents $C$. $C$ is in an
/// input's slot and the output's two polynomials are committed before the
/// challenge. The circuit equates $C(\zeta)$ with $\mathsf{Res}(\zeta) \cdot
/// \mathsf{Non}(\zeta)$, so $C = \mathsf{Res} \cdot \mathsf{Non}$. It holds
/// $C(\zeta)$ different from one, so $C$ is not the constant one.
///
/// The output copies the intake's six elements, so what [`QrIntake`] asserts
/// of them and $C$ holds of them and $\mathsf{Res} \cdot \mathsf{Non}$.
/// `non_residue_hash` is the bridge hash of the step's last output slot, which
/// holds $\mathsf{Non}$. These are the three assertions of
/// [`QrIntakeSides`].
///
/// The step shows a factorization and classifies nothing. [`QrSideSelect`]
/// and [`QrSideDescend`] show the side of one factor's roots.
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
        let (non_residue, residue) = (&witness.0, &witness.1);
        let prepared = QrIntakeSides::RESIDUE.poly(Prepared::new(), residue);
        Ok(QrIntakeSides::NON_RESIDUE.poly(prepared, non_residue))
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
        let residue_at_z = oracles.output(QrIntakeSides::RESIDUE).open(dr, &z)?;
        let non_residue_at_z = oracles.output(QrIntakeSides::NON_RESIDUE).open(dr, &z)?;
        let contents_at_z = oracles.left(TachygramSetPoly::SLOT).open(dr, &z)?;
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
/// The non-residue contents open once at $-R$, and the two hint polynomials
/// supply output commitments. [`QrSideDescend`] checks their class identity.
///
/// # Soundness
///
/// The input is a verified [`QrIntakeSides`]. The circuit computes $-(R_0 +
/// d)$ from the input's `discriminant` and `depth`, opens the input's
/// $\mathsf{Non}$ there and holds the opening nonzero. The point is not a root
/// of $\mathsf{Non}$.
///
/// The output header is the input header's eight elements, unchanged. The
/// input is the verified [`QrIntakeSides`] that [`QrSideSelection`] asserts.
///
/// The circuit opens both output slots at $\zeta$ and constrains neither
/// opening. An opened output slot holds the polynomial the prover committed,
/// and an unopened one would hold the constant one. The two hints are thereby
/// in the output PCD's slots, with nothing shown about them.
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
        let (interpolant, quotient) = (&witness.0, &witness.1);
        let prepared = QrInterpolantPoly::SLOT.poly(Prepared::new(), interpolant);
        Ok(QrQuotientPoly::SLOT.poly(prepared, quotient))
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
        let value = oracles
            .left(QrIntakeSides::NON_RESIDUE)
            .open(dr, &exceptional_element)?;
        value.enforce_nonzero(dr)?;
        // The hints are checked by `QrSideDescend`; opening them here keeps
        // them committed rather than held to the constant one.
        let zeta = oracles.zeta().clone();
        oracles.output(QrInterpolantPoly::SLOT).open(dr, &zeta)?;
        oracles.output(QrQuotientPoly::SLOT).open(dr, &zeta)?;
        let encoded = Encoded::from_gadget(sides.clone());
        Ok(((left_encoded, right_encoded, encoded), left, D::unit()))
    }
}

/// Extract one side of a partition and carry it down one level, attesting
/// the other side's class.
///
/// The step takes a side bit $b$. The child is $\mathsf{Res}$ when $b = 1$ and
/// $\mathsf{Non}$ when $b = 0$, and the sibling is the other polynomial. With
/// $s$ the sibling, $u$ the interpolant, $h$ the quotient and $R = R_0 + d$
/// the discriminant at the parent's depth $d$, the step checks
///
/// $$
///   u(X)^2 - c \cdot (X + R) = s(X) \cdot h(X)
/// $$
///
/// at the sibling's class multiplier $c$.
///
/// # Soundness
///
/// The left input is a verified [`QrIntakeSides`] and the right input a
/// verified [`QrSideSelection`]. The circuit holds their eight header
/// elements equal. The two then carry one `non_residue_hash`, so the
/// polynomial the selection asserts about is the left input's $\mathsf{Non}$,
/// and one `discriminant` and `depth`, so the point is $-R$. Hence
/// $\mathsf{Non}(-R) \neq 0$. The argument does not use the equality of the
/// other four elements.
///
/// The circuit holds $b$ boolean and equal to the staged value, which fixes
/// it before the challenge. $\mathsf{Res}$, $\mathsf{Non}$, $u$ and $h$ are
/// in input slots, the output's contents are committed, and $R$ is a sum of
/// input header fields. All are fixed before the challenge.
///
/// The circuit selects the child's and the sibling's openings at $\zeta$ by
/// $b$. It equates the output contents' opening with the child's, so the
/// output's contents are the child. It equates $u(\zeta)^2 - s(\zeta) \cdot
/// h(\zeta)$ with $c \cdot (\zeta + R)$ for $c = 1 + (n - 1) \cdot b$, which
/// is the non-residue $n$ when the sibling is $\mathsf{Non}$ and one when it
/// is $\mathsf{Res}$. The identity above therefore holds. It is the
/// [class decomposition](crate::collections::qr#class-decomposition) of the
/// sibling. When $b = 0$ every root of $\mathsf{Res}$ takes the residue side
/// at $R$. When $b = 1$ every root of $\mathsf{Non}$ other than $-R$ takes the
/// non-residue side, and $-R$ is not a root. Either way no root of the
/// sibling takes side $b$ at $R$.
///
/// The output keeps the input's `epoch`, anchors and `discriminant`, so the
/// chain the left input's prover knows, with product $P$, is a chain between
/// the output's anchors. The output's profile is the input's path
/// followed by $b$, by the gadget's `descend`. That last side is the side at
/// depth $d$, which classifies at $R$. The left input asserts that
/// $\mathsf{Res} \cdot \mathsf{Non}$ divides $P$ and has every root of $P$ in
/// the parent's class. The child divides the product, so it divides $P$. A root
/// of $P$ in the child's class is in the parent's class and takes side $b$ at
/// $R$. It is a root of the product and not of the sibling, so it is a root of
/// the child. This is what [`QrIntake`] asserts of the output.
///
/// The child may have roots of $P$ that take the sibling's side, because
/// nothing is shown about the child's own roots. [`QrIntake`] allows for
/// them.
///
/// The circuit also holds $\mathsf{Non}(\zeta) - \mathsf{Res}(\zeta)$ nonzero,
/// so the two sides are different polynomials. No step relies on it. When the
/// two sides are one polynomial, the class identity still shows that none of
/// its roots takes side $b$.
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
        let &(bit,) = witness;
        let prepared = if bit {
            TachygramSetPoly::SLOT.copy_from(Prepared::new(), &left, QrIntakeSides::RESIDUE)
        } else {
            TachygramSetPoly::SLOT.copy_from(Prepared::new(), &left, QrIntakeSides::NON_RESIDUE)
        };
        Ok(prepared.stage([Fp::from(u64::from(bit))]))
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
        let non_residue_at_z = oracles.left(QrIntakeSides::NON_RESIDUE).open(dr, &z)?;
        let residue_at_z = oracles.left(QrIntakeSides::RESIDUE).open(dr, &z)?;
        let delta = non_residue_at_z.sub(dr, &residue_at_z);
        delta.clone().enforce_nonzero(dr)?;
        let selected_delta = bit.element().mul(dr, &delta)?;
        let sibling_at_z = residue_at_z.add(dr, &selected_delta);
        let selected_at_z = non_residue_at_z.sub(dr, &selected_delta);
        oracles
            .output(TachygramSetPoly::SLOT)
            .open(dr, &z)?
            .enforce_equal(dr, &selected_at_z)?;
        let interpolant_at_z = oracles.right(QrInterpolantPoly::SLOT).open(dr, &z)?;
        let quotient_at_z = oracles.right(QrQuotientPoly::SLOT).open(dr, &z)?;
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

/// One profile's members between two boundary digests of one epoch.
///
/// The bucket covers `[anchor_start, anchor_next)`. Both bounds are boundary
/// digests. The range excludes `anchor_next`. [`QrBucketSeal`] computes
/// `anchor_next` from the intake's `anchor_end`. The [`TachygramSetPoly`]
/// holds the contents, and `contents_hash` is a bridge hash of its
/// accumulator.
///
/// # Injectivity
///
/// [`QrBucketSeal`] and
/// [`EvidenceTreeOpen`](super::evidence::EvidenceTreeOpen) output this
/// header. A verified `QrBucket` with contents $C$ asserts that its prover
/// knows an anchor $a$ for which
///
/// - `epoch` is an integer $e$ below `EPOCH_MAX`,
/// - `anchor_start` is a [boundary digest](poseidon::anchor_next_epoch) into
///   $e$, and `anchor_next` is the boundary digest of $a$ into $e + 1$,
/// - what [`QrIntake`] asserts holds of `(epoch, anchor_start, a, discriminant,
///   profile)` with $C$ as the contents,
/// - `contents_hash` is a [bridge hash](TachygramSetBridge) of the accumulator
///   of $C$.
///
/// Each field determines what it stands for.
///
/// - `anchor_next` stands for the end of the chain. A boundary digest
///   determines the anchor and the epoch it absorbs, so it determines $a$ and
///   $e + 1$.
/// - `anchor_start` stands for the start of the chain. Take two stamp chains
///   from `anchor_start` to $a$. Each anchor after the first determines the
///   absorption behind it, so walking back from $a$ the two agree for as long
///   as both run. A boundary digest and a stamp absorption have different tags,
///   so no anchor after the first of either chain is `anchor_start`, and
///   neither chain runs on past the other's start. The two are one chain.
///   `anchor_start` and `anchor_next` therefore determine the chain, its number
///   of absorptions and its product $P$.
/// - `epoch` is absorbed by both boundary digests and by every stamp
///   absorption, so either anchor determines it.
/// - `discriminant` and `profile` stand for a class, as in [`QrIntake`].
/// - `contents_hash` stands for $C$ and determines it. $C$ does not determine
///   `contents_hash`, because one accumulator has many bridge hashes.
/// - $C$ stands for the roots of $P$ in the class, as in [`QrIntake`].
///
/// The first slot is padding. No producer opens it.
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
    type OnlinePolyCommit = (Padding, PolySlot<TachygramSetPoly>);
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
/// `epoch`. The bucket covers `[anchor_start, anchor_next)`. `anchor_start`
/// absorbs no tachygrams. Both bucket bounds are boundary digests.
///
/// # Soundness
///
/// The input is a verified [`QrIntake`] with contents $C$ and epoch $e$.
///
/// - The gadget's `next` range-checks $e + 1$ and has no assignment at
///   `EPOCH_MAX`. So $e$ is below `EPOCH_MAX` and the successor is the integer
///   $e + 1$.
/// - The circuit computes the [boundary digest](poseidon::anchor_next_epoch) of
///   `anchor_final_prev` into $e$ and holds the intake's `anchor_prev` equal to
///   it. `anchor_final_prev` is a wire from `Step::Witness`. The bucket's
///   `anchor_start` is therefore a boundary digest into $e$ of an anchor the
///   prover knows.
/// - `anchor_next` is the boundary digest circuit's output on the intake's
///   `anchor_end` and $e + 1$.
/// - The input's contents are in an input slot and the output's are committed
///   before the challenge. The circuit equates their openings at $\zeta$, so
///   the output's contents are $C$. `contents_hash` is the bridge hash of the
///   step's last output slot, which holds $C$.
///
/// `discriminant` and `profile` are copied. With the intake's `anchor_end` as
/// the anchor $a$, these are the four assertions of [`QrBucket`].
///
/// The step does not show that `anchor_final_prev` is the final anchor of
/// any epoch, or that `anchor_end` is the final anchor of $e$. The boundary
/// digests absorb both anchors, so `anchor_start` and `anchor_next` determine
/// them.
///
/// # Caller contract
///
/// The caller confirms that the intake's epoch is before `EPOCH_MAX`. The
/// circuit has no assignment at `EPOCH_MAX`, and proving fails.
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
        Ok(TachygramSetPoly::SLOT.copy_from(Prepared::new(), &left, TachygramSetPoly::SLOT))
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
        let contents = oracles.left(TachygramSetPoly::SLOT).open(dr, &zeta)?;
        oracles
            .output(TachygramSetPoly::SLOT)
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
/// The step takes a value, shows that the bucket's profile is the value's
/// own, and opens the bucket's contents at the value for nonzero.
///
/// The emitted segment reads the value as a nullifier and takes the bucket's
/// extent, `[anchor_start, anchor_next)`, with epochs `[epoch, epoch + 1)`.
/// Its one member is the value at `epoch`. `anchor_next` is the boundary
/// digest into `epoch + 1`, excluded, so that epoch's nullifier is the next
/// segment's to test. Consecutive epochs' segments meet on that boundary and
/// fuse directly, or [`UnspentLift`](super::pool::UnspentLift) appends the
/// next epoch's bucket in one step.
///
/// # Soundness
///
/// The input is a verified [`QrBucket`] with epoch $e$, discriminant $R_0$
/// and contents $C$.
///
/// - `value` is a wire $x$ from `Step::Witness`. The circuit holds it nonzero
///   and equal to the staged value, which fixes it before the challenge.
/// - [`enforce_sides_of`] holds the bucket's `profile` to the path of the first
///   `depth` sides of $x$ at $R_0$, so $x$ is in the bucket's class.
/// - The circuit opens $C$ at $x$ and holds the opening nonzero, so $x$ is not
///   a root of $C$.
/// - The output's sequence is committed before the challenge. The circuit
///   equates its opening at $\zeta$ with $F_{e,\ x}(\zeta)$, computed from the
///   input header's `epoch` and from $x$. The sequence is therefore the
///   [encoding](crate::collections::indexed_multiset) of the one member $x$ at
///   index $e$.
/// - `epoch_next` is the gadget's `next` of the bucket's `epoch`. It
///   range-checks the sum, so `epoch_next` is the integer $e + 1$ and is at
///   most `EPOCH_MAX`.
///
/// The output copies the bucket's `anchor_start` and `anchor_next`. The input
/// is then the bucket by which $x$ is
/// [excluded](ArbitraryUnspent#injectivity) at $e$ between the output's two
/// anchors, and the output is what [`ArbitraryUnspent`] asserts of a segment
/// of the one epoch $e$.
///
/// The step does not show that $x$ is a nullifier.
/// [`UnspentBind`](super::pool::UnspentBind) shows that.
///
/// [`enforce_sides_of`]: gadgets::qr::QrProfile::enforce_sides_of
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
        let sequence = &witness.3;
        Ok(NfSeqPoly::SLOT
            .poly(Prepared::new(), sequence)
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
        let sequence_at_z = oracles.output(NfSeqPoly::SLOT).open(dr, &z)?;
        let expected_sequence = gadgets::indexed_multiset::Member {
            index: (*bucket.epoch).clone(),
            value: value_element.clone(),
        }
        .eval(dr, &z)?;
        sequence_at_z.enforce_equal(dr, &expected_sequence)?;
        let contents_at_value = oracles
            .left(TachygramSetPoly::SLOT)
            .open(dr, &value_element)?;
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
