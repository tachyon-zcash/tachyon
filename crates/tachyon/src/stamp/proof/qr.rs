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
//! partitions an intake at its discriminant into [`QrIntakeSides`], with
//! non-residue and residue set polynomials $q_0$ and $q_1$.
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
use crate::{
    collections::qr::QUADRATIC_NON_RESIDUE,
    digest::poseidon,
    gadgets,
    pasta::{EpAffine, Fp},
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, PolySlot, QrClass, QrClassRoot, QrDiscriminant,
        QrInterpolantPoly, QrProfile, QrQuotientPoly, Tachygram, TachygramSetBridge,
        TachygramSetPoly,
    },
};

/// Tachygrams under routing, complete for `profile` over the covered span.
///
/// Covers stamp folds over `(anchor_prev, anchor_end]`.
/// A split classifies at `discriminant.at(profile.depth)`. A builder
/// keeps its intake headers unpublished until the epoch closes.
///
/// # Injectivity
///
/// [`QrSummaryIntake`], [`QrStampIntakeSeed`], [`QrEmptyIntakeSeed`],
/// [`QrIntakeMerge`] and [`QrSideDescend`] output this header. A verified
/// `QrIntake` with contents $C$ asserts that `epoch` is an
/// [integer](gadgets::epoch::EpochIndex) at most `EPOCH_MAX`, that `profile` is
/// a [path](QrProfile#injectivity), and that its prover knows a [stamp
/// chain](Anchor#chains-in-a-step) in `epoch` from `anchor_prev` to
/// `anchor_end` for which, with $P$ the product of the chain's polynomials,
///
/// - $C$ divides $P$,
/// - every root of $P$ in the [class](QrDiscriminant#injectivity) of `profile`
///   at `discriminant` is a root of $C$.
///
/// $C$ stands for the roots of $P$ in the class. It has all of them and no
/// root that $P$ lacks, and it may have roots of $P$ outside the class. A root
/// of $P$ is a tachygram where the chain's polynomials are
/// [set polynomials](crate::collections::multiset), which no constraint here
/// makes them.
///
/// The header does not determine the chain. It does not carry the number of
/// absorptions, and nothing here shows that the two anchors have one chain
/// only. [`QrBucket`] shows that of a sealed intake. A chain of no
/// absorptions has $P = 1$ and absorbs `epoch` nowhere, so `epoch` is then
/// any integer in range until [`QrBucketSeal`] absorbs it.
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
/// [`QrIntakeSplit`] outputs this header. With $q_0$ its non-residue
/// polynomial and $q_1$ its residue polynomial, a verified `QrIntakeSides`
/// asserts that
///
/// - what [`QrIntake`] asserts holds of `intake` with $q_0 \cdot q_1$ as the
///   contents,
/// - $q_0 \cdot q_1$ is not the constant one, which no step relies on,
/// - `non_residue_hash` is a [bridge hash](TachygramSetBridge) of the
///   accumulator of $q_0$.
///
/// The header asserts nothing about the side of any root. `non_residue_hash`
/// determines $q_0$, so two verified `QrIntakeSides` with one hash have one
/// $q_0$, which is how a [`QrSideSelection`] speaks of it. No field stands
/// for $q_1$.
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
/// elements and a non-residue polynomial $q_0$ with $q_0(-(R_0 + j)) \neq 0$,
/// for $R_0$ the `discriminant` and $j$ the profile's `depth`. That point is
/// the one value whose side a class root under the non-residue multiplier
/// [does not show](crate::collections::qr#class-decomposition).
///
/// $q_0$ is not in this header's slots. `non_residue_hash`
/// [determines it](QrIntakeSides#injectivity), so the assertion holds of
/// every verified [`QrIntakeSides`] with this hash. The header asserts
/// nothing about the two hints in its slots. They sit there so that they are
/// fixed before the challenge of the step that reads them.
///
/// `Data` is the `Data` of [`QrIntakeSides`]. The suffix tells the two
/// headers apart.
#[derive(Clone, Debug)]
pub struct QrSideSelection;

impl Header<Fp> for QrSideSelection {
    /// `(epoch, anchor_prev, anchor_end, discriminant, profile,
    /// non_residue_hash)`
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
/// The output's contents are committed before the challenge and the input's
/// [`Summary::ACCUMULATED`] is in an input slot. The circuit equates their
/// openings at $\zeta$, so the contents are the product $P$ of the chain that
/// [`Summary`] asserts. `epoch` and both anchors are copied, so that chain is
/// the output's. The profile is the constant path of no sides, whose class is
/// every value. `discriminant` is a wire from `Step::Witness`. See [Choosing
/// the first discriminant](QrDiscriminant#choosing-the-first-discriminant).
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
/// `anchor_prev`, `epoch` and `discriminant` are wires from `Step::Witness`,
/// and `epoch` is range-checked. The circuit holds the opening of the output's
/// contents $C$ at $\zeta$ different from one, so $C$ is not the constant one.
/// `anchor_end` is the [stamp absorption](poseidon::anchor_next_stamp) of
/// `anchor_prev`, `epoch` and the bridge hash of the step's last output slot,
/// which holds $C$. That absorption is the chain, with $P = C$, and the
/// profile is the constant path of no sides.
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
/// `anchor`, `epoch` and `discriminant` are wires from `Step::Witness`, and
/// `epoch` is range-checked. The output's contents are committed before the
/// challenge and the circuit holds their opening at $\zeta$ equal to one, so
/// they are the constant one. With `anchor` at both ends the chain has no
/// absorptions, and $P = 1$ has no root.
///
/// The step does not show that `epoch` has no stamp or that `anchor` belongs
/// to it. [`QrBucketSeal`] absorbs both into its boundary digests.
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
/// Write $C_L$, $C_R$ for the inputs' contents and $P_L$, $P_R$ for the
/// products of their chains. The circuit holds `epoch`, `discriminant` and
/// both elements of `profile` equal across the inputs, and the left
/// `anchor_end` equal to the right `anchor_prev`. The left chain followed by
/// the right chain is then a chain between the output's anchors, with product
/// $P_L \cdot P_R$.
///
/// All three contents are fixed before the challenge. The circuit equates the
/// output's opening at $\zeta$ with the product of the inputs', so the
/// output's contents are $C_L \cdot C_R$, which divides $P_L \cdot P_R$. A
/// root of $P_L \cdot P_R$ in the shared class is a root of $P_L$ or of $P_R$,
/// so of $C_L$ or of $C_R$. The argument does not need the two chains to have
/// different roots.
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
/// The input's contents $C$ are in an input slot and the output's two
/// polynomials are committed before the challenge. The circuit equates
/// $C(\zeta)$ with $q_0(\zeta) \cdot q_1(\zeta)$, so $C = q_0 \cdot q_1$, and
/// holds $C(\zeta)$ different from one, so $C$ is not the constant one. The
/// intake's six elements are copied. `non_residue_hash` is the bridge hash of
/// the step's last output slot, which holds $q_0$.
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
/// The non-residue set polynomial $q_0$ opens once at $-R$; the two hint
/// polynomials supply output commitments. [`QrSideDescend`] checks their class
/// identity and rejects a split whose two sides are the same set.
///
/// # Soundness
///
/// The circuit computes $-(R_0 + j)$ from the input header's `discriminant`
/// and `depth`, opens the input's $q_0$ there and holds the opening nonzero.
/// The output header is the input's eight elements, so the input is the
/// [`QrIntakeSides`] that [`QrSideSelection`] asserts. The circuit opens both
/// output slots at $\zeta$ and constrains neither opening, so each holds the
/// hint the prover committed.
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
/// For the sibling's set polynomial $q$, interpolant $u$ and quotient $h$,
/// the class decomposition satisfies
///
/// $$
///   u(X)^2 - m \cdot (X + R) = q(X) \cdot h(X).
/// $$
///
/// The discriminant is $R = R_0 + j$ at parent depth $j$. For child bit $b$,
/// the sibling's multiplier is $m = 1 + b(c - 1)$, with $c$ the fixed
/// non-residue. A residue child has a non-residue sibling, so the multiplier
/// is the opposite of the one used to check the queried class directly.
/// The identity and the exceptional-value check attest the sibling's class:
/// at every member $x_i$, the class root $r_i = u(x_i)$ satisfies
/// $r_i^2 = m \cdot (x_i + R)$. The split's product then places every
/// member of the extracted class in the child. Equal side openings are
/// rejected.
///
/// Opens both sides, the interpolant, the quotient and the selected output
/// once each at $\zeta$.
///
/// # Soundness
///
/// The circuit holds the two inputs' eight header elements equal, and the
/// argument uses `non_residue_hash`, `discriminant` and `depth` only. With one
/// hash, the polynomial the [`QrSideSelection`] asserts about is the left
/// input's $q_0$, and its point is $-R$, so $q_0(-R) \neq 0$.
///
/// The circuit holds $b$ boolean and equal to the staged value. With $q_0$,
/// $q_1$, $u$ and $h$ in input slots, the output's contents committed and $R$
/// a sum of input header fields, all are fixed before the challenge.
///
/// The child is $q_1$ when $b = 1$ and $q_0$ when $b = 0$, and the sibling
/// $q$ is the other. The circuit selects their openings at $\zeta$ by $b$. It
/// equates the output contents' opening with the child's, so the output's
/// contents are the child. It equates $u(\zeta)^2 - q(\zeta) \cdot h(\zeta)$
/// with $m \cdot (\zeta + R)$, so the identity above holds. By the
/// [class decomposition](crate::collections::qr#class-decomposition) and
/// $q_0(-R) \neq 0$, no root of the sibling takes side $b$ at $R$.
///
/// The output keeps the input's `epoch`, anchors and `discriminant`, so the
/// left input's chain, with product $P$, is the output's. Its profile is the
/// input's path followed by $b$, by the gadget's `descend`, and depth $j$
/// classifies at $R$. The child divides $q_0 \cdot q_1$ and so $P$. A root of
/// $P$ in the child's class is in the parent's class and takes side $b$ at
/// $R$. It is a root of the product and not of the sibling, so it is a root
/// of the child. Nothing is shown of the child's other roots.
///
/// The circuit also holds $q_0(\zeta) - q_1(\zeta)$ nonzero, so the two sides
/// are different polynomials. No step relies on it, since the class identity
/// holds of the sibling either way.
#[derive(Debug)]
pub struct QrSideDescend;

impl Step<Pasta> for QrSideDescend {
    type Aux<'source> = ();
    type Left = QrIntakeSides;
    type Output = QrIntake;
    type Right = QrSideSelection;
    /// `(class,)`
    type Witness<'source> = (QrClass,);

    const INDEX: Index = Index::new(18);
    const NUM_STAGED: usize = 1;

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        left: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let &(class,) = witness;
        let prepared = match class {
            QrClass::NonResidue => {
                TachygramSetPoly::SLOT.copy_from(Prepared::new(), &left, QrIntakeSides::NON_RESIDUE)
            },
            QrClass::Residue => {
                TachygramSetPoly::SLOT.copy_from(Prepared::new(), &left, QrIntakeSides::RESIDUE)
            },
        };
        Ok(prepared.stage([Fp::from(u64::from(class.bit()))]))
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
        let bit = Boolean::alloc(dr, &mut (), witness.as_ref().map(|&(class,)| class.bit()))?;
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
                profile.descend(QrClass::from_bit(bit.value().take())),
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
/// - `anchor_start` is the [boundary digest](poseidon::anchor_next_epoch) into
///   $e$ of an anchor the prover knows, and `anchor_next` is the boundary
///   digest of $a$ into $e + 1$,
/// - what [`QrIntake`] asserts holds of `(epoch, anchor_start, a, discriminant,
///   profile)` with $C$ as the contents,
/// - `contents_hash` is a [bridge hash](TachygramSetBridge) of the accumulator
///   of $C$.
///
/// Unlike an intake's, the two anchors determine the chain. `anchor_next`
/// determines $a$ and $e + 1$, and `anchor_start` determines $e$ and the
/// anchor it absorbs. Take two stamp chains from `anchor_start` to $a$. Each
/// anchor after the first determines the absorption behind it, so walking
/// back from $a$ the two agree for as long as both run. A boundary digest and
/// a stamp absorption have different tags, so no anchor after the first of
/// either chain is `anchor_start`, and neither chain runs past the other's
/// start. The header therefore determines the chain, its product $P$ and the
/// class.
///
/// `contents_hash` determines $C$. $C$ does not determine `contents_hash`,
/// because one accumulator has many bridge hashes.
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
/// - The gadget's `next` range-checks `epoch + 1` and has no assignment at
///   `EPOCH_MAX`, so the intake's `epoch` is an integer $e$ below `EPOCH_MAX`
///   and its successor is $e + 1$.
/// - The circuit holds the intake's `anchor_prev` equal to the [boundary
///   digest](poseidon::anchor_next_epoch) of `anchor_final_prev` into $e$.
///   `anchor_final_prev` is a wire from `Step::Witness`, so `anchor_start` is a
///   boundary digest into $e$ of an anchor the prover knows.
/// - `anchor_next` is the boundary digest circuit's output on the intake's
///   `anchor_end` and $e + 1$, so `anchor_end` is the anchor $a$ of
///   [`QrBucket`].
/// - The input's contents are in an input slot and the output's are committed
///   before the challenge. The circuit equates their openings at $\zeta$, so
///   they are one polynomial. `contents_hash` is the bridge hash of the step's
///   last output slot, which holds it.
///
/// `discriminant` and `profile` are copied. The step does not show that
/// `anchor_final_prev` is the final anchor of any epoch, or that `anchor_end`
/// is the final anchor of $e$. The boundary digests absorb both anchors, so
/// `anchor_start` and `anchor_next` determine them.
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
/// `path` gives the value's class at each of the 32 depths, its QR path. Its
/// first `depth` classes pack to the bucket's profile. `roots[j]` is the class
/// root witnessing class `j`, including positions past that prefix. The step
/// also opens the bucket at the value for nonzero.
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
/// - `value` is a wire $x$ from `Step::Witness`. The circuit holds it nonzero
///   and equal to the staged value, which fixes it before the challenge.
/// - [`enforce_sides_of`](gadgets::qr::QrProfile::enforce_sides_of) reads
///   `path`, `roots` and `mask` and holds the bucket's `profile` to the first
///   `depth` sides of $x$ at the bucket's `discriminant`, so $x$ is in its
///   class. The sides past `depth` are held too and compared with nothing.
/// - The circuit holds the opening of the bucket's contents at $x$ nonzero.
/// - The output's sequence is committed before the challenge. The circuit
///   equates its opening at $\zeta$ with $F_{e,\ x}(\zeta)$ for $e$ the
///   bucket's `epoch`, so the sequence is the
///   [encoding](crate::collections::indexed_multiset) of the one member $x$ at
///   index $e$.
/// - `epoch_next` is the gadget's `next` of `epoch`, which range-checks it, so
///   it is the integer $e + 1$.
///
/// The two anchors are copied, so the input is the bucket by which $x$ is
/// [excluded](ArbitraryUnspent#injectivity) at $e$ between them. The step
/// does not show that $x$ is a nullifier.
/// [`UnspentBind`](super::pool::UnspentBind) shows that.
#[derive(Debug)]
pub struct QrUnspentInit;

impl Step<Pasta> for QrUnspentInit {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = ArbitraryUnspent;
    type Right = ();
    /// `(value, path, roots, mask, sequence)`
    type Witness<'source> = (
        Tachygram,
        [QrClass; QrProfile::MAX_DEPTH],
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
    );

    const INDEX: Index = Index::new(19);
    const NUM_STAGED: usize = 1;

    #[expect(
        clippy::pattern_type_mismatch,
        reason = "borrow the named witness operands"
    )]
    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let (value, _path, _roots, _mask, sequence) = witness;
        Ok(NfSeqPoly::SLOT
            .poly(Prepared::new(), sequence)
            .stage([Fp::from(*value)]))
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
            witness.as_ref().map(|&(_, path, ..)| path),
            witness.as_ref().map(|&(_, _, roots, ..)| roots),
            witness.as_ref().map(|&(_, _, _, mask, _)| mask),
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
