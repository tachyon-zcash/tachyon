//! Anchor-bound primitives over consensus state.
//!
//! Hosts the nf-free anchor path ([`AnchorSpan`]) used by
//! [`super::stamp::StampLift`] to advance a stamp's anchor, and the
//! multi-stamp / multi-epoch exclusion proof ([`ArbitraryUnspent`]) used by
//! [`super::spendable::SpendableLift`] to advance a spendable.
//!
//! An [`ArbitraryUnspent`] covers whole epochs, `[anchor_start, anchor_next)`.
//! An [`AnchorSpan`] covers `[anchor_start, anchor_end]`, and its members are
//! the anchors in `(anchor_start, anchor_end]`.
//!
//! Each [`Anchor`] advances via a stamp absorption or boundary digest without a
//! block-level digest. Consensus conventions handle block alignment as
//! validators check that anchor endpoints lie on the published per-block anchor
//! sequence.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

use ragu::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Padding, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
    primitives::{Element, GadgetExt as _, allocator::Allocator, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
    udon::field::Field as _,
};

use super::{delegation::NoteNullifiers, qr::QrBucket};
use crate::{
    bridge_hash::bridge_hash,
    digest::poseidon,
    gadgets, note,
    pasta::Fp,
    primitives::{
        Anchor, AnchorSetPoly, EpochIndex, NfSeqPoly, PolySlot, QrClass, QrClassRoot, QrProfile,
        Tachygram, TachygramSetPoly,
    },
};

/// Multi-stamp / multi-epoch nf-exclusion proof over arbitrary values.
///
/// The tested values are arbitrary field elements until [`UnspentBind`]
/// shows that they are a note's nullifiers. No step producing one touches a
/// note, `cm`, or `mk`, so the segment is safe to delegate.
///
/// A segment covers whole epochs, half-open on both axes:
/// `[anchor_start, anchor_next)` and `[epoch_start, epoch_next)`. It starts at
/// [`QrUnspentInit`](super::qr::QrUnspentInit) over one epoch's [`QrBucket`],
/// [`UnspentLift`] appends the next epoch's bucket, and [`UnspentFuse`] joins
/// segments on a shared boundary.
///
/// `epoch_next`'s nullifier is the next segment's to test, or
/// [`SpendBind`](super::spend::SpendBind)'s once a spendable rests on
/// `anchor_next`.
///
/// # Injectivity
///
/// [`QrUnspentInit`](super::qr::QrUnspentInit), [`UnspentLift`] and
/// [`UnspentFuse`] output this header. Every verified `ArbitraryUnspent`
/// asserts `epoch_start < epoch_next <= EPOCH_MAX` over the integers
/// ([`EpochIndex`](gadgets::epoch::EpochIndex)), prover-known anchors $b_e$
/// across $e \in \text{epoch\_start}..=\text{epoch\_next}$ from `anchor_start`
/// to `anchor_next`, and prover-known nonzero values $v_e$ across
/// $e \in \text{epoch\_start}..\text{epoch\_next}$ where each $v_e$ is
/// *excluded at* $e$ *between* $b_e$ and $b_{e+1}$ and the [`NfSeqPoly`] equals
/// $E(X) = \prod_{e} F_{e,\ v_e}(X)$ under the
/// [indexed multiset](crate::collections::indexed_multiset) encoding $F_{i,m}$.
///
/// Exclusion of $v$ at $e$ between $b$ and $b'$ means a prover-known verified
/// [`QrBucket`] at `(e, b, b')` places $v$ in the
/// [class](crate::QrDiscriminant#injectivity) of its `profile` at its
/// `discriminant` and has contents non-vanishing at $v$. Under the bucket's
/// [assertion](QrBucket#injectivity), its contents hold every root in that
/// class across its [stamp chain](Anchor#chains-in-a-step), so $v$ is a root of
/// none of those polynomials. Boundary digests $b$ and $b'$ fix that chain for
/// every bucket sharing `(e, b, b')`, and $b'$ determines $e + 1$ and the
/// chain's end.
///
/// Although zero is never a root of a published polynomial
/// ([zero tachygrams](super#zero-tachygrams)) and no argument here requires
/// rejecting it, holding each $v_e$ nonzero ensures that once [`UnspentBind`]
/// equates $v_e$ with a note's nullifier, any note with a zero nullifier at
/// epoch $e$ has no [`NoteUnspent`] across $e$ and cannot lift past it.
///
/// Because $E$ holds one factor per epoch in range within the index bound, $E$
/// determines every $(e, v_e)$ pair, while `anchor_next` from the final bucket
/// determines `epoch_next` and that bucket's chain end.
#[derive(Clone, Debug)]
pub struct ArbitraryUnspent;

#[derive(Gadget, Write)]
pub struct ArbitraryUnspentOutput<'dr, D: Driver<'dr>> {
    pub anchor_start: Element<'dr, D>,
    #[ragu(gadget)]
    pub epoch_start: gadgets::epoch::EpochIndex<'dr, D>,
    #[ragu(gadget)]
    pub epoch_next: gadgets::epoch::EpochIndex<'dr, D>,
    pub anchor_next: Element<'dr, D>,
}

impl Header<Fp> for ArbitraryUnspent {
    /// `(anchor_start, epoch_start, epoch_next, anchor_next)`
    type Data = (Anchor, EpochIndex, EpochIndex, Anchor);
    type OnlinePolyCommit = (PolySlot<NfSeqPoly>, Padding);
    type Output = Kind![Fp; ArbitraryUnspentOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(ArbitraryUnspentOutput {
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(anchor_start, ..)| Fp::from(anchor_start)),
            )?,
            epoch_start: gadgets::epoch::EpochIndex::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(_, epoch_start, ..)| epoch_start),
            )?,
            epoch_next: gadgets::epoch::EpochIndex::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(_, _, epoch_next, _)| epoch_next),
            )?,
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(.., anchor_next)| Fp::from(anchor_next)),
            )?,
        })
    }
}

/// A note proven unspent across a span, produced when [`UnspentBind`] ties an
/// [`ArbitraryUnspent`]'s values to the note's nullifiers.
///
/// # Injectivity
///
/// [`UnspentBind`] outputs this header. Every verified `NoteUnspent` asserts
/// `epoch_start < epoch_next <= EPOCH_MAX` over the integers, a prover-known
/// verified [`NoteNullifiers`] carrying `cm`, and prover-known anchors $b_e$
/// across $e \in \text{epoch\_start}..=\text{epoch\_next}$ from `anchor_start`
/// to `anchor_next` such that `cm`'s nullifier at each
/// $e \in \text{epoch\_start}..\text{epoch\_next}$ is
/// [excluded](ArbitraryUnspent#injectivity) between $b_e$ and $b_{e+1}$.
///
/// Because `cm` determines its master key
/// ([`NoteSecret`](super::delegation::NoteSecret)) and the master key and $e$
/// determine the [nullifier](poseidon::nullifier_group), the five header fields
/// fix every tested value. Nothing is asserted about the [`NfSeqPoly`] slot,
/// where [`UnspentBind`] commits the unread quotient of the derived sequence by
/// the tested values for its challenge identity.
#[derive(Clone, Debug)]
pub struct NoteUnspent;

#[derive(Gadget, Write)]
pub struct NoteUnspentOutput<'dr, D: Driver<'dr>> {
    pub cm: Element<'dr, D>,
    pub anchor_start: Element<'dr, D>,
    #[ragu(gadget)]
    pub epoch_start: gadgets::epoch::EpochIndex<'dr, D>,
    #[ragu(gadget)]
    pub epoch_next: gadgets::epoch::EpochIndex<'dr, D>,
    pub anchor_next: Element<'dr, D>,
}

impl Header<Fp> for NoteUnspent {
    /// `(cm, anchor_start, epoch_start, epoch_next, anchor_next)`
    type Data = (note::Commitment, Anchor, EpochIndex, EpochIndex, Anchor);
    type OnlinePolyCommit = (PolySlot<NfSeqPoly>, Padding);
    type Output = Kind![Fp; NoteUnspentOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteUnspentOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(cm, ..)| Fp::from(cm)),
            )?,
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(_, anchor_start, ..)| Fp::from(anchor_start)),
            )?,
            epoch_start: gadgets::epoch::EpochIndex::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(_, _, epoch_start, ..)| epoch_start),
            )?,
            epoch_next: gadgets::epoch::EpochIndex::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(.., epoch_next, _)| epoch_next),
            )?,
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(.., anchor_next)| Fp::from(anchor_next)),
            )?,
        })
    }
}

/// An anchor path with a commitment to the anchors inside it.
///
/// Each stamp absorbed into the span contributes its resulting anchor as a root
/// of the members polynomial. [`StampLift`](super::stamp::StampLift) and
/// [`ActionLift`](super::stamp::ActionLift) advance anchors across spans.
/// Spendables advance via [`NoteUnspent`], after [`UnspentBind`] ties an
/// [`ArbitraryUnspent`]'s exclusions to the note's nullifiers.
///
/// # Injectivity
///
/// [`AnchorSpanSeed`] and [`AnchorSpanFuse`] output this header. Every verified
/// `AnchorSpan` asserts a prover-known [stamp chain](Anchor#chains-in-a-step)
/// of $k \geq 1$ absorptions from `anchor_start` to `anchor_end` whose anchors
/// after `anchor_start` form the [`AnchorSetPoly`]
/// $M(X) = \prod_{i=1}^{k} (X - a_i)$.
///
/// Provers choose `anchor_start` and each absorption's epoch freely, without
/// equating epochs or constraining history behind `anchor_start`. No
/// absorption's polynomial equals the constant one, matching
/// [`Anchor::next_stamp`] rejecting the empty set in a pool history.
///
/// As a [set polynomial](crate::collections::multiset), $M$ determines $a_1,
/// \dots, a_k$ with no extra roots. Each root connects to `anchor_end` by a
/// stamp chain, `anchor_end` determines every preceding absorption
/// ([`Anchor`]), and no $a_i$ is a boundary digest, so any span ending on a
/// pool-history anchor covers a boundary-free run of stamp entries in that
/// history.
///
/// No consumer reads the second slot, which holds the stamp polynomial for its
/// bridge hash at [`AnchorSpanSeed`] and the constant one at
/// [`AnchorSpanFuse`].
#[derive(Clone, Debug)]
pub struct AnchorSpan;

#[derive(Gadget, Write)]
pub struct AnchorSpanOutput<'dr, D: Driver<'dr>> {
    pub anchor_start: Element<'dr, D>,
    pub anchor_end: Element<'dr, D>,
}

impl Header<Fp> for AnchorSpan {
    /// `(anchor_start, anchor_end)`
    type Data = (Anchor, Anchor);
    type OnlinePolyCommit = (PolySlot<AnchorSetPoly>, PolySlot<TachygramSetPoly>);
    type Output = Kind![Fp; AnchorSpanOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(14);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(AnchorSpanOutput {
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            anchor_end: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
        })
    }
}

/// Start an [`AnchorSpan`] from one stamp.
///
/// The step absorbs the stamp's bridge hash into `anchor_start`.
/// The span's only member is the resulting anchor.
///
/// # Soundness
///
/// Except with probability at most $2^{13} \cdot T \cdot Q/p$ across $T$
/// challenges and $Q$ stamp absorption digests, the member polynomial $M$
/// equals $X - a$ as [`AnchorSpan`] asserts for a single-absorption chain.
///
/// The step [adds an absorption](Anchor#chains-in-a-step) $a$ of prover-chosen
/// `anchor_start` and `epoch` with the stamp polynomial, holding that
/// polynomial's opening at $\zeta$ away from one to rule out the constant one.
///
/// Although $M$ is committed before $\zeta$ and the circuit equates $M(\zeta)$
/// with $\zeta - a$, none of $a$'s three inputs is fixed before $\zeta$. This
/// is the sole step whose challenge identity evaluates an unfixed root, so the
/// identity alone does not force $M = X - a$.
///
/// - When $M = X - c$ for a constant $c$, the constraint enforces $a = c$,
///   giving $M = X - a$.
/// - Otherwise $X - M(X)$ is nonconstant of degree below $2^{13}$, and the
///   constraint requires $a = \zeta - M(\zeta)$. Collision resistance does not
///   rule that out, so this step models the stamp absorption digest as a random
///   function ([Poseidon assumption](crate::stamp::proof#assumptions)). Any
///   single challenge and digest output satisfy the equation with probability
///   below $2^{13}/p$ in either draw order, summing to $2^{13} \cdot T \cdot
///   Q/p$ whereas checks on pre-challenge values avoid the factor $Q$.
#[derive(Debug)]
pub struct AnchorSpanSeed;

impl Step<Pasta> for AnchorSpanSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorSpan;
    type Right = ();
    /// `(anchor_start, epoch, stamp)`
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetPoly);

    const INDEX: Index = Index::new(31);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        // The witness phase rejects the empty stamp at its polynomial opening.
        let anchor_end = Anchor::from(poseidon::anchor_next_stamp(
            witness.0.into(),
            witness.1.into(),
            bridge_hash(witness.2.commit().into()),
        ));
        let stamp = &witness.2;
        let prepared =
            AnchorSetPoly::SLOT.poly(Prepared::new(), &AnchorSetPoly::from_iter([anchor_end]));
        Ok(TachygramSetPoly::SLOT.poly(prepared, stamp))
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
                .map(|&(anchor_start, ..)| Fp::from(anchor_start)),
        )?;
        let epoch_element = gadgets::epoch::EpochIndex::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|&(_, epoch, _)| epoch),
        )?;
        // The empty set polynomial is the constant one, so a stamp whose
        // polynomial is the constant one cannot pass this check.
        let z = oracles.zeta().clone();
        let stamp_at_z = oracles.output(TachygramSetPoly::SLOT).open(dr, &z)?;
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
        // The span's sole member is the stamp absorption above, whose inputs
        // are not fixed before the challenge (see the step's Soundness section).
        let members = oracles.output(AnchorSetPoly::SLOT).open(dr, &z)?;
        let member_factor = z.sub(dr, &anchor);
        members.enforce_equal(dr, &member_factor)?;
        let data = D::just(|| {
            let (anchor_start, ..) = witness.take();
            (anchor_start, Anchor::from(*anchor.value().take()))
        });
        let fields = AnchorSpanOutput {
            anchor_start: previous,
            anchor_end: anchor,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

/// Concatenate two [`AnchorSpan`]s with
/// `left.anchor_end == right.anchor_start`.
///
/// # Soundness
///
/// Equating `left.anchor_end` with `right.anchor_start` joins the two chains
/// into one from `left.anchor_start` to `right.anchor_end`. Because all three
/// member polynomials are committed before $\zeta$ and the circuit equates the
/// output's opening at $\zeta$ with the product of the inputs' openings, the
/// output polynomial multiplies the input polynomials to hold one factor per
/// anchor after `left.anchor_start`. The output's second slot goes unopened.
#[derive(Debug)]
pub struct AnchorSpanFuse;

impl Step<Pasta> for AnchorSpanFuse {
    type Aux<'source> = ();
    type Left = AnchorSpan;
    type Output = AnchorSpan;
    type Right = AnchorSpan;
    /// `(combined,)`
    type Witness<'source> = (AnchorSetPoly,);

    const INDEX: Index = Index::new(32);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let combined = &witness.0;
        Ok(AnchorSetPoly::SLOT.poly(Prepared::new(), combined))
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
        let left_span = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let right_span = right_encoded.as_gadget();
        left_span
            .anchor_end
            .enforce_equal(dr, &right_span.anchor_start)?;
        let data = D::just(|| {
            let (left_anchor_start, ..) = left.take();
            let (_, right_anchor_end) = right.take();
            (left_anchor_start, right_anchor_end)
        });
        let z = oracles.zeta().clone();
        let left_members = oracles.left(AnchorSetPoly::SLOT).open(dr, &z)?;
        let right_members = oracles.right(AnchorSetPoly::SLOT).open(dr, &z)?;
        let combined = oracles.output(AnchorSetPoly::SLOT).open(dr, &z)?;
        let expected_members = left_members.mul(dr, &right_members)?;
        combined.enforce_equal(dr, &expected_members)?;
        let fields = AnchorSpanOutput {
            anchor_start: left_span.anchor_start.clone(),
            anchor_end: right_span.anchor_end.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

/// Compose two [`ArbitraryUnspent`] lineages meeting at a boundary digest.
///
/// # Soundness
///
/// Equating `left.epoch_next` with `right.epoch_start` over the integers and
/// `left.anchor_next` with `right.anchor_start` joins the two epoch ranges and
/// merges the anchor sequences at their shared boundary, preserving each
/// value's exclusion. Because all three sequences are committed before $\zeta$
/// and the circuit equates the output's opening at $\zeta$ with the product of
/// the inputs' openings, the output sequence multiplies the inputs to hold one
/// factor per epoch across `left.epoch_start..right.epoch_next`.
///
/// Opens both input sequences and their product once each.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step<Pasta> for UnspentFuse {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = ArbitraryUnspent;
    /// `(combined_elapsed_seq,)`
    type Witness<'source> = (NfSeqPoly,);

    const INDEX: Index = Index::new(2);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let combined_elapsed_seq = &witness.0;
        Ok(NfSeqPoly::SLOT.poly(Prepared::new(), combined_elapsed_seq))
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
        let left_unspent = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let right_unspent = right_encoded.as_gadget();
        left_unspent
            .anchor_next
            .enforce_equal(dr, &right_unspent.anchor_start)?;
        left_unspent
            .epoch_next
            .enforce_equal(dr, &right_unspent.epoch_start)?;
        let data = D::just(|| {
            let (left_anchor_start, left_epoch_start, ..) = left.take();
            let (_, _, right_epoch_next, right_anchor_next) = right.take();
            (
                left_anchor_start,
                left_epoch_start,
                right_epoch_next,
                right_anchor_next,
            )
        });
        let z = oracles.zeta().clone();
        let left_elapsed = oracles.left(NfSeqPoly::SLOT).open(dr, &z)?;
        let right_elapsed = oracles.right(NfSeqPoly::SLOT).open(dr, &z)?;
        let combined = oracles.output(NfSeqPoly::SLOT).open(dr, &z)?;
        let expected_elapsed = left_elapsed.mul(dr, &right_elapsed)?;
        combined.enforce_equal(dr, &expected_elapsed)?;
        let fields = ArbitraryUnspentOutput {
            anchor_start: left_unspent.anchor_start.clone(),
            epoch_start: left_unspent.epoch_start.clone(),
            epoch_next: right_unspent.epoch_next.clone(),
            anchor_next: right_unspent.anchor_next.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

/// Append one epoch to an [`ArbitraryUnspent`] from that epoch's
/// [`QrBucket`].
///
/// One step per epoch, where [`QrUnspentInit`](super::qr::QrUnspentInit) then
/// [`UnspentFuse`] takes two.
///
/// `path` gives the value's class at each of the 32 depths, its QR path. Its
/// first `depth` classes pack to the bucket's profile. `roots[j]` is the class
/// root witnessing class `j`, including positions past that prefix.
///
/// # Soundness
///
/// Equating `(epoch_next, anchor_next)` on the segment with `(epoch,
/// anchor_start)` on the bucket, outputting the range-checked successor of
/// `bucket.epoch` and `bucket.anchor_next`, and holding the prover-chosen
/// `value` wire nonzero and equal to the staged value fixes `value` before
/// $\zeta$. [`enforce_sides_of`](gadgets::qr::QrProfile::enforce_sides_of)
/// places `value` in the class of `bucket.profile` at `bucket.discriminant`,
/// and holding the bucket contents' opening at `value` nonzero establishes its
/// [exclusion](ArbitraryUnspent#injectivity) across the bucket, extending the
/// segment by one epoch.
///
/// With both sequences committed before $\zeta$, $e = \text{bucket.epoch}$ in
/// the input header, and $v = \text{value}$ staged, equating the output
/// sequence's opening at $\zeta$ with the input's opening times $F_{e,\
/// v}(\zeta)$ multiplies that factor onto the input sequence across the
/// extended epoch range.
///
/// Opens three committed polynomials once each.
#[derive(Debug)]
pub struct UnspentLift;

impl Step<Pasta> for UnspentLift {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = QrBucket;
    /// `(value, path, roots, mask, extended_seq)`
    type Witness<'source> = (
        Tachygram,
        [QrClass; QrProfile::MAX_DEPTH],
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
    );

    const INDEX: Index = Index::new(24);
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
        let (value, _path, _roots, _mask, extended_seq) = witness;
        Ok(NfSeqPoly::SLOT
            .poly(Prepared::new(), extended_seq)
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
        let unspent = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let bucket = right_encoded.as_gadget();
        let epoch_next_element = bucket.epoch.next(dr)?;
        unspent
            .anchor_next
            .enforce_equal(dr, &bucket.anchor_start)?;
        unspent.epoch_next.enforce_equal(dr, &bucket.epoch)?;
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
        #[expect(
            clippy::indexing_slicing,
            reason = "the framework enforces NUM_STAGED = 1"
        )]
        value_element.enforce_equal(dr, &oracles.staged()[0])?;
        let z = oracles.zeta().clone();
        let elapsed_at_z = oracles.left(NfSeqPoly::SLOT).open(dr, &z)?;
        let extended_at_z = oracles.output(NfSeqPoly::SLOT).open(dr, &z)?;
        let factor = gadgets::indexed_multiset::Member {
            index: (*bucket.epoch).clone(),
            value: value_element.clone(),
        }
        .eval(dr, &z)?;
        let expected_extended = elapsed_at_z.mul(dr, &factor)?;
        extended_at_z.enforce_equal(dr, &expected_extended)?;
        let contents_at_value = oracles
            .right(TachygramSetPoly::SLOT)
            .open(dr, &value_element)?;
        let nonzero_value = Element::promote(
            contents_at_value.wire().clone(),
            contents_at_value.value().map(Clone::clone),
        );
        nonzero_value.enforce_nonzero(dr)?;

        let output = D::just(|| {
            let (unspent_anchor_start, unspent_epoch_start, ..) = left.take();
            let (bucket_epoch, _, bucket_anchor_next, ..) = right.take();
            #[expect(
                clippy::expect_used,
                reason = "QrBucketSeal rejects the final epoch, so only a bucket proof that \
                          doesn't verify carries it"
            )]
            let epoch_next = bucket_epoch.next().expect("bucket epoch has a successor");
            (
                unspent_anchor_start,
                unspent_epoch_start,
                epoch_next,
                bucket_anchor_next,
            )
        });
        let fields = ArbitraryUnspentOutput {
            anchor_start: unspent.anchor_start.clone(),
            epoch_start: unspent.epoch_start.clone(),
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

/// Prove that an [`ArbitraryUnspent`]'s tested values match a note's nullifiers
/// by dividing them into the note's derived sequence.
///
/// Consumes any [`NoteNullifiers`] and outputs the complement holding derived
/// members outside the lineage (earlier epochs plus epochs ahead of published
/// exclusion evidence, since a spend publishes two nullifiers).
///
/// # Soundness
///
/// With the segment sequence $E$ and derived sequence $D$ fixed in the input
/// PCDs and the complement $Q$ committed before $\zeta$, equating $D(\zeta)$
/// with $E(\zeta) \cdot Q(\zeta)$ proves that $E$ divides $D$.
///
/// Because $E = \prod F_{e,\ v_e}$ over the segment's epochs and $D = \prod
/// F_{e,\ n_e}$ over the derivation's epochs (for note nullifier $n_e$), and
/// epoch-indexed factors are irreducible and determine their tuples
/// ([indexed multiset](crate::collections::indexed_multiset#injectivity)),
/// every factor of $E$ appears in $D$, forcing every segment epoch $e$ into the
/// derivation with $v_e = n_e$.
///
/// Having one tested value per epoch in the segment excludes the note's
/// nullifier across `epoch_start..epoch_next`, establishing [`NoteUnspent`]
/// while copying `cm` from the right input and the remaining four fields from
/// the left.
///
/// Opens the elapsed sequence, derivation and complement once each.
#[derive(Debug)]
pub struct UnspentBind;

impl Step<Pasta> for UnspentBind {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = NoteUnspent;
    type Right = NoteNullifiers;
    /// `(complement_seq,)`
    type Witness<'source> = (NfSeqPoly,);

    const INDEX: Index = Index::new(3);

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let complement_seq = &witness.0;
        Ok(NfSeqPoly::SLOT.poly(Prepared::new(), complement_seq))
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
        let ArbitraryUnspentOutput {
            anchor_start,
            epoch_start,
            epoch_next,
            anchor_next,
        } = left_encoded.as_gadget().clone();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        // The divisibility bind: `nf_seq = elapsed · complement`, so every
        // elapsed member is a genuine derived pair.
        let z = oracles.zeta().clone();
        let elapsed = oracles.left(NfSeqPoly::SLOT).open(dr, &z)?;
        let complement = oracles.output(NfSeqPoly::SLOT).open(dr, &z)?;
        let derivation = oracles.right(NfSeqPoly::SLOT).open(dr, &z)?;
        let expected_derivation = elapsed.mul(dr, &complement)?;
        derivation.enforce_equal(dr, &expected_derivation)?;
        // Every `ArbitraryUnspent` covers at least one epoch: `QrUnspentInit`
        // and `UnspentLift` emit `epoch_next` as the range-checked `successor`
        // of a range-checked epoch, and `UnspentFuse` joins halves at an equal
        // epoch.
        let data = D::just(|| {
            let (
                unspent_anchor_start,
                unspent_epoch_start,
                unspent_epoch_next,
                unspent_anchor_next,
            ) = left.take();
            let (nullifiers_cm, ..) = right.take();
            (
                nullifiers_cm,
                unspent_anchor_start,
                unspent_epoch_start,
                unspent_epoch_next,
                unspent_anchor_next,
            )
        });
        let fields = NoteUnspentOutput {
            cm: right_encoded.as_gadget().cm.clone(),
            anchor_start,
            epoch_start,
            epoch_next,
            anchor_next,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            data,
            D::unit(),
        ))
    }
}

#[cfg(test)]
mod tests;
