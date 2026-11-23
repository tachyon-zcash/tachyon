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
//! An [`Anchor`] advances by a stamp absorption or by a boundary digest, and
//! no digest marks a block. Block alignment is a consensus convention, with
//! validators checking that anchor endpoints belong to the published
//! per-block anchor sequence.

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
/// A value $v$ is *excluded at* epoch $e$ *between* anchors $b$ and $b'$ when
/// the prover knows a verified [`QrBucket`] with `epoch` $e$, `anchor_start`
/// $b$ and `anchor_next` $b'$, for which $v$ is in the
/// [class](crate::QrDiscriminant#injectivity) of its `profile` at its
/// `discriminant` and its contents do not vanish at $v$. By the bucket's
/// [assertion](QrBucket#injectivity), its contents have every root in that
/// class of the polynomials of its
/// [stamp chain](Anchor#chains-in-a-step), so $v$ is a root of none of them.
/// Its two bounds are boundary digests and determine that chain, so every
/// bucket with these three fields has the same one. $b'$ is the boundary
/// digest of the chain's end into $e + 1$ and determines both.
///
/// [`QrUnspentInit`](super::qr::QrUnspentInit), [`UnspentLift`] and
/// [`UnspentFuse`] output this header. A verified `ArbitraryUnspent` asserts
/// that `epoch_start < epoch_next <= EPOCH_MAX` as integers
/// ([`EpochIndex`](gadgets::epoch::EpochIndex)), and that its prover knows an
/// anchor $b_e$ for each epoch $e$ of `epoch_start..=epoch_next`, the first
/// `anchor_start` and the last `anchor_next`, and a nonzero value $v_e$ for
/// each epoch $e$ of `epoch_start..epoch_next` for which
///
/// - $v_e$ is excluded at $e$ between $b_e$ and $b_{e+1}$,
/// - the [`NfSeqPoly`] is $E(X) = \prod_{e} F_{e,\ v_e}(X)$, with $F_{i,m}$ the
///   [indexed multiset](crate::collections::indexed_multiset)'s encoding of
///   member $m$ at index $i$.
///
/// Each $v_e$ is nonzero, as every published tachygram is. Zero is a root of
/// no published polynomial ([zero tachygrams](super#zero-tachygrams)), so a
/// segment never stands for the exclusion of a value that no spend can
/// publish. [`UnspentBind`] makes each $v_e$ a note's nullifier, so a note
/// whose nullifier at some epoch is zero has no [`NoteUnspent`] over that
/// epoch and is not lifted past it. The exclusion of zero would be true
/// wherever a bucket shows it, and no argument here needs it refused.
///
/// $E$ has one factor for each epoch of the range and no other. An
/// epoch is within the encoding's index bound, so $E$ determines each pair of
/// an epoch and its value. `anchor_next` is the last bucket's, so it determines
/// `epoch_next` and the end of that bucket's chain.
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

/// A note proven unspent across a span: an [`ArbitraryUnspent`] whose values
/// [`UnspentBind`] has shown to be the note's nullifiers.
///
/// # Injectivity
///
/// [`UnspentBind`] outputs this header. A verified `NoteUnspent` asserts
/// that `epoch_start < epoch_next <= EPOCH_MAX` as integers, and that its
/// prover knows a verified [`NoteNullifiers`] that carries this `cm` and an
/// anchor $b_e$ for each epoch $e$ of `epoch_start..=epoch_next`, the first
/// `anchor_start` and the last `anchor_next`. At every epoch $e$ of
/// `epoch_start..epoch_next`, the nullifier of `cm` at $e$ is
/// [excluded](ArbitraryUnspent#injectivity) between $b_e$ and $b_{e+1}$.
///
/// `cm` determines its master key
/// ([`NoteSecret`](super::delegation::NoteSecret)), and the master key and
/// $e$ determine the [nullifier](poseidon::nullifier_group), so the five
/// fields determine every tested value. The assertion says nothing of the
/// polynomial in the [`NfSeqPoly`] slot. [`UnspentBind`] commits the quotient
/// of the note's derived sequence by the tested values there, for its
/// identity, and no step reads it.
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
/// The members polynomial has one root for each stamp absorbed in the span.
/// The root is the anchor that stamp gives.
/// [`StampLift`](super::stamp::StampLift) and
/// [`ActionLift`](super::stamp::ActionLift) use spans to advance an anchor. A
/// spendable's anchor advances through [`ArbitraryUnspent`], whose steps prove
/// the note's nullifiers absent.
///
/// # Injectivity
///
/// [`AnchorSpanSeed`] and [`AnchorSpanFuse`] output this header. A verified
/// `AnchorSpan` asserts that its prover knows a
/// [stamp chain](Anchor#chains-in-a-step) of $k \geq 1$ absorptions from
/// `anchor_start` to `anchor_end`, and that its [`AnchorSetPoly`] is
/// $M(X) = \prod_{i=1}^{k} (X - a_i)$ over the chain's anchors after
/// `anchor_start`.
///
/// `anchor_start` and each absorption's epoch are the prover's choice. The
/// assertion does not make the epochs equal, and it says nothing of what lies
/// behind `anchor_start`. No absorption's polynomial is the constant one, as
/// in a pool history, where [`Anchor::next_stamp`] rejects the empty set.
///
/// $M$ is a [set polynomial](crate::collections::multiset), so it determines
/// those anchors and has no other root. A stamp chain leads from each root to
/// `anchor_end`, and `anchor_end` determines each absorption behind it
/// ([`Anchor`]). None of those anchors is a boundary digest. A span whose
/// `anchor_end` is an anchor of a pool history is therefore a run of that
/// history's stamp entries with no boundary among them.
///
/// The second slot holds the stamp's polynomial where [`AnchorSpanSeed`]
/// outputs the header, for its bridge hash, and the constant one where
/// [`AnchorSpanFuse`] does. No step reads it.
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
/// The step [adds an absorption](Anchor#chains-in-a-step) $a$ of
/// `anchor_start`, `epoch` and the stamp polynomial, with both wires the
/// prover's choice. The circuit holds the stamp polynomial's opening at
/// $\zeta$ away from one, so it is not the constant one.
///
/// The circuit equates the member polynomial's opening at $\zeta$ with
/// $\zeta - a$. The member polynomial $M$ is committed before $\zeta$, but
/// $a$ is not fixed before $\zeta$, because none of the three values it
/// absorbs is. This is the one step whose identity at the challenge reads a
/// root that is not fixed before the challenge, and the identity alone does
/// not give $M = X - a$.
///
/// - If $M$ is $X - c$ for a constant $c$, the constraint reads $a = c$, so $M$
///   is $X - a$.
/// - Otherwise $X - M(X)$ is not constant and has degree below $2^{13}$, and
///   the constraint requires $a$ to equal its value at $\zeta$. Collision
///   resistance does not exclude that. This case models the stamp absorption
///   digest as a random function, as the [Poseidon
///   assumption](crate::stamp::proof#assumptions) says of this step. One
///   challenge and one digest output then meet the constraint with probability
///   below $2^{13}/p$, whichever of the two is drawn first. With $T$ challenges
///   and $Q$ digests the bound is $2^{13} \cdot T \cdot Q/p$. A check on values
///   fixed before the challenge has no factor $Q$.
///
/// Outside that probability $M$ is $X - a$, the set polynomial that
/// [`AnchorSpan`] asserts for a chain of one absorption.
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
        // polynomial opens to one at zeta has no tachygrams.
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
        // The span's one member is the stamp absorption just computed. Its
        // inputs are not fixed before the challenge; see the step's Soundness.
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
/// `left.anchor_end` is held equal to `right.anchor_start`, so the two chains
/// are one from `left.anchor_start` to `right.anchor_end`. The three member
/// polynomials are committed before the challenge. The
/// circuit equates the output's opening at $\zeta$ with the product of the
/// inputs' openings, so the output polynomial is the product of the input
/// polynomials. It has one factor for each anchor of the joined chain after
/// `left.anchor_start`. The step does not open the output's second slot.
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
/// The circuit holds `left.epoch_next` equal to `right.epoch_start` and
/// `left.anchor_next` equal to `right.anchor_start`. The epochs are integers,
/// so the right half's epochs follow the left half's without a gap or an
/// overlap, and its anchors continue the left half's from the shared one.
/// Each value stays excluded at its own epoch between the same two anchors.
/// The three sequences are committed before the challenge. The circuit
/// equates the output's opening at $\zeta$ with the product of the inputs'
/// openings, so the output sequence is the product of the input sequences.
/// It has one factor for each epoch of `left.epoch_start..right.epoch_next`,
/// the range on the output header.
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
/// The circuit holds the segment's `epoch_next` and `anchor_next` equal to
/// the bucket's `epoch` and `anchor_start`. It outputs the successor of the
/// bucket's epoch, range-checked, and the bucket's `anchor_next`. `value` is
/// a wire of the prover's choice, held nonzero and equal to the
/// staged value, so it is fixed before the challenge.
/// [`enforce_sides_of`](gadgets::qr::QrProfile::enforce_sides_of) shows that
/// it is in the class of the bucket's `profile` at the bucket's
/// `discriminant`, and the circuit holds the opening of the bucket's contents
/// at it nonzero. It is therefore [excluded](ArbitraryUnspent#injectivity)
/// at the bucket's epoch between the bucket's two anchors, which extends the
/// segment's anchors and values by one epoch.
///
/// The circuit equates the output sequence's opening at $\zeta$ with the
/// input sequence's opening times $F_{e,\ v}(\zeta)$, for $e$ the bucket's
/// epoch and $v$ `value`. Both sequences are committed before $\zeta$, $e$
/// is an input header field and $v$ is staged. The output sequence is
/// therefore the input sequence times that one factor, with one factor for
/// each epoch of the output header's range.
///
/// Three committed polynomials, each opened once.
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

/// Show that an [`ArbitraryUnspent`]'s tested values are a note's nullifiers,
/// by divisibility into the note's derived sequence.
///
/// Consumes any [`NoteNullifiers`]. The output polynomial is the complement,
/// the derivation's members outside the lineage: epochs below it, and the
/// epochs it runs ahead of the exclusion evidence, since a spend publishes
/// two nullifiers while the lineage stops at published evidence.
///
/// # Soundness
///
/// Write $E$ for the segment's sequence, $D$ for the derivation's and $Q$ for
/// the output polynomial. $E$ and $D$ are fixed in the input PCDs, and $Q$ is
/// committed before the challenge. The circuit equates $D(\zeta)$ with
/// $E(\zeta) \cdot Q(\zeta)$, so $E$ divides $D$.
///
/// $E$ is the product of the factors $F_{e,\ v_e}$ over the segment's epochs,
/// and $D$ of the factors $F_{e,\ n_e}$ over the derivation's, with $n_e$ the
/// note's nullifier at $e$. Every index is an epoch, so each factor is
/// irreducible and determines its tuple
/// ([indexed multiset](crate::collections::indexed_multiset#injectivity)).
/// Each factor of $E$ is therefore a factor of $D$. Hence every epoch $e$ of
/// the segment is an epoch of the derivation, and $v_e = n_e$.
///
/// The segment has one tested value for each of its epochs, so the note's
/// nullifier is excluded at every epoch of `epoch_start..epoch_next`, as
/// [`NoteUnspent`] asserts. The step copies `cm` from the right input and the
/// other four fields from the left.
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
