//! Anchor-bound primitives over consensus state.
//!
//! Hosts the nf-free anchor path ([`AnchorSpan`]) used by
//! [`super::stamp::StampLift`] to advance a stamp's anchor, and the
//! multi-stamp / multi-epoch exclusion proof ([`ArbitraryUnspent`]) used by
//! [`super::spendable::SpendableLift`] to advance a spendable.
//!
//! An [`ArbitraryUnspent`] covers whole epochs, `[anchor_start, anchor_next)`:
//! both bounds are entry anchors, and `anchor_next` belongs to the epoch after
//! the segment. An [`AnchorSpan`] covers `[anchor_start, anchor_end]`, both
//! endpoints included. Its `members` commit to the anchors in
//! `(anchor_start, anchor_end]`.
//!
//! Anchor advances are single-level: every fold absorbs the containing
//! block's epoch and one stamp's tachygram-set commitment into the running
//! [`Anchor`] via [`Anchor::next_stamp`]. There is no per-block hash domain;
//! block alignment is a consensus convention, with validators checking that
//! anchor endpoints belong to the published per-block anchor sequence.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

use alloc::vec::Vec;
use core::array;

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

use super::{
    delegation::NoteNullifiers,
    qr::{QrBucket, enforce_value_profile},
};
use crate::{
    collections::indexed_multiset,
    note::{self},
    pasta::Fp,
    primitives::{
        Anchor, AnchorSetPoly, EpochIndex, NfSeqPoly, QrClassRoot, QrProfile, Tachygram,
        TachygramSetCommit,
    },
    ragu_constraint::{enforce_nonzero, enforce_zero},
    relations::enforce::{enforce_poly_product, enforce_poly_roots},
};

/// Multi-stamp / multi-epoch nf-exclusion proof over arbitrary values.
///
/// The tested values are arbitrary field elements until [`UnspentBind`]
/// attributes them to a note's derivation. No step producing one touches a
/// note, `cm`, or `mk`, so the segment is safe to delegate.
///
/// A segment covers whole epochs, half-open on both axes:
/// `[anchor_start, anchor_next)` and `[epoch_start, epoch_next)`.
/// `anchor_start` is the entry anchor of `epoch_start`, and `anchor_next` is
/// the entry anchor of `epoch_next`. It starts at
/// [`QrUnspentInit`](super::qr::QrUnspentInit) over one epoch's [`QrBucket`],
/// [`UnspentLift`] appends the next epoch's bucket, and [`UnspentFuse`] joins
/// segments on a shared boundary. Each producer takes an anchor bound and its
/// epoch from the same bucket or the same half, and
/// [`QrBucketSeal`](super::qr::QrBucketSeal) gives every bucket that form.
///
/// Slot `O0` holds the `elapsed` [`NfSeqPoly`], one tested nullifier per epoch
/// in `[epoch_start, epoch_next)`. `epoch_next`'s nullifier is the next
/// segment's to test, or [`SpendBind`](super::spend::SpendBind)'s once a
/// spendable rests on `anchor_next`.
///
/// Every producer maintains the provenance [`UnspentBind`]'s completeness
/// argument leans on. Each member's epoch lies in `[epoch_start, epoch_next)`,
/// because `QrUnspentInit` and [`UnspentLift`] encode their member from the
/// bucket's own epoch. Each epoch carries exactly one member: `QrUnspentInit`
/// pins its one member by its challenge identity, `UnspentLift` adds exactly
/// one at `epoch_next` by its, and [`UnspentFuse`]'s identity determines the
/// combined polynomial exactly, so the property composes by induction.
#[derive(Clone, Debug)]
pub struct ArbitraryUnspent;

/// `ArbitraryUnspent` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct ArbitraryUnspentOutput<'dr, D: Driver<'dr>> {
    /// `anchor_start`.
    pub anchor_start: Element<'dr, D>,
    /// `epoch_start`.
    pub epoch_start: Element<'dr, D>,
    /// `epoch_next`.
    pub epoch_next: Element<'dr, D>,
    /// `anchor_next`.
    pub anchor_next: Element<'dr, D>,
}

impl Header<Fp> for ArbitraryUnspent {
    /// `(anchor_start, epoch_start, epoch_next, anchor_next)`
    type Data = (Anchor, EpochIndex, EpochIndex, Anchor);
    type Output = Kind![Fp; ArbitraryUnspentOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(1);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(ArbitraryUnspentOutput {
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            epoch_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            epoch_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?,
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.3)),
            )?,
        })
    }
}

/// A note proven unspent across a span: an [`ArbitraryUnspent`] whose values
/// [`UnspentBind`] has attributed to the note's genuine derivation.
#[derive(Clone, Debug)]
pub struct NoteUnspent;

/// `NoteUnspent` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct NoteUnspentOutput<'dr, D: Driver<'dr>> {
    /// `cm`.
    pub cm: Element<'dr, D>,
    /// `anchor_start`.
    pub anchor_start: Element<'dr, D>,
    /// `epoch_start`.
    pub epoch_start: Element<'dr, D>,
    /// `epoch_next`.
    pub epoch_next: Element<'dr, D>,
    /// `anchor_next`.
    pub anchor_next: Element<'dr, D>,
}

impl Header<Fp> for NoteUnspent {
    /// `(cm, anchor_start, epoch_start, epoch_next, anchor_next)`. `cm` leads;
    /// the rest mirrors the [`ArbitraryUnspent`] without `elapsed`.
    type Data = (note::Commitment, Anchor, EpochIndex, EpochIndex, Anchor);
    type Output = Kind![Fp; NoteUnspentOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(3);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(NoteUnspentOutput {
            cm: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            epoch_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?,
            epoch_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.3)),
            )?,
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.4)),
            )?,
        })
    }
}

/// An anchor path whose slot `O0` holds the anchors inside it.
///
/// The members polynomial has one root for each stamp folded into the span. The
/// root is the anchor that fold produces. `anchor_end` is a member and
/// `anchor_start` is not. [`super::stamp::StampLift`] uses spans to
/// advance a stamp's anchor. A spendable's anchor advances through
/// [`ArbitraryUnspent`], whose steps prove the note's nullifiers absent.
///
/// A span stays within one epoch. [`AnchorSpanSeed`] folds only with
/// [`Anchor::next_stamp`], which hashes under the `Tachyon-AnchorSt` domain.
/// Entering the next epoch takes [`Anchor::next_epoch`], which hashes under
/// `Tachyon-AnchorEp`. Among the proof steps, only
/// [`QrBucketSeal`](super::qr::QrBucketSeal) computes it. Consensus also
/// rejects a tachygram published twice within two epochs. That check catches a
/// tachygram already published earlier in the epoch a stamp is lifted across.
///
/// [`AnchorSpanSeed`] takes `anchor_start` as a free witness. A span on its own
/// is not tied to the published chain. Consensus ties it when it checks the
/// anchor of the stamp that [`super::stamp::StampLift`] outputs.
#[derive(Clone, Debug)]
pub struct AnchorSpan;

/// `AnchorSpan` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct AnchorSpanOutput<'dr, D: Driver<'dr>> {
    /// `anchor_start`.
    pub anchor_start: Element<'dr, D>,
    /// `anchor_end`.
    pub anchor_end: Element<'dr, D>,
}

impl Header<Fp> for AnchorSpan {
    /// `(anchor_start, anchor_end)`
    type Data = (Anchor, Anchor);
    type Output = Kind![Fp; AnchorSpanOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(14);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
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
/// The step folds the stamp into `anchor_start` with [`Anchor::next_stamp`].
/// The span's only member is the resulting anchor; `O0` carries that
/// singleton.
///
/// # Soundness
///
/// `epoch` is a free witness. Consensus computes each fold with the epoch of
/// the block that contains the stamp. A span built with a different epoch
/// holds anchors that are not on the published chain.
#[derive(Debug)]
pub struct AnchorSpanSeed;

impl Step<Pasta> for AnchorSpanSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorSpan;
    type Right = ();
    /// `(anchor_start, epoch, stamp_commit)`
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetCommit);

    const INDEX: Index = Index::new(31);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        let anchor_end = witness
            .0
            .next_stamp(witness.1, &witness.2)
            .map_err(|_err| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(AnchorSetPoly::from_iter([anchor_end]).as_ref());
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
        let output = D::try_just(|| {
            let (anchor_start, epoch, stamp_commit) = witness.take();
            let anchor_end = anchor_start
                .next_stamp(epoch, &stamp_commit)
                .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;

            Ok(((anchor_start, anchor_end), ()))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        let header = encoded.as_gadget();
        enforce_poly_roots(
            dr,
            oracles,
            &Slot::output(0),
            array::from_ref(&header.anchor_end),
            "AnchorSpanSeed: members must contain the resulting anchor",
        )?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Concatenate two [`AnchorSpan`]s with
/// `left.anchor_end == right.anchor_start`.
///
/// The shared anchor is a member of the left span and not of the right span.
/// The two member sets are therefore disjoint, and the combined members
/// polynomial is the product of the two.
///
/// # Soundness
///
/// The product check opens both halves' `R0`/`L0` member slots and the
/// combined `O0` at a challenge that absorbs all three commitments. `combined`
/// therefore holds exactly the members of both halves.
#[derive(Debug)]
pub struct AnchorSpanFuse;

impl Step<Pasta> for AnchorSpanFuse {
    type Aux<'source> = ();
    type Left = AnchorSpan;
    type Output = AnchorSpan;
    type Right = AnchorSpan;
    /// `(combined)`
    type Witness<'source> = (AnchorSetPoly,);

    const INDEX: Index = Index::new(32);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.0.as_ref());
        Ok(polynomials)
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
        let output = D::try_just(|| {
            let (left_anchor_start, left_anchor_end) = left.take();
            let (right_anchor_start, right_anchor_end) = right.take();
            enforce_zero(
                Fp::from(left_anchor_end) - Fp::from(right_anchor_start),
                "AnchorSpanFuse: spans do not share a vertex",
            )?;
            Ok(((left_anchor_start, right_anchor_end), ()))
        })?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::right(0),
            &Slot::output(0),
            "AnchorSpanFuse: combined is not the union of the halves",
        )?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Compose two [`ArbitraryUnspent`] lineages meeting at an entry anchor.
///
/// The halves meet at one boundary: `left.anchor_next == right.anchor_start`
/// and `left.epoch_next == right.epoch_start`. The left half holds members
/// below that epoch and the right half from it, so the combined sequence is
/// their product.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step<Pasta> for UnspentFuse {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = ArbitraryUnspent;
    /// `(combined_elapsed_seq)`
    type Witness<'source> = (NfSeqPoly,);

    const INDEX: Index = Index::new(2);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.0.as_ref());
        Ok(polynomials)
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
        let output = D::try_just(|| {
            let (left_anchor_start, left_epoch_start, left_epoch_next, left_anchor_next) =
                left.take();
            let (right_anchor_start, right_epoch_start, right_epoch_next, right_anchor_next) =
                right.take();
            enforce_zero(
                Fp::from(left_anchor_next) - Fp::from(right_anchor_start),
                "UnspentFuse: left.anchor_next must equal right.anchor_start",
            )?;
            enforce_zero(
                Fp::from(right_epoch_start) - Fp::from(left_epoch_next),
                "UnspentFuse: halves do not meet at one epoch",
            )?;
            Ok((
                (
                    left_anchor_start,
                    left_epoch_start,
                    right_epoch_next,
                    right_anchor_next,
                ),
                (),
            ))
        })?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::right(0),
            &Slot::output(0),
            "UnspentFuse: combined is not the concatenation of the halves",
        )?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Append one epoch to an [`ArbitraryUnspent`] from that epoch's
/// [`QrBucket`].
///
/// The bucket starts on the segment's excluded bound: `anchor_next` and
/// `epoch_next` are the bucket's `anchor_start` and `epoch`. The step tests one
/// value against the bucket as [`QrUnspentInit`](super::qr::QrUnspentInit)
/// does, appends it to `elapsed` as the member at `epoch_next`, and moves the
/// segment's bound to the bucket's `anchor_next`. One step per epoch, where
/// [`QrUnspentInit`](super::qr::QrUnspentInit) then [`UnspentFuse`] takes two.
///
/// # Soundness
///
/// `elapsed` is the left segment's `L0` slot and `contents` the bucket's `R0`
/// slot. The framework fixes both sequences and stages `value`, so the
/// identity $\mathsf{extended}(z) = \mathsf{elapsed}(z) \cdot F(z)$, with $F$
/// the one indexed member `(epoch_next, value)`, fixes `extended` to `elapsed`
/// plus exactly that member. The member's epoch is `epoch_next`, which
/// advances by one, so `extended` keeps one member per epoch in
/// `[epoch_start, epoch_next)`. `value` is free until
/// [`UnspentBind`] forces it against the note's derivation.
///
/// Three committed polynomials, each opened once.
/// `L0` is elapsed, `O0` extended, and `R0` the bucket contents.
#[derive(Debug)]
pub struct UnspentLift;

impl Step<Pasta> for UnspentLift {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = QrBucket;
    /// `(value, classes, mask, extended_seq)`
    type Witness<'source> = (
        Tachygram,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
    );

    const INDEX: Index = Index::new(24);
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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let native = D::try_just(|| {
            let (value, classes, mask, ..) = witness.take();
            let (
                unspent_anchor_start,
                unspent_epoch_start,
                unspent_epoch_next,
                unspent_anchor_next,
            ) = left.take();
            let (bucket_epoch, bucket_anchor_start, bucket_anchor_next, discriminant, profile) =
                right.take();
            enforce_zero(
                Fp::from(unspent_anchor_next) - Fp::from(bucket_anchor_start),
                "UnspentLift: the bucket does not start where the segment ends",
            )?;
            enforce_zero(
                Fp::from(unspent_epoch_next) - Fp::from(bucket_epoch),
                "UnspentLift: the bucket is not the segment's next epoch",
            )?;
            enforce_nonzero(Fp::from(value), "UnspentLift: tested value is zero")?;
            enforce_value_profile(value, discriminant, profile, &classes, &mask)?;

            let epoch_next = bucket_epoch.next().ok_or_else(|| {
                ragu_core::Error::InvalidWitness("UnspentLift: bucket has no next epoch".into())
            })?;
            let output = (
                unspent_anchor_start,
                unspent_epoch_start,
                epoch_next,
                bucket_anchor_next,
            );
            Ok((value, bucket_epoch, output))
        })?;

        let value_element = Element::alloc(
            dr,
            &mut (),
            native.clone().map(|witnessed| Fp::from(witnessed.0)),
        )?;
        #[expect(
            clippy::indexing_slicing,
            reason = "the framework enforces NUM_STAGED = 1"
        )]
        value_element.enforce_equal(dr, &oracles.staged()[0])?;
        let z = oracles.zeta().clone();
        let elapsed_at_z = oracles.query(dr, Slot::left(0), &z)?;
        let extended_at_z = oracles.query(dr, Slot::output(0), &z)?;
        let challenge = z.value().map(|value| *value);
        let expected = D::try_just(|| {
            let (value, bucket_epoch, _) = native.clone().take();
            Ok(indexed_multiset::direct_eval(
                [(u64::from(bucket_epoch), Fp::from(value))],
                challenge.take(),
            ))
        })?;
        let factor = Element::alloc(dr, &mut (), expected)?;
        let expected_extended = elapsed_at_z.mul(dr, &factor)?;
        extended_at_z
            .enforce_equal(dr, &expected_extended)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "UnspentLift: extended is not elapsed with the tested pair".into(),
                )
            })?;
        let contents_at_value = oracles.query(dr, Slot::right(0), &value_element)?;
        let nonzero_value = Element::promote(
            contents_at_value.wire().clone(),
            contents_at_value.value().map(|value| *value),
        );
        nonzero_value.enforce_nonzero(dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("UnspentLift: found nullifier in the bucket".into())
        })?;

        let output = native.map(|witnessed| witnessed.2);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), output.clone())?;
        Ok(((left_encoded, right_encoded, encoded), output, D::unit()))
    }
}

/// Bind an [`ArbitraryUnspent`]'s free-witness nullifiers to a note's genuine
/// nullifiers, by divisibility into the derivation's sequence.
///
/// Consumes any [`NoteNullifiers`], `elapsed` covering
/// `[epoch_start, epoch_next)`, one member per epoch:
///
/// `nf_seq` factors as
///
/// $$
///   \mathsf{elapsed}(X) \cdot \mathsf{complement}(X)
/// $$
///
/// The complement holds the derivation's members outside the lineage: epochs
/// below it, and the epochs it runs ahead of the exclusion evidence, since a
/// spend publishes two nullifiers while the lineage stops at published
/// evidence.
///
/// # Soundness
///
/// `elapsed` is a subsequence of the derivation, so every one of its members
/// is a genuine derived pair and coverage is a conclusion of the identity.
///
/// Completeness rides `elapsed`'s provenance invariants, so every epoch of
/// `[epoch_start, epoch_next)` was tested with its own genuine nullifier.
///
/// The lineage is note-blind, so the bind stamps the derivation's `cm` onto
/// the validated [`NoteUnspent`].
/// `L0` is elapsed, `R0` the derivation, and `O0` the local complement.
#[derive(Debug)]
pub struct UnspentBind;

impl Step<Pasta> for UnspentBind {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = NoteUnspent;
    type Right = NoteNullifiers;
    /// `(complement_seq)`
    type Witness<'source> = (NfSeqPoly,);

    const INDEX: Index = Index::new(3);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.0.as_ref());
        Ok(polynomials)
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
        // The divisibility bind: `nf_seq = elapsed · complement`, so every
        // elapsed member is a genuine derived pair.
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::output(0),
            &Slot::right(0),
            "UnspentBind: sequence does not match the derivation",
        )?;
        let output = D::try_just(|| {
            let (
                unspent_anchor_start,
                unspent_epoch_start,
                unspent_epoch_next,
                unspent_anchor_next,
            ) = left.take();
            let (nullifiers_cm, ..) = right.take();
            // Defensive. `QrUnspentInit` emits `epoch_next = epoch_start + 1`, and
            // every other producer only raises `epoch_next`, so every
            // `ArbitraryUnspent` covers at least one epoch.
            // TODO: a real circuit needs a range decomposition of
            // `epoch_next - epoch_start`; mock ragu accepts the native comparison.
            if unspent_epoch_next <= unspent_epoch_start {
                return Err(ragu_core::Error::InvalidWitness(
                    "UnspentBind: segment covers no epoch".into(),
                ));
            }

            Ok((
                (
                    nullifiers_cm,
                    unspent_anchor_start,
                    unspent_epoch_start,
                    unspent_epoch_next,
                    unspent_anchor_next,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}
