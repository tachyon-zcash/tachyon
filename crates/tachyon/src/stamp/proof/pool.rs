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

use ragu::{Encoded, Header, HeaderInput, Index, Oracles, Slot, Step, pasta::Pasta};
use ragu_core::{
    drivers::{Driver, DriverValue},
    maybe::Maybe as _,
};
use ragu_primitives::{Element, GadgetExt as _};
use udon::field::Field as _;

use super::{
    delegation::NoteNullifiers,
    qr::{QrBucket, enforce_value_profile},
};
pub use crate::stamp::headers::pool::{AnchorSpan, ArbitraryUnspent, NoteUnspent};
use crate::{
    digest::poseidon,
    pasta::{Eq, Fp},
    primitives::{
        Anchor, AnchorSetCommit, AnchorSetPoly, EpochIndex, NfSeqPoly, QrClassRoot, QrProfile,
        Tachygram, TachygramSetPoly,
    },
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
    relations::enforce::{enforce_poly_product, enforce_poly_roots},
};

/// Start an [`AnchorSpan`] from one stamp.
///
/// The step folds the stamp into `anchor_start` with [`Anchor::next_stamp`].
/// The span's only member is the resulting anchor, committed with
/// [`AnchorSetCommit::singleton`].
/// `O0` carries that singleton; `O1` carries the stamp for its bridge digest.
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
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetPoly);

    const INDEX: Index = Index::new(31);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        let end = witness
            .0
            .next_stamp(witness.1, &witness.2.commit())
            .map_err(|_err| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = alloc::vec![-Fp::from(end), Fp::ONE];
        polynomials[1] = super::coefficients(witness.2.as_ref());
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
        let epoch = Element::alloc(
            dr,
            &mut (),
            witness.as_ref().map(|fields| Fp::from(fields.1)),
        )?;
        let output = D::try_just(|| {
            let (anchor_start, epoch_index, stamp) = witness.take();
            let stamp_commit = stamp.commit();
            let anchor_end = anchor_start
                .next_stamp(epoch_index, &stamp_commit)
                .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;

            Ok((
                (
                    anchor_start,
                    AnchorSetCommit::singleton(anchor_end),
                    anchor_end,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        let header = encoded.as_gadget();
        enforce_poly_roots(
            dr,
            oracles,
            &Slot::output(0),
            array::from_ref(&header.anchor_end.element),
            "AnchorSpanSeed: members must contain the resulting anchor",
        )?;
        let anchor = poseidon::anchor_next_stamp_gadget(
            dr,
            &header.anchor_start.element,
            &epoch,
            oracles.bridge_hash(),
        )?;
        header.anchor_end.element.enforce_equal(dr, &anchor)?;
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
/// The step checks each half's witnessed polynomial against its header's
/// `members`. The product check's challenge absorbs all three commitments.
/// `combined` therefore holds exactly the members of both halves.
#[derive(Debug)]
pub struct AnchorSpanFuse;

impl Step<Pasta> for AnchorSpanFuse {
    type Aux<'source> = ();
    type Left = AnchorSpan;
    type Output = AnchorSpan;
    type Right = AnchorSpan;
    /// `(left_members, combined, right_members)`
    type Witness<'source> = (AnchorSetPoly, AnchorSetPoly, AnchorSetPoly);

    const INDEX: Index = Index::new(32);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.1.as_ref());
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
        let _precheck = D::try_just(|| {
            let (left_members, _, right_members) = witness.clone().take();
            let (_left_anchor_start, left_members_commit, left_anchor_end) = left.clone().take();
            let (right_anchor_start, right_members_commit, _) = right.clone().take();
            enforce_zero(
                Fp::from(left_anchor_end) - Fp::from(right_anchor_start),
                "AnchorSpanFuse: spans do not share a vertex",
            )?;
            enforce_equal_point(
                Eq::from(left_members.commit()),
                Eq::from(left_members_commit),
                "AnchorSpanFuse: left members do not match header",
            )?;
            enforce_equal_point(
                Eq::from(right_members.commit()),
                Eq::from(right_members_commit),
                "AnchorSpanFuse: right members do not match header",
            )?;
            Ok(())
        })?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::right(0),
            &Slot::output(0),
            "AnchorSpanFuse: combined is not the union of the halves",
        )?;
        let output = D::try_just(|| {
            let (left_members, combined, right_members) = witness.take();
            let (left_anchor_start, left_members_commit, left_anchor_end) = left.take();
            let (right_anchor_start, right_members_commit, right_anchor_end) = right.take();
            enforce_zero(
                Fp::from(left_anchor_end) - Fp::from(right_anchor_start),
                "AnchorSpanFuse: spans do not share a vertex",
            )?;
            enforce_equal_point(
                Eq::from(left_members.commit()),
                Eq::from(left_members_commit),
                "AnchorSpanFuse: left members do not match header",
            )?;
            enforce_equal_point(
                Eq::from(right_members.commit()),
                Eq::from(right_members_commit),
                "AnchorSpanFuse: right members do not match header",
            )?;
            Ok(((left_anchor_start, combined.commit(), right_anchor_end), ()))
        })?;
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
    /// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(2);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.1.as_ref());
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
        let _precheck = D::try_just(|| {
            let (left_elapsed_seq, _, right_elapsed_seq) = witness.clone().take();
            let (_, _, left_elapsed, left_epoch_next, left_anchor_next) = left.clone().take();
            let (right_anchor_start, right_epoch_start, right_elapsed, ..) = right.clone().take();
            enforce_equal_point(
                Eq::from(left_elapsed_seq.commit()),
                Eq::from(left_elapsed),
                "UnspentFuse: left polynomial does not match header",
            )?;
            enforce_equal_point(
                Eq::from(right_elapsed_seq.commit()),
                Eq::from(right_elapsed),
                "UnspentFuse: right polynomial does not match header",
            )?;
            enforce_zero(
                Fp::from(left_anchor_next) - Fp::from(right_anchor_start),
                "UnspentFuse: left.anchor_next must equal right.anchor_start",
            )?;
            enforce_zero(
                Fp::from(right_epoch_start) - Fp::from(left_epoch_next),
                "UnspentFuse: halves do not meet at one epoch",
            )?;
            Ok(())
        })?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::right(0),
            &Slot::output(0),
            "UnspentFuse: combined is not the concatenation of the halves",
        )?;
        let output = D::try_just(|| {
            let (_left_elapsed_seq, combined_elapsed_seq, _right_elapsed_seq) = witness.take();
            let (left_anchor_start, left_epoch_start, ..) = left.take();
            let (_, _, _, right_epoch_next, right_anchor_next) = right.take();
            Ok((
                (
                    left_anchor_start,
                    left_epoch_start,
                    combined_elapsed_seq.commit(),
                    right_epoch_next,
                    right_anchor_next,
                ),
                (),
            ))
        })?;
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
/// `elapsed_seq` is bound to the header by commit-equality and `contents` to
/// the bucket. The framework fixes both sequences and stages `value`, so the
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
    /// `(value, classes, mask, elapsed_seq, extended_seq, contents)`
    type Witness<'source> = (
        Tachygram,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
        NfSeqPoly,
        TachygramSetPoly,
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
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
        let mut polynomials = super::unit_polynomials();
        polynomials[0] = super::coefficients(witness.4.as_ref());
        Ok(polynomials)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "exclusion and the three-polynomial extension identity share one witness"
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
        let native = D::try_just(|| {
            let (value, classes, mask, elapsed_seq, extended_seq, contents) = witness.take();
            let (
                unspent_anchor_start,
                unspent_epoch_start,
                unspent_elapsed,
                unspent_epoch_next,
                unspent_anchor_next,
            ) = left.take();
            let (
                bucket_epoch,
                bucket_anchor_start,
                bucket_anchor_next,
                discriminant,
                profile,
                contents_commit,
            ) = right.take();
            enforce_zero(
                Fp::from(unspent_anchor_next) - Fp::from(bucket_anchor_start),
                "UnspentLift: the bucket does not start where the segment ends",
            )?;
            enforce_zero(
                Fp::from(unspent_epoch_next) - Fp::from(bucket_epoch),
                "UnspentLift: the bucket is not the segment's next epoch",
            )?;
            enforce_equal_point(
                Eq::from(contents.commit()),
                Eq::from(contents_commit),
                "UnspentLift: contents do not match the bucket",
            )?;
            enforce_equal_point(
                Eq::from(elapsed_seq.commit()),
                Eq::from(unspent_elapsed),
                "UnspentLift: elapsed does not match header",
            )?;
            enforce_nonzero(Fp::from(value), "UnspentLift: tested value is zero")?;
            enforce_value_profile(value, discriminant, profile, &classes, &mask)?;

            let epoch_next = bucket_epoch.next().ok_or_else(|| {
                ragu_core::Error::InvalidWitness("UnspentLift: bucket has no next epoch".into())
            })?;
            let output = (
                unspent_anchor_start,
                unspent_epoch_start,
                extended_seq.commit(),
                epoch_next,
                bucket_anchor_next,
            );
            Ok((
                elapsed_seq,
                extended_seq,
                contents,
                value,
                bucket_epoch,
                output,
            ))
        })?;

        let value_element = Element::alloc(
            dr,
            &mut (),
            native.clone().map(|witnessed| Fp::from(witnessed.3)),
        )?;
        #[expect(
            clippy::indexing_slicing,
            reason = "the framework enforces NUM_STAGED = 1"
        )]
        value_element.enforce_equal(dr, &oracles.staged()[0])?;
        let z = oracles.zeta().clone();
        let elapsed_at_z = oracles.query_at_zeta(dr, Slot::left(0))?;
        let extended_at_z = oracles.query_at_zeta(dr, Slot::output(0))?;
        let index_element = Element::alloc(
            dr,
            &mut (),
            native
                .as_ref()
                .map(|witnessed| Fp::from(u64::from(witnessed.4)) + Fp::ONE),
        )?;
        let index_times_z = index_element.mul(dr, &z)?;
        let shifted = value_element.add(dr, &index_times_z);
        let square = shifted.square(dr)?;
        let cube = square.mul(dr, &shifted)?;
        let two = Element::constant(dr, Fp::from(2));
        let factor = cube.sub(dr, &two);
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

        let output = native.map(|witnessed| witnessed.5);
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
    /// `(elapsed_seq, nf_seq, complement_seq)`
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(3);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 3]> {
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
        let _precheck = D::try_just(|| {
            let (elapsed_seq, nf_seq, _) = witness.clone().take();
            let (_, _, elapsed_commit, ..) = left.clone().take();
            let (_, _, nf_commit, _) = right.clone().take();
            enforce_equal_point(
                elapsed_seq.commit().into(),
                Eq::from(elapsed_commit),
                "UnspentBind: elapsed polynomial does not match header",
            )?;
            enforce_equal_point(
                nf_seq.commit().into(),
                Eq::from(nf_commit),
                "UnspentBind: covering sequence does not match header",
            )?;
            Ok(())
        })?;
        enforce_poly_product(
            dr,
            oracles,
            &Slot::left(0),
            &Slot::output(0),
            &Slot::right(0),
            "UnspentBind: sequence does not match the derivation",
        )?;
        let output = D::try_just(|| {
            let (elapsed_seq, nf_seq, _complement_seq) = witness.take();
            let (
                unspent_anchor_start,
                unspent_epoch_start,
                unspent_elapsed,
                unspent_epoch_next,
                unspent_anchor_next,
            ) = left.take();
            let (nullifiers_cm, _, nf_commit, _) = right.take();
            if unspent_epoch_next <= unspent_epoch_start {
                return Err(ragu_core::Error::InvalidWitness(
                    "UnspentBind: segment covers no epoch".into(),
                ));
            }

            enforce_equal_point(
                elapsed_seq.commit().into(),
                Eq::from(unspent_elapsed),
                "UnspentBind: elapsed polynomial does not match header",
            )?;
            enforce_equal_point(
                Eq::from(nf_seq.commit()),
                Eq::from(nf_commit),
                "UnspentBind: covering sequence does not match header",
            )?;
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
