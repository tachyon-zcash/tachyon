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
use ragu::{
    Encoded, Header, Index, Step, StepCtx,
    pasta::{Eq, Fp},
};
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use ragu_primitives::{Element, GadgetExt as _};
use udon::{curve::Projective as _, field::Field as _};

use super::{delegation::NoteNullifiers, qr::QrBucket};
use crate::{
    gadgets::arithmetic as circuit,
    primitives::{
        Anchor, AnchorSetPoly, EpochIndex, NfSeqPoly, QrClassRoot, QrProfile, Tachygram,
        TachygramSetCommit, TachygramSetPoly,
    },
    relations::enforce::{
        bind_poly_handle, enforce_constant_polynomial, enforce_poly_product, indexed_member_factor,
        poly_handle_limbs,
    },
};

/// Start an [`AnchorSpan`] from one stamp.
///
/// The step folds the stamp into `anchor_start` with [`Anchor::next_stamp`].
/// The span's only member is the resulting anchor, committed with
/// [`AnchorSetCommit::singleton`](crate::primitives::AnchorSetCommit::singleton).
///
/// # Soundness
///
/// `epoch` is a free witness. Consensus computes each fold with the epoch of
/// the block that contains the stamp. A span built with a different epoch
/// holds anchors that are not on the published chain.
#[derive(Debug)]
pub struct AnchorSpanSeed;

impl Step for AnchorSpanSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorSpan;
    type Right = ();
    type Shared = ();
    /// `(anchor_start, epoch, stamp_commit, members)`; `members` is witnessed
    /// off circuit and pinned to exactly `X - anchor_end` by a challenge query.
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetCommit, AnchorSetPoly);

    const INDEX: Index = Index::new(31);

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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left)?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
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
            witness.as_ref().map(|data| Eq::from(data.2).to_affine()),
        )
        .map(|encoding| encoding.limbs)?;
        let anchor_element = crate::gadgets::anchor::AnchorGadget::from(previous.clone())
            .next_stamp(ctx.dr, epoch_element, limbs)
            .map(|anchor| anchor.element)?;
        let members_handle =
            ctx.witness_polynomial(witness.as_ref().map(|data| data.3.as_ref().clone()))?;
        let members_limbs = poly_handle_limbs(ctx.dr, &members_handle)?;
        let challenge = ctx.derive_challenge(&(members_limbs, anchor_element.clone()))?;
        let evaluation = challenge.sub(ctx.dr, &anchor_element);
        ctx.enforce_poly_query(&members_handle, challenge, evaluation)?;
        let output = D::try_just(|| {
            let (anchor_start, _, _, members) = witness.take();
            let anchor_end = Anchor::from(*anchor_element.value().take());

            Ok(((anchor_start, members.commit(), anchor_end), ()))
        })?;
        let (data, aux) = output.cast();
        let fields = crate::stamp::headers::pool::AnchorSpanOutput {
            anchor_start: (previous).into(),
            anchor_end: (anchor_element).into(),
            members: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &members_handle)?,
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

impl Step for AnchorSpanFuse {
    type Aux<'source> = ();
    type Left = AnchorSpan;
    type Output = AnchorSpan;
    type Right = AnchorSpan;
    type Shared = ();
    /// `(left_members, combined, right_members)`
    type Witness<'source> = (AnchorSetPoly, AnchorSetPoly, AnchorSetPoly);

    const INDEX: Index = Index::new(32);

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
        let left_end = left_encoded.as_gadget().anchor_end.element.clone();
        let right_start = right_encoded.as_gadget().anchor_start.element.clone();
        left_end
            .enforce_equal(ctx.dr, &right_start)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "AnchorSpanFuse: spans do not share a vertex".into(),
                )
            })?;
        let left_handle =
            ctx.witness_polynomial(witness.as_ref().map(|members| members.0.as_ref().clone()))?;
        let combined_handle =
            ctx.witness_polynomial(witness.as_ref().map(|members| members.1.as_ref().clone()))?;
        let right_handle =
            ctx.witness_polynomial(witness.as_ref().map(|members| members.2.as_ref().clone()))?;
        bind_poly_handle(
            ctx,
            &left_handle,
            &left_encoded.as_gadget().members.encoding.limbs,
            "AnchorSpanFuse: left members do not match header",
        )?;
        bind_poly_handle(
            ctx,
            &right_handle,
            &right_encoded.as_gadget().members.encoding.limbs,
            "AnchorSpanFuse: right members do not match header",
        )?;
        enforce_poly_product(
            ctx,
            &left_handle,
            &right_handle,
            &combined_handle,
            "AnchorSpanFuse: combined is not the union of the halves",
        )?;
        let output = D::try_just(|| {
            let (_, combined, _) = witness.take();
            let (left_anchor_start, ..) = left.take();
            let (_, _, right_anchor_end) = right.take();
            Ok(((left_anchor_start, combined.commit(), right_anchor_end), ()))
        })?;
        let (data, aux) = output.cast();
        let fields = crate::stamp::headers::pool::AnchorSpanOutput {
            anchor_start: (left_encoded.as_gadget().anchor_start.element.clone()).into(),
            anchor_end: (right_encoded.as_gadget().anchor_end.element.clone()).into(),
            members: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &combined_handle)?,
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

/// Compose two [`ArbitraryUnspent`] lineages meeting at an entry anchor.
///
/// The halves meet at one boundary: `left.anchor_next == right.anchor_start`
/// and `left.epoch_next == right.epoch_start`. The left half holds members
/// below that epoch and the right half from it, so the combined sequence is
/// their product.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = ArbitraryUnspent;
    type Shared = ();
    /// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(2);

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
        let left_anchor = left_encoded.as_gadget().anchor_next.element.clone();
        let right_anchor = right_encoded.as_gadget().anchor_start.element.clone();
        left_anchor
            .enforce_equal(ctx.dr, &right_anchor)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "UnspentFuse: left.anchor_next must equal right.anchor_start".into(),
                )
            })?;
        let left_epoch = left_encoded.as_gadget().epoch_next.element.clone();
        let right_epoch = right_encoded.as_gadget().epoch_start.element.clone();
        left_epoch
            .enforce_equal(ctx.dr, &right_epoch)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "UnspentFuse: halves do not meet at one epoch".into(),
                )
            })?;
        let left_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|sequences| sequences.0.as_ref().clone()),
        )?;
        let combined_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|sequences| sequences.1.as_ref().clone()),
        )?;
        let right_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|sequences| sequences.2.as_ref().clone()),
        )?;
        bind_poly_handle(
            ctx,
            &left_handle,
            &left_encoded.as_gadget().elapsed.encoding.limbs,
            "UnspentFuse: left polynomial does not match header",
        )?;
        bind_poly_handle(
            ctx,
            &right_handle,
            &right_encoded.as_gadget().elapsed.encoding.limbs,
            "UnspentFuse: right polynomial does not match header",
        )?;
        enforce_poly_product(
            ctx,
            &left_handle,
            &right_handle,
            &combined_handle,
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
        let fields = crate::stamp::headers::pool::ArbitraryUnspentOutput {
            anchor_start: (left_encoded.as_gadget().anchor_start.element.clone()).into(),
            epoch_start: (left_encoded.as_gadget().epoch_start.element.clone()).into(),
            epoch_next: (right_encoded.as_gadget().epoch_next.element.clone()).into(),
            anchor_next: (right_encoded.as_gadget().anchor_next.element.clone()).into(),
            elapsed: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &combined_handle)?,
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
/// the bucket. The challenge absorbs both sequences and `[value]·G_0`, so the
/// identity $\mathsf{extended}(z) = \mathsf{elapsed}(z) \cdot F(z)$, with $F$
/// the one indexed member `(epoch_next, value)`, fixes `extended` to `elapsed`
/// plus exactly that member. The member's epoch is `epoch_next`, which
/// advances by one, so `extended` keeps one member per epoch in
/// `[epoch_start, epoch_next)`. `value` is free until
/// [`UnspentBind`] forces it against the note's derivation.
///
/// The elapsed, extended and contents polynomials are joined by a fourth
/// witnessed polynomial: the constant scalar shim. A separate challenge
/// opening binds that shim to the same tested-value Element used below.
#[derive(Debug)]
pub struct UnspentLift;

impl Step for UnspentLift {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = QrBucket;
    type Shared = ();
    /// `(value, classes, mask, elapsed_seq, extended_seq, contents,
    /// value_shim)`
    type Witness<'source> = (
        Tachygram,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
        NfSeqPoly,
        TachygramSetPoly,
        Polynomial<Fp, ProductionRank>,
    );

    const INDEX: Index = Index::new(24);

    #[expect(
        clippy::too_many_lines,
        reason = "the step handles the scalar shim and three checked polynomial openings"
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
        let epoch_element = right_encoded.as_gadget().epoch.element.clone();
        let epoch_next = crate::gadgets::epoch::EpochIndexGadget::from((epoch_element).clone())
            .next(ctx.dr)
            .map(|epoch| epoch.element)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("UnspentLift: bucket has no next epoch".into())
            })?;
        let unspent_epoch = left_encoded.as_gadget().epoch_next.element.clone();
        unspent_epoch
            .enforce_equal(ctx.dr, &epoch_element)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "UnspentLift: the bucket is not the segment's next epoch".into(),
                )
            })?;
        let unspent_end = left_encoded.as_gadget().anchor_next.element.clone();
        let bucket_start = right_encoded.as_gadget().anchor_start.element.clone();
        unspent_end
            .enforce_equal(ctx.dr, &bucket_start)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "UnspentLift: the bucket does not start where the segment ends".into(),
                )
            })?;
        let value_element = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0)),
        )?;
        value_element
            .clone()
            .enforce_nonzero(ctx.dr)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("UnspentLift: tested value is zero".into())
            })?;
        let discriminant_element = right_encoded.as_gadget().discriminant.element.clone();
        crate::gadgets::profile::QrProfileGadget {
            depth: (&[
                right_encoded.as_gadget().profile.depth.clone(),
                right_encoded.as_gadget().profile.bits.clone(),
            ])[0]
                .clone(),
            bits: (&[
                right_encoded.as_gadget().profile.depth.clone(),
                right_encoded.as_gadget().profile.bits.clone(),
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
        let native = D::try_just(|| {
            let (value, _, _, elapsed_seq, extended_seq, contents, _) = witness.clone().take();
            let (unspent_anchor_start, unspent_epoch_start, ..) = left.take();
            let (bucket_epoch, _, bucket_anchor_next, ..) = right.take();
            let output = (
                unspent_anchor_start,
                unspent_epoch_start,
                extended_seq.commit(),
                crate::gadgets::epoch::EpochIndexGadget::from((epoch_next).clone())
                    .value()
                    .take(),
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

        let elapsed_handle =
            ctx.witness_polynomial(native.clone().map(|witnessed| witnessed.0.as_ref().clone()))?;
        let extended_handle =
            ctx.witness_polynomial(native.clone().map(|witnessed| witnessed.1.as_ref().clone()))?;
        let contents_handle =
            ctx.witness_polynomial(native.clone().map(|witnessed| witnessed.2.as_ref().clone()))?;
        bind_poly_handle(
            ctx,
            &elapsed_handle,
            &left_encoded.as_gadget().elapsed.encoding.limbs,
            "UnspentLift: elapsed does not match header",
        )?;
        bind_poly_handle(
            ctx,
            &contents_handle,
            &right_encoded.as_gadget().contents.encoding.limbs,
            "UnspentLift: contents do not match the bucket",
        )?;

        let [elapsed_lo, elapsed_hi] = poly_handle_limbs(ctx.dr, &elapsed_handle)?;
        let [extended_lo, extended_hi] = poly_handle_limbs(ctx.dr, &extended_handle)?;
        let shim_handle = ctx.witness_polynomial(witness.as_ref().map(|data| data.6.clone()))?;
        enforce_constant_polynomial(
            ctx,
            &shim_handle,
            &value_element,
            "UnspentLift: value shim is not constant",
        )?;
        let [shim_lo, shim_hi] = poly_handle_limbs(ctx.dr, &shim_handle)?;
        let z = ctx.derive_challenge(&(
            [elapsed_lo, elapsed_hi],
            ([extended_lo, extended_hi], [shim_lo, shim_hi]),
        ))?;

        let elapsed_assignment =
            ctx.evaluate(&elapsed_handle, z.value().map(|challenge| *challenge))?;
        let extended_assignment =
            ctx.evaluate(&extended_handle, z.value().map(|challenge| *challenge))?;
        let elapsed_at_z = Element::alloc(ctx.dr, &mut (), elapsed_assignment)?;
        let extended_at_z = Element::alloc(ctx.dr, &mut (), extended_assignment)?;
        let index_element = epoch_next.clone();
        let factor = indexed_member_factor(ctx.dr, &value_element, &index_element, &z)?;
        let expected_extended = elapsed_at_z.mul(ctx.dr, &factor)?;
        extended_at_z
            .enforce_equal(ctx.dr, &expected_extended)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "UnspentLift: extended is not elapsed with the tested pair".into(),
                )
            })?;
        ctx.enforce_poly_query(
            &elapsed_handle,
            Element::promote(z.wire().clone(), z.value().map(|challenge| *challenge)),
            elapsed_at_z,
        )?;
        ctx.enforce_poly_query(
            &extended_handle,
            Element::promote(z.wire().clone(), z.value().map(|challenge| *challenge)),
            extended_at_z,
        )?;

        let contents_assignment =
            ctx.evaluate(&contents_handle, value_element.value().map(|value| *value))?;
        let contents_at_value = Element::alloc(ctx.dr, &mut (), contents_assignment)?;
        let nonzero_value = Element::promote(
            contents_at_value.wire().clone(),
            contents_at_value.value().map(|value| *value),
        );
        nonzero_value.enforce_nonzero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("UnspentLift: found nullifier in the bucket".into())
        })?;
        ctx.enforce_poly_query(&contents_handle, value_element, contents_at_value)?;

        let output = native.map(|witnessed| witnessed.5);
        let fields = crate::stamp::headers::pool::ArbitraryUnspentOutput {
            anchor_start: (left_encoded.as_gadget().anchor_start.element.clone()).into(),
            epoch_start: (left_encoded.as_gadget().epoch_start.element.clone()).into(),
            epoch_next: (epoch_next).into(),
            anchor_next: (right_encoded.as_gadget().anchor_next.element.clone()).into(),
            elapsed: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &extended_handle)?,
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
#[derive(Debug)]
pub struct UnspentBind;

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
impl Step for UnspentBind {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = NoteUnspent;
    type Right = NoteNullifiers;
    type Shared = ();
    /// `(elapsed_seq, nf_seq, complement_seq)`
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(3);

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
        let elapsed_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(elapsed_seq, ..)| elapsed_seq.as_ref().clone()),
        )?;
        let nf_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, nf_seq, _)| nf_seq.as_ref().clone()),
        )?;
        let complement_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, complement_seq)| complement_seq.as_ref().clone()),
        )?;
        bind_poly_handle(
            ctx,
            &elapsed_handle,
            &left_encoded.as_gadget().elapsed.encoding.limbs,
            "UnspentBind: elapsed polynomial does not match header",
        )?;
        bind_poly_handle(
            ctx,
            &nf_handle,
            &right_encoded.as_gadget().nf_commit.encoding.limbs,
            "UnspentBind: covering sequence does not match header",
        )?;
        enforce_poly_product(
            ctx,
            &elapsed_handle,
            &complement_handle,
            &nf_handle,
            "UnspentBind: sequence does not match the derivation",
        )?;
        let start = left_encoded.as_gadget().epoch_start.element.clone();
        let end = left_encoded.as_gadget().epoch_next.element.clone();
        let one = Element::constant(ctx.dr, Fp::ONE);
        let span_minus_one = end.sub(ctx.dr, &start).sub(ctx.dr, &one);
        circuit::bits::<D, 32>(ctx.dr, &span_minus_one).map_err(|_err| {
            ragu_core::Error::InvalidWitness("UnspentBind: segment covers no epoch".into())
        })?;
        let output = D::try_just(|| {
            let (
                unspent_anchor_start,
                unspent_epoch_start,
                _,
                unspent_epoch_next,
                unspent_anchor_next,
            ) = left.take();
            let (nullifiers_cm, ..) = right.take();
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
        let fields = crate::stamp::headers::pool::NoteUnspentOutput {
            cm: (right_encoded.as_gadget().cm.element.clone()).into(),
            anchor_start: (left_encoded.as_gadget().anchor_start.element.clone()).into(),
            epoch_start: (left_encoded.as_gadget().epoch_start.element.clone()).into(),
            epoch_next: (left_encoded.as_gadget().epoch_next.element.clone()).into(),
            anchor_next: (left_encoded.as_gadget().anchor_next.element.clone()).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            data,
            aux,
        ))
    }
}

pub use crate::stamp::headers::pool::{AnchorSpan, ArbitraryUnspent, NoteUnspent};
