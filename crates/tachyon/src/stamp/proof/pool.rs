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
#![expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving their polynomial wrappers"
)]

extern crate alloc;
use ragu::{
    Cycle as _, Encoded, FixedGenerators as _, Header, Index, Step, StepCtx,
    pasta::{Eq, Fp, Pasta},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use ragu_pcd::pasta::baked;
use ragu_primitives::{Element, GadgetExt as _};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use super::{
    delegation::NoteNullifiers,
    qr::{QrBucket, enforce_value_profile},
};
pub use crate::stamp::headers::pool::{AnchorSpan, ArbitraryUnspent, NoteUnspent};
use crate::{
    primitives::{
        Anchor, AnchorSetCommit, AnchorSetPoly, EpochIndex, NfSeqPoly, QrClassRoot, QrProfile,
        Tachygram, TachygramSetCommit, TachygramSetPoly,
    },
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
    relations::enforce::{bind_poly_handle, enforce_poly_product, poly_handle_limbs},
};

/// Start an [`AnchorSpan`] from one stamp.
///
/// The step folds the stamp into `anchor_start` with [`Anchor::next_stamp`].
/// The span's only member is the resulting anchor, committed with
/// [`AnchorSetCommit::singleton`].
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
    /// `(anchor_start, epoch, stamp_commit)`
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetCommit);

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
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let (anchor_start, epoch, stamp_commit) = witness.take();
            let anchor_end = anchor_start
                .next_stamp(epoch, &stamp_commit)
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
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
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
        let left_handle =
            ctx.witness_polynomial(witness.as_ref().map(|members| members.0.as_ref().clone()))?;
        let combined_handle =
            ctx.witness_polynomial(witness.as_ref().map(|members| members.1.as_ref().clone()))?;
        let right_handle =
            ctx.witness_polynomial(witness.as_ref().map(|members| members.2.as_ref().clone()))?;
        bind_poly_handle(
            ctx,
            &left_handle,
            left.as_ref().map(|data| Eq::from(data.1).to_affine()),
            "AnchorSpanFuse: left members do not match header",
        )?;
        bind_poly_handle(
            ctx,
            &right_handle,
            right.as_ref().map(|data| Eq::from(data.1).to_affine()),
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
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
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
            left.as_ref().map(|data| Eq::from(data.2).to_affine()),
            "UnspentFuse: left polynomial does not match header",
        )?;
        bind_poly_handle(
            ctx,
            &right_handle,
            right.as_ref().map(|data| Eq::from(data.2).to_affine()),
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
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
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
/// Three committed polynomials, each opened once.
#[derive(Debug)]
pub struct UnspentLift;

impl Step for UnspentLift {
    type Aux<'source> = ();
    type Left = ArbitraryUnspent;
    type Output = ArbitraryUnspent;
    type Right = QrBucket;
    type Shared = ();
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
        let left_header = left.clone();
        let right_header = right.clone();
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

        let elapsed_handle =
            ctx.witness_polynomial(native.clone().map(|witnessed| witnessed.0.as_ref().clone()))?;
        let extended_handle =
            ctx.witness_polynomial(native.clone().map(|witnessed| witnessed.1.as_ref().clone()))?;
        let contents_handle =
            ctx.witness_polynomial(native.clone().map(|witnessed| witnessed.2.as_ref().clone()))?;
        bind_poly_handle(
            ctx,
            &elapsed_handle,
            left_header
                .as_ref()
                .map(|data| Eq::from(data.2).to_affine()),
            "UnspentLift: elapsed does not match header",
        )?;
        bind_poly_handle(
            ctx,
            &contents_handle,
            right_header
                .as_ref()
                .map(|data| Eq::from(data.5).to_affine()),
            "UnspentLift: contents do not match the bucket",
        )?;

        let [elapsed_lo, elapsed_hi] = poly_handle_limbs(ctx.dr, &elapsed_handle)?;
        let [extended_lo, extended_hi] = poly_handle_limbs(ctx.dr, &extended_handle)?;
        let value_assignment = native.clone().map(|witnessed| Fp::from(witnessed.3));
        let scalar_shim = D::try_just(|| {
            let tested_value = value_assignment.take();
            #[expect(clippy::expect_used, reason = "the host generator table is nonempty")]
            let &g0 = Pasta::host_generators(baked())
                .g()
                .first()
                .expect("at least one generator");
            let point = (g0.to_projective() * tested_value).to_affine();
            let encoding = point.to_bytes();
            let (lo, hi) = encoding.split_at(16);
            let limb = |encoded_limb: &[u8]| -> ragu_core::Result<Fp> {
                let limb_bytes: [u8; 16] = encoded_limb.try_into().map_err(|_err| {
                    ragu_core::Error::InvalidWitness(
                        "a commitment limb must contain 16 bytes".into(),
                    )
                })?;
                Ok(Fp::from_u128(u128::from_le_bytes(limb_bytes)))
            };
            Ok([limb(lo)?, limb(hi)?])
        })?;
        let shim_lo = Element::alloc(ctx.dr, &mut (), scalar_shim.as_ref().map(|limbs| limbs[0]))?;
        let shim_hi = Element::alloc(ctx.dr, &mut (), scalar_shim.as_ref().map(|limbs| limbs[1]))?;
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
        let value_element = Element::alloc(
            ctx.dr,
            &mut (),
            native.clone().map(|witnessed| Fp::from(witnessed.3)),
        )?;
        let index_element = Element::alloc(
            ctx.dr,
            &mut (),
            native
                .as_ref()
                .map(|witnessed| Fp::from(u64::from(witnessed.4)) + Fp::ONE),
        )?;
        let index_times_z = index_element.mul(ctx.dr, &z)?;
        let shifted = value_element.add(ctx.dr, &index_times_z);
        let square = shifted.square(ctx.dr)?;
        let cube = square.mul(ctx.dr, &shifted)?;
        let two = Element::constant(ctx.dr, Fp::from(2));
        let factor = cube.sub(ctx.dr, &two);
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
        let encoded =
            Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), output.clone())?;
        Ok((
            (left_encoded, right_encoded, encoded),
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
            left.as_ref().map(|data| Eq::from(data.2).to_affine()),
            "UnspentBind: elapsed polynomial does not match header",
        )?;
        bind_poly_handle(
            ctx,
            &nf_handle,
            right.as_ref().map(|data| Eq::from(data.2).to_affine()),
            "UnspentBind: covering sequence does not match header",
        )?;
        enforce_poly_product(
            ctx,
            &elapsed_handle,
            &complement_handle,
            &nf_handle,
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
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
    }
}
