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

use super::{pool::ArbitraryUnspent, summary::Summary};
pub use crate::{
    collections::qr::classify,
    stamp::headers::qr::{QrBucket, QrIntake, QrIntakeSides},
};
use crate::{
    digest::poseidon,
    primitives::{
        Anchor, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrInterpolantPoly, QrProfile,
        QrQuotientPoly, Tachygram, TachygramSetCommit, TachygramSetPoly,
    },
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
    relations::enforce::{bind_poly_handle, enforce_poly_product, poly_handle_limbs},
};

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
        let output = D::try_just(|| {
            let (discriminant,) = witness.take();
            let (summary_epoch, summary_anchor_prev, summary_anchor_end, summary_acc_commit) =
                left.take();
            let () = right.take();
            Ok((
                (
                    summary_epoch,
                    summary_anchor_prev,
                    summary_anchor_end,
                    discriminant,
                    QrProfile::ROOT,
                    summary_acc_commit,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
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
        let output = D::try_just(|| {
            let (anchor_prev, epoch, discriminant, stamp_commit) = witness.take();
            let () = left.take();
            let () = right.take();
            let anchor_end = anchor_prev
                .next_stamp(epoch, &stamp_commit)
                .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
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
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
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
                    TachygramSetCommit::default(),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
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
        reason = "the native merge also returns three encoded headers"
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
            left.as_ref().map(|data| Eq::from(data.5).to_affine()),
            "QrIntakeMerge: left contents do not match header",
        )?;
        bind_poly_handle(
            ctx,
            &right_handle,
            right.as_ref().map(|data| Eq::from(data.5).to_affine()),
            "QrIntakeMerge: right contents do not match header",
        )?;
        enforce_poly_product(
            ctx,
            &left_handle,
            &right_handle,
            &merged_handle,
            "QrIntakeMerge: merged contents are not the union of the inputs",
        )?;
        let output = D::try_just(|| {
            let (left_contents, right_contents, merged) = witness.take();
            let (
                left_epoch,
                left_anchor_prev,
                left_anchor_end,
                left_discriminant,
                left_profile,
                left_commit,
            ) = left.take();
            let (
                right_epoch,
                right_anchor_prev,
                right_anchor_end,
                right_discriminant,
                right_profile,
                right_commit,
            ) = right.take();
            enforce_zero(
                Fp::from(left_epoch) - Fp::from(right_epoch),
                "QrIntakeMerge: inputs cover different epochs",
            )?;
            enforce_zero(
                Fp::from(left_discriminant) - Fp::from(right_discriminant),
                "QrIntakeMerge: inputs derive from different discriminants",
            )?;
            enforce_zero(
                Fp::from(u64::from(left_profile.depth)) - Fp::from(u64::from(right_profile.depth)),
                "QrIntakeMerge: inputs sit at different depths",
            )?;
            enforce_zero(
                Fp::from(u64::from(left_profile.bits)) - Fp::from(u64::from(right_profile.bits)),
                "QrIntakeMerge: inputs sit at different profiles",
            )?;
            enforce_zero(
                Fp::from(left_anchor_end) - Fp::from(right_anchor_prev),
                "QrIntakeMerge: left.anchor_end must equal right.anchor_prev",
            )?;
            enforce_equal_point(
                Eq::from(left_contents.commit()),
                Eq::from(left_commit),
                "QrIntakeMerge: left contents do not match header",
            )?;
            enforce_equal_point(
                Eq::from(right_contents.commit()),
                Eq::from(right_commit),
                "QrIntakeMerge: right contents do not match header",
            )?;
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
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
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

impl Step for QrIntakeSplit {
    type Aux<'source> = ();
    type Left = QrIntake;
    type Output = QrIntakeSides;
    type Right = ();
    type Shared = ();
    /// `(contents, non_residue, residue)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(17);

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
            left.as_ref().map(|data| Eq::from(data.5).to_affine()),
            "QrIntakeSplit: contents do not match header",
        )?;
        enforce_poly_product(
            ctx,
            &non_residue_handle,
            &residue_handle,
            &contents_handle,
            "QrIntakeSplit: the sides do not partition the contents",
        )?;

        let exceptional = left.as_ref().map(|data| -data.3.at(data.4.depth));
        let exceptional_element = Element::alloc(ctx.dr, &mut (), exceptional)?;
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
            let (contents, non_residue, residue) = witness.take();
            let (epoch, anchor_prev, anchor_end, discriminant, profile, contents_commit) =
                left.take();
            let () = right.take();
            enforce_equal_point(
                Eq::from(contents.commit()),
                Eq::from(contents_commit),
                "QrIntakeSplit: contents do not match header",
            )?;
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
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
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

impl Step for QrSideDescend {
    type Aux<'source> = ();
    type Left = QrIntakeSides;
    type Output = QrIntake;
    type Right = ();
    type Shared = ();
    /// `(bit, sibling_contents, interpolant, quotient)`
    type Witness<'source> = (bool, TachygramSetPoly, QrInterpolantPoly, QrQuotientPoly);

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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        // TODO: a real circuit needs a bit decomposition of `depth` here; mock
        // ragu accepts the native comparison.
        let witness_for_native = witness.clone();
        let native = D::try_just(|| {
            let (bit, sibling_contents, ..) = witness_for_native.take();
            let (epoch, anchor_prev, anchor_end, discriminant, profile, non_residue, residue) =
                left.take();
            let () = right.take();
            if profile.depth >= u32::BITS {
                return Err(ragu_core::Error::InvalidWitness(
                    "QrSideDescend: profile has no bit left for another side".into(),
                ));
            }

            // TODO: a real circuit must constrain `bit` boolean; the type carries it
            // under mock ragu.
            // TODO: select point coordinates in the real circuit. These native group
            // selectors produce identity intermediates when the commitments agree or
            // `bit` is false, which Ragu's nonidentity point gadgets cannot represent.
            let sibling_commit = sibling_contents.commit();
            let sibling = Eq::from(residue)
                + ((Eq::from(non_residue) - Eq::from(residue)) * Fp::from(u64::from(bit)));
            enforce_equal_point(
                Eq::from(sibling_commit),
                sibling,
                "QrSideDescend: sibling does not match the header",
            )?;
            let selected = Eq::from(non_residue)
                + ((Eq::from(residue) - Eq::from(non_residue)) * Fp::from(u64::from(bit)));
            let output = (
                epoch,
                anchor_prev,
                anchor_end,
                discriminant,
                profile.descend(bit),
                TachygramSetCommit::from(selected),
            );
            Ok((
                output,
                bit,
                discriminant.at(profile.depth),
                Eq::from(sibling_commit).to_affine(),
            ))
        })?;
        let sibling_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, sibling, ..)| sibling.as_ref().clone()),
        )?;
        let interpolant_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, interpolant, _)| interpolant.as_ref().clone()),
        )?;
        let quotient_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, _, quotient)| quotient.as_ref().clone()),
        )?;
        bind_poly_handle(
            ctx,
            &sibling_handle,
            native
                .as_ref()
                .map(|(_, _, _, sibling_commit)| *sibling_commit),
            "QrSideDescend: sibling does not match the header",
        )?;

        let [sibling_lo, sibling_hi] = poly_handle_limbs(ctx.dr, &sibling_handle)?;
        let [interpolant_lo, interpolant_hi] = poly_handle_limbs(ctx.dr, &interpolant_handle)?;
        let [quotient_lo, quotient_hi] = poly_handle_limbs(ctx.dr, &quotient_handle)?;
        let discriminant_assignment = native
            .clone()
            .map(|(_, _, discriminant_at_depth, _)| discriminant_at_depth);
        let shim = D::try_just(|| {
            let discriminant_at_depth = discriminant_assignment.take();
            #[expect(clippy::expect_used, reason = "the host generator table is nonempty")]
            let &g0 = Pasta::host_generators(baked())
                .g()
                .first()
                .expect("at least one generator");
            let point = (g0.to_projective() * discriminant_at_depth).to_affine();
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
        let shim_lo = Element::alloc(ctx.dr, &mut (), shim.as_ref().map(|limbs| limbs[0]))?;
        let shim_hi = Element::alloc(ctx.dr, &mut (), shim.as_ref().map(|limbs| limbs[1]))?;
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
        let bit_element = Element::alloc(
            ctx.dr,
            &mut (),
            native.clone().map(|(_, bit, ..)| Fp::from(u64::from(bit))),
        )?;
        let discriminant_element = Element::alloc(
            ctx.dr,
            &mut (),
            native
                .clone()
                .map(|(_, _, discriminant_at_depth, _)| discriminant_at_depth),
        )?;
        let shifted = z.add(ctx.dr, &discriminant_element);
        let sibling_product = sibling_at_z.mul(ctx.dr, &quotient_at_z)?;
        let interpolant_square = interpolant_at_z.square(ctx.dr)?;
        let class_residual = interpolant_square.sub(ctx.dr, &sibling_product);
        let multiplier_delta = Element::constant(ctx.dr, Fp::from(4));
        let scaled_bit = bit_element.mul(ctx.dr, &multiplier_delta)?;
        let one = Element::constant(ctx.dr, Fp::ONE);
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

        let output = native.map(|(output, ..)| output);
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
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let (anchor_final_prev,) = witness.take();
            let (epoch, anchor_prev, anchor_end, discriminant, profile, contents) = left.take();
            let () = right.take();
            enforce_zero(
                Fp::from(anchor_prev)
                    - poseidon::anchor_next_epoch(Fp::from(anchor_final_prev), Fp::from(epoch)),
                "QrBucketSeal: witnessed boundary digest does not match intake's first anchor",
            )?;
            let epoch_next = epoch.next().ok_or_else(|| {
                ragu_core::Error::InvalidWitness(
                    "QrBucketSeal: crossing past the final epoch".into(),
                )
            })?;
            let crossing = anchor_end
                .next_epoch(epoch_next)
                .map_err(|_e| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;

            Ok((
                (
                    epoch,
                    anchor_prev,
                    crossing,
                    discriminant,
                    profile,
                    contents,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
    }
}

/// Fix `value`'s side at every discriminant of the progression from
/// `discriminant`, and check `profile` is the value's first `depth` sides.
///
/// The relations and their soundness are on [`QrUnspentInit`].
/// [`UnspentLift`](super::pool::UnspentLift) runs the same checks.
pub(super) fn enforce_value_profile(
    value: Tachygram,
    discriminant: QrDiscriminant,
    profile: QrProfile,
    classes: &[QrClassRoot; QrProfile::MAX_DEPTH],
    mask: &[bool; QrProfile::MAX_DEPTH],
) -> ragu_core::Result<()> {
    // TODO: a real circuit must constrain every side and mask bit boolean;
    // the types carry it under mock ragu.
    let mut shifted = Fp::from(value) + Fp::from(discriminant);
    let mut position_fp = Fp::ZERO;
    let mut depth_acc = Fp::ZERO;
    let mut index_acc = Fp::ZERO;
    let mut bits_acc = Fp::ZERO;
    for (&QrClassRoot(side, root), &selected) in classes.iter().zip(mask) {
        let side_fp = Fp::from(u64::from(side));
        let multiplier = Fp::from(5) - ((Fp::from(5) - Fp::ONE) * side_fp);
        enforce_zero(
            root.square() - (multiplier * shifted),
            "QR profile: root does not square to the claimed class",
        )?;
        enforce_nonzero(
            (shifted * (Fp::ONE - side_fp)) + side_fp,
            "QR profile: exceptional discriminant claimed the non-residue class",
        )?;

        let selected_fp = Fp::from(u64::from(selected));
        depth_acc += selected_fp;
        index_acc += selected_fp * position_fp;
        bits_acc += selected_fp * (bits_acc + side_fp);
        shifted += Fp::ONE;
        position_fp += Fp::ONE;
    }
    enforce_zero(
        depth_acc - Fp::from(u64::from(profile.depth)),
        "QR profile: depth mask does not match the bucket's depth",
    )?;
    enforce_zero(
        index_acc.double() - (depth_acc * (depth_acc - Fp::ONE)),
        "QR profile: depth mask is not a prefix",
    )?;
    enforce_zero(
        bits_acc - Fp::from(u64::from(profile.bits)),
        "QR profile: value does not take the bucket's profile",
    )?;
    Ok(())
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
    /// `(value, classes, mask, sequence, contents)`
    type Witness<'source> = (
        Tachygram,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(19);

    #[expect(
        clippy::too_many_lines,
        reason = "the step checks a fixed-depth profile and a fixed-width scalar shim"
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
        let native = D::try_just(|| {
            let (value, classes, mask, sequence, contents) = witness.take();
            let (
                bucket_epoch,
                bucket_anchor_start,
                bucket_anchor_next,
                discriminant,
                profile,
                contents_commit,
            ) = left.take();
            let () = right.take();
            enforce_equal_point(
                Eq::from(contents.commit()),
                Eq::from(contents_commit),
                "QrUnspentInit: contents do not match the bucket",
            )?;
            enforce_nonzero(Fp::from(value), "QrUnspentInit: tested value is zero")?;
            enforce_value_profile(value, discriminant, profile, &classes, &mask)?;
            let epoch_next = bucket_epoch.next().ok_or_else(|| {
                ragu_core::Error::InvalidWitness("QrUnspentInit: bucket has no next epoch".into())
            })?;
            let output = (
                bucket_anchor_start,
                bucket_epoch,
                sequence.commit(),
                epoch_next,
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
            left_header
                .as_ref()
                .map(|data| Eq::from(data.5).to_affine()),
            "QrUnspentInit: contents do not match the bucket",
        )?;

        let [sequence_lo, sequence_hi] = poly_handle_limbs(ctx.dr, &sequence_handle)?;
        let value_assignment = native.clone().map(|(_, _, value, ..)| Fp::from(value));
        let scalar_shim = D::try_just(|| {
            let value = value_assignment.take();
            #[expect(clippy::expect_used, reason = "the host generator table is nonempty")]
            let &g0 = Pasta::host_generators(baked())
                .g()
                .first()
                .expect("at least one generator");
            let point = (g0.to_projective() * value).to_affine();
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
        let z = ctx.derive_challenge(&([sequence_lo, sequence_hi], [shim_lo, shim_hi]))?;
        let sequence_assignment =
            ctx.evaluate(&sequence_handle, z.value().map(|challenge| *challenge))?;
        let sequence_at_z = Element::alloc(ctx.dr, &mut (), sequence_assignment)?;
        let value_element = Element::alloc(
            ctx.dr,
            &mut (),
            native.clone().map(|(_, _, value, ..)| Fp::from(value)),
        )?;
        let index_element = Element::alloc(
            ctx.dr,
            &mut (),
            native
                .as_ref()
                .map(|(_, _, _, bucket_epoch, _)| Fp::from(u64::from(*bucket_epoch)) + Fp::ONE),
        )?;
        let index_times_z = index_element.mul(ctx.dr, &z)?;
        let shifted = value_element.add(ctx.dr, &index_times_z);
        let square = shifted.square(ctx.dr)?;
        let cube = square.mul(ctx.dr, &shifted)?;
        let two = Element::constant(ctx.dr, Fp::from(2));
        let expected_sequence = cube.sub(ctx.dr, &two);
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
