//! Stamp header and stamp-producing/transforming steps.

#![expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving their polynomial wrappers"
)]

extern crate alloc;
use ragu::{
    Encoded, Header, Index, Step, StepCtx,
    pasta::{EpAffine, Eq, Fp, Fq},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use ragu_primitives::Element;
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use super::{output::OutputHeader, pool::AnchorSpan, spend::SpendHeader};
pub use crate::stamp::headers::stamp::{Actions, Stamp};
use crate::{
    ActionSetPoly, TachygramSetPoly,
    constants::MAX_MONEY,
    digest::poseidon,
    entropy::ActionEntropy,
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    primitives::{ActionDigest, Anchor, AnchorSetPoly, effect},
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
    relations::enforce::{bind_poly_handle, enforce_poly_product, enforce_poly_roots},
    value,
};

/// Proves an output's action as [`Actions`].
///
/// Reads `cm`, `pad` and `cv` off the [`OutputHeader`]
/// [`OutputBind`](super::output::OutputBind) derived, derives the action
/// randomizer `alpha` from the witnessed `theta` and `cm`, then the randomized
/// action key `rk`, and enforces the one-action set plus the stamp accumulator
/// over the two-element tachygram set `{cm, pad}`.
///
/// `theta` is free, but `alpha` is its hash with the certified `cm`, so an
/// `rk` planned over one note matches another only through a preimage.
///
/// Two permutations (`alpha`, the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set polynomials.
#[derive(Debug)]
pub struct OutputAction;

impl Step for OutputAction {
    type Aux<'source> = ();
    type Left = OutputHeader;
    type Output = Actions;
    type Right = ();
    type Shared = ();
    /// `(theta, anchor, action_set, tachygram_set)`
    type Witness<'source> = (ActionEntropy, Anchor, ActionSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(7);

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
        let action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, action_set, _)| action_set.as_ref().clone()),
        )?;
        let tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, _, tachygram_set)| tachygram_set.as_ref().clone()),
        )?;
        let native = D::try_just(|| {
            let (theta, anchor, action_set, tachygram_set) = witness.take();
            let (cm, pad, cv) = left.take();
            let () = right.take();
            // TODO: a real circuit squeezes alpha in Fp and needs its bit
            // decomposition to use it as an Fq scalar (p < q, so no reduction);
            // mock ragu embeds it natively.
            let alpha = theta.randomizer::<effect::Output>(note::Commitment::from(Fp::from(cm)));
            let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
            let action_digest = ActionDigest::new(cv, rk).map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "OutputAction: action digest construction failed".into(),
                )
            })?;
            let output = (action_set.commit(), tachygram_set.commit(), anchor);
            Ok((output, Fp::from(action_digest), Fp::from(cm), Fp::from(pad)))
        })?;
        let action_root =
            Element::alloc(ctx.dr, &mut (), native.clone().map(|(_, root, ..)| root))?;
        let action_roots = [action_root];
        enforce_poly_roots(
            ctx,
            &action_handle,
            &action_roots,
            "OutputAction: action set does not commit to the action",
        )?;
        let cm_root = Element::alloc(ctx.dr, &mut (), native.clone().map(|(_, _, cm, _)| cm))?;
        let pad_root = Element::alloc(ctx.dr, &mut (), native.clone().map(|(_, _, _, pad)| pad))?;
        let tachygram_roots = [cm_root, pad_root];
        enforce_poly_roots(
            ctx,
            &tachygram_handle,
            &tachygram_roots,
            "OutputAction: tachygram set does not commit to the bound pair",
        )?;
        let data = native.map(|(output, ..)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, D::unit()))
    }
}

/// Proves a spend's action as [`Actions`].
///
/// The spent note's `pk` and value commitment `cv` arrive on the
/// [`SpendHeader`] [`SpendBind`](super::spend::SpendBind) derived. The step
/// derives the action randomizer `alpha` from the witnessed `theta` and `cm`,
/// then the randomized action key `rk`, and enforces the one-action set plus
/// the stamp accumulator over the two-element tachygram set
/// `{nf_current, nf_next}` (the pair `SpendBind` derived from the master
/// key).
///
/// `pk = payment_key(ak, nk)` is the only thing tying `ak` to the note.
/// `theta` is free, but `alpha` is its hash with the certified `cm`, so an
/// `rk` planned over one note matches another only through a preimage.
///
/// Three permutations (`pk`, `alpha`, the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set
/// polynomials.
#[derive(Debug)]
pub struct SpendAction;

impl Step for SpendAction {
    type Aux<'source> = ();
    type Left = SpendHeader;
    type Output = Actions;
    type Right = ();
    type Shared = ();
    /// `(theta, pak, action_set, tachygram_set)`
    type Witness<'source> = (
        ActionEntropy,
        ProofAuthorizingKey,
        ActionSetPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(9);

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
        let action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, action_set, _)| action_set.as_ref().clone()),
        )?;
        let tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, _, tachygram_set)| tachygram_set.as_ref().clone()),
        )?;
        let native = D::try_just(|| {
            let (theta, pak, action_set, tachygram_set) = witness.take();
            let (cm, nf_current, nf_next, anchor, pk, cv) = left.take();
            let () = right.take();
            enforce_zero(
                Fp::from(pk) - Fp::from(pak.derive_payment_key()),
                "SpendAction: pak not related to note",
            )?;
            // TODO: a real circuit squeezes alpha in Fp and needs its bit
            // decomposition to use it as an Fq scalar (p < q, so no reduction);
            // mock ragu embeds it natively.
            let alpha = theta.randomizer::<effect::Spend>(cm);
            let rk = pak.ak.derive_action_public(&alpha);
            let action_digest = ActionDigest::new(cv, rk).map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "SpendAction: action digest construction failed".into(),
                )
            })?;
            let output = (action_set.commit(), tachygram_set.commit(), anchor);
            Ok((
                output,
                Fp::from(action_digest),
                Fp::from(nf_current),
                Fp::from(nf_next),
            ))
        })?;
        let action_root =
            Element::alloc(ctx.dr, &mut (), native.clone().map(|(_, root, ..)| root))?;
        enforce_poly_roots(
            ctx,
            &action_handle,
            &[action_root],
            "SpendAction: action set does not commit to the action",
        )?;
        let current_root = Element::alloc(
            ctx.dr,
            &mut (),
            native.clone().map(|(_, _, current, _)| current),
        )?;
        let next_root =
            Element::alloc(ctx.dr, &mut (), native.clone().map(|(_, _, _, next)| next))?;
        enforce_poly_roots(
            ctx,
            &tachygram_handle,
            &[current_root, next_root],
            "SpendAction: tachygram set does not commit to the nullifier pair",
        )?;
        let data = native.map(|(output, ..)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, D::unit()))
    }
}

/// Transaction assembly and aggregation.
#[derive(Debug)]
pub struct StampMerge;

impl Step for StampMerge {
    type Aux<'source> = ();
    type Left = Stamp;
    type Output = Stamp;
    type Right = Stamp;
    type Shared = ();
    /// `(left, merged, right)`, each an `(action_set, tachygram_set)` pair.
    type Witness<'source> = (
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
    );

    const INDEX: Index = Index::new(10);

    #[expect(
        clippy::too_many_lines,
        reason = "header binding, product constraints, and output projection stay together"
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
        let left_action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|((action_set, _), ..)| action_set.as_ref().clone()),
        )?;
        let left_tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|((_, tachygram_set), ..)| tachygram_set.as_ref().clone()),
        )?;
        let merged_action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, (action_set, _), _)| action_set.as_ref().clone()),
        )?;
        let merged_tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, (_, tachygram_set), _)| tachygram_set.as_ref().clone()),
        )?;
        let right_action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, (action_set, _))| action_set.as_ref().clone()),
        )?;
        let right_tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, (_, tachygram_set))| tachygram_set.as_ref().clone()),
        )?;
        bind_poly_handle(
            ctx,
            &left_action_handle,
            left.as_ref().map(|data| Eq::from(data.0).to_affine()),
            "StampMerge: left action accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &left_tachygram_handle,
            left.as_ref().map(|data| Eq::from(data.1).to_affine()),
            "StampMerge: left tachygram accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &right_action_handle,
            right.as_ref().map(|data| Eq::from(data.0).to_affine()),
            "StampMerge: right action accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &right_tachygram_handle,
            right.as_ref().map(|data| Eq::from(data.1).to_affine()),
            "StampMerge: right tachygram accumulator must commit to header commit",
        )?;
        enforce_poly_product(
            ctx,
            &left_action_handle,
            &right_action_handle,
            &merged_action_handle,
            "StampMerge: merged action set must be the product of left and right action sets",
        )?;
        enforce_poly_product(
            ctx,
            &left_tachygram_handle,
            &right_tachygram_handle,
            &merged_tachygram_handle,
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        )?;
        let output = D::try_just(|| {
            let (
                (left_action_set, left_tachygram_set),
                (merged_action_set, merged_tachygram_set),
                (right_action_set, right_tachygram_set),
            ) = witness.take();
            let (left_action_commit, left_tachygram_commit, left_anchor) = left.take();
            let (right_action_commit, right_tachygram_commit, right_anchor) = right.take();
            enforce_zero(
                Fp::from(left_anchor) - Fp::from(right_anchor),
                "StampMerge: anchors must match",
            )?;
            enforce_equal_point(
                Eq::from(left_action_set.commit()),
                Eq::from(left_action_commit),
                "StampMerge: left action accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(right_action_set.commit()),
                Eq::from(right_action_commit),
                "StampMerge: right action accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(left_tachygram_set.commit()),
                Eq::from(left_tachygram_commit),
                "StampMerge: left tachygram accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(right_tachygram_set.commit()),
                Eq::from(right_tachygram_commit),
                "StampMerge: right tachygram accumulator must commit to header commit",
            )?;
            Ok((
                (
                    merged_action_set.commit(),
                    merged_tachygram_set.commit(),
                    left_anchor,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
    }
}

/// Merges action content.
#[derive(Debug)]
pub struct ActionMerge;

impl Step for ActionMerge {
    type Aux<'source> = ();
    type Left = Actions;
    type Output = Actions;
    type Right = Actions;
    type Shared = ();
    /// `(left, merged, right)`, each an `(action_set, tachygram_set)` pair.
    type Witness<'source> = (
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
    );

    const INDEX: Index = Index::new(34);

    #[expect(
        clippy::too_many_lines,
        reason = "header binding, product constraints, and output projection stay together"
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
        let left_action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|((action_set, _), ..)| action_set.as_ref().clone()),
        )?;
        let left_tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|((_, tachygram_set), ..)| tachygram_set.as_ref().clone()),
        )?;
        let merged_action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, (action_set, _), _)| action_set.as_ref().clone()),
        )?;
        let merged_tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, (_, tachygram_set), _)| tachygram_set.as_ref().clone()),
        )?;
        let right_action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, (action_set, _))| action_set.as_ref().clone()),
        )?;
        let right_tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, (_, tachygram_set))| tachygram_set.as_ref().clone()),
        )?;
        bind_poly_handle(
            ctx,
            &left_action_handle,
            left.as_ref().map(|data| Eq::from(data.0).to_affine()),
            "ActionMerge: left action accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &left_tachygram_handle,
            left.as_ref().map(|data| Eq::from(data.1).to_affine()),
            "ActionMerge: left tachygram accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &right_action_handle,
            right.as_ref().map(|data| Eq::from(data.0).to_affine()),
            "ActionMerge: right action accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &right_tachygram_handle,
            right.as_ref().map(|data| Eq::from(data.1).to_affine()),
            "ActionMerge: right tachygram accumulator must commit to header commit",
        )?;
        enforce_poly_product(
            ctx,
            &left_action_handle,
            &right_action_handle,
            &merged_action_handle,
            "ActionMerge: merged action set must be the product of left and right action sets",
        )?;
        enforce_poly_product(
            ctx,
            &left_tachygram_handle,
            &right_tachygram_handle,
            &merged_tachygram_handle,
            "ActionMerge: merged tachygram set must be the product of left and right tachygram sets",
        )?;
        let output = D::try_just(|| {
            let (
                (left_action_set, left_tachygram_set),
                (merged_action_set, merged_tachygram_set),
                (right_action_set, right_tachygram_set),
            ) = witness.take();
            let (left_action_commit, left_tachygram_commit, left_anchor) = left.take();
            let (right_action_commit, right_tachygram_commit, right_anchor) = right.take();
            enforce_zero(
                Fp::from(left_anchor) - Fp::from(right_anchor),
                "ActionMerge: anchors must match",
            )?;
            enforce_equal_point(
                Eq::from(left_action_set.commit()),
                Eq::from(left_action_commit),
                "ActionMerge: left action accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(right_action_set.commit()),
                Eq::from(right_action_commit),
                "ActionMerge: right action accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(left_tachygram_set.commit()),
                Eq::from(left_tachygram_commit),
                "ActionMerge: left tachygram accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(right_tachygram_set.commit()),
                Eq::from(right_tachygram_commit),
                "ActionMerge: right tachygram accumulator must commit to header commit",
            )?;
            Ok((
                (
                    merged_action_set.commit(),
                    merged_tachygram_set.commit(),
                    left_anchor,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
    }
}

/// Advance a stamp's anchor to the end of an [`AnchorSpan`].
///
/// The stamp's `anchor` must be the span's `anchor_start` or one of its
/// members:
///
/// $$
///   M(\mathsf{anchor}) \cdot (\mathsf{anchor} - \mathsf{anchor\_start}) = 0
/// $$
///
/// The output anchor is always `anchor_end`, because the members polynomial
/// does not record the order of its members. A stamp already at `anchor_end`
/// keeps its anchor.
///
/// # Soundness
///
/// The step opens $M$ at the stamp's anchor, and checks $M$'s commitment
/// against the header's `members`. A stamp anchored outside the span passes
/// only if its anchor collides with `anchor_start` or a member.
#[derive(Debug)]
pub struct StampLift;

impl Step for StampLift {
    type Aux<'source> = ();
    type Left = Stamp;
    type Output = Stamp;
    type Right = AnchorSpan;
    type Shared = ();
    /// `(members)`
    type Witness<'source> = (AnchorSetPoly,);

    const INDEX: Index = Index::new(11);

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
        let handle =
            ctx.witness_polynomial(witness.as_ref().map(|(members,)| members.as_ref().clone()))?;
        bind_poly_handle(
            ctx,
            &handle,
            right.as_ref().map(|data| Eq::from(data.1).to_affine()),
            "StampLift: members do not match header",
        )?;
        let anchor = Element::alloc(ctx.dr, &mut (), left.as_ref().map(|data| Fp::from(data.2)))?;
        let anchor_start =
            Element::alloc(ctx.dr, &mut (), right.as_ref().map(|data| Fp::from(data.0)))?;
        let anchor_assignment =
            ctx.evaluate(&handle, anchor.value().map(|coordinate| *coordinate))?;
        let anchor_evaluation = Element::alloc(ctx.dr, &mut (), anchor_assignment)?;
        let delta = anchor.sub(ctx.dr, &anchor_start);
        let membership = anchor_evaluation.mul(ctx.dr, &delta)?;
        membership.enforce_zero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "StampLift: stamp anchor is neither the span's start nor a member".into(),
            )
        })?;
        ctx.enforce_poly_query(&handle, anchor, anchor_evaluation)?;
        let output = D::try_just(|| {
            let (members,) = witness.take();
            let (stamp_action_commit, stamp_tachygram_commit, _stamp_anchor) = left.take();
            let (_span_anchor_start, span_members, span_anchor_end) = right.take();
            enforce_equal_point(
                Eq::from(members.commit()),
                Eq::from(span_members),
                "StampLift: members do not match header",
            )?;
            Ok((
                (stamp_action_commit, stamp_tachygram_commit, span_anchor_end),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
    }
}

/// Advances action content's anchor to the end of an [`AnchorSpan`].
///
/// The actions' `anchor` must be the span's `anchor_start` or one of its
/// members.
#[derive(Debug)]
pub struct ActionLift;

impl Step for ActionLift {
    type Aux<'source> = ();
    type Left = Actions;
    type Output = Actions;
    type Right = AnchorSpan;
    type Shared = ();
    /// `(members)`
    type Witness<'source> = (AnchorSetPoly,);

    const INDEX: Index = Index::new(35);

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
        let handle =
            ctx.witness_polynomial(witness.as_ref().map(|(members,)| members.as_ref().clone()))?;
        bind_poly_handle(
            ctx,
            &handle,
            right.as_ref().map(|data| Eq::from(data.1).to_affine()),
            "ActionLift: members do not match header",
        )?;
        let anchor = Element::alloc(ctx.dr, &mut (), left.as_ref().map(|data| Fp::from(data.2)))?;
        let anchor_start =
            Element::alloc(ctx.dr, &mut (), right.as_ref().map(|data| Fp::from(data.0)))?;
        let anchor_assignment =
            ctx.evaluate(&handle, anchor.value().map(|coordinate| *coordinate))?;
        let anchor_evaluation = Element::alloc(ctx.dr, &mut (), anchor_assignment)?;
        let delta = anchor.sub(ctx.dr, &anchor_start);
        let membership = anchor_evaluation.mul(ctx.dr, &delta)?;
        membership.enforce_zero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "ActionLift: actions anchor is neither the span's start nor a member".into(),
            )
        })?;
        ctx.enforce_poly_query(&handle, anchor, anchor_evaluation)?;
        let output = D::try_just(|| {
            let (members,) = witness.take();
            let (actions_action_commit, actions_tachygram_commit, _actions_anchor) = left.take();
            let (_span_anchor_start, span_members, span_anchor_end) = right.take();
            enforce_equal_point(
                Eq::from(members.commit()),
                Eq::from(span_members),
                "ActionLift: members do not match header",
            )?;
            Ok((
                (
                    actions_action_commit,
                    actions_tachygram_commit,
                    span_anchor_end,
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, aux))
    }
}

/// Turns [`Actions`] into a [`Stamp`] by adding the fee digest and fee change
/// note's commitment to the action and tachygram sets.
#[derive(Debug)]
pub struct FeeFuse;

impl Step for FeeFuse {
    type Aux<'source> = ();
    type Left = Actions;
    type Output = Stamp;
    type Right = ();
    type Shared = ();
    type Witness<'source> = (
        Note,
        value::Positive,
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
    );

    const INDEX: Index = Index::new(33);

    #[expect(
        clippy::too_many_lines,
        reason = "fee derivation, six handle witnesses, and all relations are coupled"
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
        let left_action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, (action_set, _), ..)| action_set.as_ref().clone()),
        )?;
        let left_tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, (_, tachygram_set), ..)| tachygram_set.as_ref().clone()),
        )?;
        let output_action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, _, (action_set, _), _)| action_set.as_ref().clone()),
        )?;
        let output_tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, _, (_, tachygram_set), _)| tachygram_set.as_ref().clone()),
        )?;
        let fee_action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, _, _, (action_set, _))| action_set.as_ref().clone()),
        )?;
        let fee_tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, _, _, (_, tachygram_set))| tachygram_set.as_ref().clone()),
        )?;
        bind_poly_handle(
            ctx,
            &left_action_handle,
            left.as_ref().map(|data| Eq::from(data.0).to_affine()),
            "FeeFuse: left action accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &left_tachygram_handle,
            left.as_ref().map(|data| Eq::from(data.1).to_affine()),
            "FeeFuse: left tachygram accumulator must commit to header commit",
        )?;
        let native = D::try_just(|| {
            let (
                max_fee_note,
                fee,
                (left_action_set, left_tachygram_set),
                (output_action_set, output_tachygram_set),
                (_fee_action_set, _fee_tachygram_set),
            ) = witness.take();
            let (left_action_commit, left_tachygram_commit, left_anchor) = left.take();
            let () = right.take();
            enforce_equal_point(
                Eq::from(left_action_set.commit()),
                Eq::from(left_action_commit),
                "FeeFuse: left action accumulator must commit to header commit",
            )?;
            enforce_equal_point(
                Eq::from(left_tachygram_set.commit()),
                Eq::from(left_tachygram_commit),
                "FeeFuse: left tachygram accumulator must commit to header commit",
            )?;

            let max_fee = u64::from(max_fee_note.value);
            if max_fee > MAX_MONEY {
                return Err(ragu_core::Error::InvalidWitness(
                    "FeeFuse: maximum fee exceeds MAX_MONEY".into(),
                ));
            }
            let change = max_fee
                .checked_sub(u64::from(fee))
                .filter(|&change| change <= MAX_MONEY)
                .ok_or_else(|| {
                    ragu_core::Error::InvalidWitness("FeeFuse: change is out of range".into())
                })?;
            let (pk, psi, rcm) = (
                Fp::from(max_fee_note.pk),
                Fp::from(max_fee_note.psi),
                Fp::from(max_fee_note.rcm),
            );
            // TODO: a real circuit squeezes r in Fp and needs its bit
            // decomposition to use it as an Fq scalar (p < q, so no reduction);
            // mock ragu embeds it natively.
            let blind = poseidon::fee_blind(pk, psi, rcm);
            #[expect(
                clippy::expect_used,
                reason = "p < q, so every Fp repr is canonical in Fq"
            )]
            let cv_max_fee =
                value::Trapdoor::from_scalar(Fq::from_bytes(blind.to_bytes()).expect("p < q"))
                    .commit(-max_fee_note.value);
            let (cv_max_fee_x, cv_max_fee_y) =
                EpAffine::from(cv_max_fee).coordinates().ok_or_else(|| {
                    ragu_core::Error::InvalidWitness(
                        "FeeFuse: fee commitment is the identity".into(),
                    )
                })?;
            let fee_digest = poseidon::fee_digest((cv_max_fee_x, cv_max_fee_y), u64::from(fee));
            let fee_change_commitment = enforce_nonzero(
                poseidon::note_commitment(rcm, pk, change, psi),
                "FeeFuse: fee change note commitment is zero",
            )?;
            let output = (
                output_action_set.commit(),
                output_tachygram_set.commit(),
                left_anchor,
            );
            Ok((output, fee_digest, fee_change_commitment))
        })?;

        let fee_digest =
            Element::alloc(ctx.dr, &mut (), native.clone().map(|(_, digest, _)| digest))?;
        enforce_poly_roots(
            ctx,
            &fee_action_handle,
            &[fee_digest],
            "FeeFuse: fee action set does not commit to the fee digest",
        )?;
        let fee_change =
            Element::alloc(ctx.dr, &mut (), native.clone().map(|(_, _, change)| change))?;
        enforce_poly_roots(
            ctx,
            &fee_tachygram_handle,
            &[fee_change],
            "FeeFuse: fee tachygram set does not commit to the fee change note",
        )?;
        enforce_poly_product(
            ctx,
            &left_action_handle,
            &fee_action_handle,
            &output_action_handle,
            "FeeFuse: output action set must be the product of left and fee action sets",
        )?;
        enforce_poly_product(
            ctx,
            &left_tachygram_handle,
            &fee_tachygram_handle,
            &output_tachygram_handle,
            "FeeFuse: output tachygram set must be the product of left and fee tachygram sets",
        )?;
        let data = native.map(|(output, ..)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, D::unit()))
    }
}

/// Proves a zero-action bundle's zero fee.
#[derive(Debug)]
pub struct FeeSeed;

impl Step for FeeSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Stamp;
    type Right = ();
    type Shared = ();
    /// `(max_fee_note, anchor, fee_action_set, fee_tachygram_set)`
    type Witness<'source> = (Note, Anchor, ActionSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(36);

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
        let action_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, action_set, _)| action_set.as_ref().clone()),
        )?;
        let tachygram_handle = ctx.witness_polynomial(
            witness
                .as_ref()
                .map(|(_, _, _, tachygram_set)| tachygram_set.as_ref().clone()),
        )?;
        let native = D::try_just(|| {
            let (max_fee_note, anchor, fee_action_set, fee_tachygram_set) = witness.take();
            let () = left.take();
            let () = right.take();
            enforce_zero(
                Fp::from(u64::from(max_fee_note.value)),
                "FeeSeed: maximum fee must be zero",
            )?;
            let (pk, psi, rcm) = (
                Fp::from(max_fee_note.pk),
                Fp::from(max_fee_note.psi),
                Fp::from(max_fee_note.rcm),
            );
            // TODO: a real circuit squeezes r in Fp and needs its bit
            // decomposition to use it as an Fq scalar (p < q, so no reduction);
            // mock ragu embeds it natively.
            let blind = poseidon::fee_blind(pk, psi, rcm);
            #[expect(
                clippy::expect_used,
                reason = "p < q, so every Fp repr is canonical in Fq"
            )]
            let cv_max_fee =
                value::Trapdoor::from_scalar(Fq::from_bytes(blind.to_bytes()).expect("p < q"))
                    .commit(-max_fee_note.value);
            let (cv_max_fee_x, cv_max_fee_y) =
                EpAffine::from(cv_max_fee).coordinates().ok_or_else(|| {
                    ragu_core::Error::InvalidWitness(
                        "FeeSeed: fee commitment is the identity".into(),
                    )
                })?;
            let fee_digest = poseidon::fee_digest((cv_max_fee_x, cv_max_fee_y), 0);
            let fee_change_commitment = enforce_nonzero(
                poseidon::note_commitment(rcm, pk, 0, psi),
                "FeeSeed: fee change note commitment is zero",
            )?;
            let output = (fee_action_set.commit(), fee_tachygram_set.commit(), anchor);
            Ok((output, fee_digest, fee_change_commitment))
        })?;
        let fee_digest =
            Element::alloc(ctx.dr, &mut (), native.clone().map(|(_, digest, _)| digest))?;
        enforce_poly_roots(
            ctx,
            &action_handle,
            &[fee_digest],
            "FeeSeed: fee action set does not commit to the fee digest",
        )?;
        let fee_change =
            Element::alloc(ctx.dr, &mut (), native.clone().map(|(_, _, change)| change))?;
        enforce_poly_roots(
            ctx,
            &tachygram_handle,
            &[fee_change],
            "FeeSeed: fee tachygram set does not commit to the fee change note",
        )?;
        let data = native.map(|(output, ..)| output);
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(ctx.dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), (), data, D::unit()))
    }
}
