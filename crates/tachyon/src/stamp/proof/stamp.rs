//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use ragu::{
    Cycle as _, Encoded, Header, Index, PoseidonPermutation as _, Step, StepCtx,
    pasta::{EpAffine, Fp, Pasta, PoseidonFp},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use ragu_pcd::pasta::baked;
use ragu_primitives::{
    Element, GadgetExt as _,
    poseidon::{Sponge, SpongeState},
    vec::FixedVec,
};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use super::{output::OutputHeader, pool::AnchorSpan, spend::SpendHeader};
use crate::{
    ActionSetPoly, TachygramSetPoly,
    constants::MAX_MONEY,
    digest::poseidon,
    entropy::ActionEntropy,
    gadgets::arithmetic as circuit,
    keys::{ProofAuthorizingKey, public::ACTION_AUTH_GENERATOR},
    note::Note,
    primitives::{Anchor, AnchorSetPoly},
    relations::enforce::{
        bind_poly_handle, enforce_poly_product, enforce_poly_roots, poly_handle_limbs,
    },
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

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
        let anchor_element = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.1)),
        )?;
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
        let cm_root = left_encoded.as_gadget().cm.element.clone();
        let pad_root = left_encoded.as_gadget().pad.element.clone();
        let theta = Element::alloc(ctx.dr, &mut (), witness.as_ref().map(|data| data.0.0))?;
        let state = SpongeState::from_elements(FixedVec::from_fn(|index| {
            Element::constant(
                ctx.dr,
                if index == PoseidonFp::RATE {
                    Fp::from_u128(u128::from_le_bytes(*b"Tachyon-Output\0\0"))
                } else {
                    Fp::ZERO
                },
            )
        }));
        let mut sponge = Sponge::resume(state, Pasta::circuit_poseidon(baked()));
        sponge.absorb(ctx.dr, &theta)?;
        sponge.absorb(ctx.dr, &cm_root)?;
        let alpha = sponge.squeeze(ctx.dr)?;
        let alpha_bits = circuit::bits::<D, 255>(ctx.dr, &alpha)?;
        let generator =
            crate::gadgets::point::CurvePoint::constant(ctx.dr, *ACTION_AUTH_GENERATOR)?;
        let rk = crate::gadgets::point::CurvePoint::scale(ctx.dr, &generator, &alpha_bits)?;
        rk.enforce_nonidentity(ctx.dr)?;
        let cv = left_encoded.as_gadget().cv.point.clone();
        let action_root = poseidon::action_digest_circuit(ctx.dr, &[cv.x, cv.y, rk.x, rk.y])?;
        let action_roots = [action_root];
        enforce_poly_roots(
            ctx,
            &action_handle,
            &action_roots,
            "OutputAction: action set does not commit to the action",
        )?;
        let tachygram_roots = [cm_root, pad_root];
        enforce_poly_roots(
            ctx,
            &tachygram_handle,
            &tachygram_roots,
            "OutputAction: tachygram set does not commit to the bound pair",
        )?;
        let output = witness.map(|(_, anchor, action_set, tachygram_set)| {
            (action_set.commit(), tachygram_set.commit(), anchor)
        });
        let fields = crate::stamp::headers::stamp::ActionsOutput {
            anchor: (anchor_element).into(),
            action_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &action_handle)?,
            })
            .into(),
            stamp_tg_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &tachygram_handle)?,
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

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
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
        let ak_assignment = D::try_just(|| {
            let bytes: [u8; 32] = witness.as_ref().take().1.ak.0.into();
            EpAffine::from_bytes(bytes)
                .ok_or_else(|| ragu_core::Error::InvalidWitness("invalid ak encoding".into()))
        })?;
        let ak = crate::gadgets::point::CurvePoint::alloc(ctx.dr, &mut (), ak_assignment)?;
        let nk = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.1.nk)),
        )?;
        let derived_pk = poseidon::payment_key_circuit(ctx.dr, &[ak.x.clone(), ak.y.clone(), nk])?;
        let pk = left_encoded.as_gadget().pk.element.clone();
        pk.enforce_equal(ctx.dr, &derived_pk).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendAction: pak not related to note".into())
        })?;
        let cm = left_encoded.as_gadget().cm.element.clone();
        let theta = Element::alloc(ctx.dr, &mut (), witness.as_ref().map(|data| data.0.0))?;
        let state = SpongeState::from_elements(FixedVec::from_fn(|index| {
            Element::constant(
                ctx.dr,
                if index == PoseidonFp::RATE {
                    Fp::from_u128(u128::from_le_bytes(*b"Tachyon-Spend\0\0\0"))
                } else {
                    Fp::ZERO
                },
            )
        }));
        let mut sponge = Sponge::resume(state, Pasta::circuit_poseidon(baked()));
        sponge.absorb(ctx.dr, &theta)?;
        sponge.absorb(ctx.dr, &cm)?;
        let alpha = sponge.squeeze(ctx.dr)?;
        let alpha_bits = circuit::bits::<D, 255>(ctx.dr, &alpha)?;
        let generator =
            crate::gadgets::point::CurvePoint::constant(ctx.dr, *ACTION_AUTH_GENERATOR)?;
        let randomization =
            crate::gadgets::point::CurvePoint::scale(ctx.dr, &generator, &alpha_bits)?;
        let rk = crate::gadgets::point::CurvePoint::add(ctx.dr, &ak, &randomization)?;
        rk.enforce_nonidentity(ctx.dr)?;
        let cv = left_encoded.as_gadget().cv.point.clone();
        let action_root = poseidon::action_digest_circuit(ctx.dr, &[cv.x, cv.y, rk.x, rk.y])?;
        enforce_poly_roots(
            ctx,
            &action_handle,
            &[action_root],
            "SpendAction: action set does not commit to the action",
        )?;
        let current_root = left_encoded.as_gadget().nf_current.element.clone();
        let next_root = left_encoded.as_gadget().nf_next.element.clone();
        enforce_poly_roots(
            ctx,
            &tachygram_handle,
            &[current_root, next_root],
            "SpendAction: tachygram set does not commit to the nullifier pair",
        )?;
        let output = D::just(|| {
            let (_, _, action_set, tachygram_set) = witness.take();
            (action_set.commit(), tachygram_set.commit(), left.take().3)
        });
        let fields = crate::stamp::headers::stamp::ActionsOutput {
            anchor: (left_encoded.as_gadget().anchor.element.clone()).into(),
            action_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &action_handle)?,
            })
            .into(),
            stamp_tg_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &tachygram_handle)?,
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

/// Transaction assembly and aggregation.
#[derive(Debug)]
pub struct StampMerge;

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
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
        reason = "predicates and connected header wiring stay together"
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
            &left_encoded.as_gadget().action_commit.encoding.limbs,
            "StampMerge: left action accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &left_tachygram_handle,
            &left_encoded.as_gadget().stamp_tg_commit.encoding.limbs,
            "StampMerge: left tachygram accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &right_action_handle,
            &right_encoded.as_gadget().action_commit.encoding.limbs,
            "StampMerge: right action accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &right_tachygram_handle,
            &right_encoded.as_gadget().stamp_tg_commit.encoding.limbs,
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
        let left_anchor_element = left_encoded.as_gadget().anchor.element.clone();
        let right_anchor_element = right_encoded.as_gadget().anchor.element.clone();
        left_anchor_element
            .enforce_equal(ctx.dr, &right_anchor_element)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("StampMerge: anchors must match".into())
            })?;
        let output = D::try_just(|| {
            let (_, (merged_action_set, merged_tachygram_set), _) = witness.take();
            let (_, _, left_anchor) = left.take();
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
        let fields = crate::stamp::headers::stamp::StampOutput {
            anchor: (left_anchor_element).into(),
            action_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &merged_action_handle)?,
            })
            .into(),
            stamp_tg_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &merged_tachygram_handle)?,
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

/// Merges action content.
#[derive(Debug)]
pub struct ActionMerge;

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
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
        reason = "predicates and connected header wiring stay together"
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
            &left_encoded.as_gadget().action_commit.encoding.limbs,
            "ActionMerge: left action accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &left_tachygram_handle,
            &left_encoded.as_gadget().stamp_tg_commit.encoding.limbs,
            "ActionMerge: left tachygram accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &right_action_handle,
            &right_encoded.as_gadget().action_commit.encoding.limbs,
            "ActionMerge: right action accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &right_tachygram_handle,
            &right_encoded.as_gadget().stamp_tg_commit.encoding.limbs,
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
        let left_anchor_element = left_encoded.as_gadget().anchor.element.clone();
        let right_anchor_element = right_encoded.as_gadget().anchor.element.clone();
        left_anchor_element
            .enforce_equal(ctx.dr, &right_anchor_element)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("ActionMerge: anchors must match".into())
            })?;
        let output = D::try_just(|| {
            let (_, (merged_action_set, merged_tachygram_set), _) = witness.take();
            let (_, _, left_anchor) = left.take();
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
        let fields = crate::stamp::headers::stamp::ActionsOutput {
            anchor: (left_anchor_element).into(),
            action_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &merged_action_handle)?,
            })
            .into(),
            stamp_tg_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &merged_tachygram_handle)?,
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

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
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
            &right_encoded.as_gadget().members.encoding.limbs,
            "StampLift: members do not match header",
        )?;
        let anchor = left_encoded.as_gadget().anchor.element.clone();
        let anchor_start = right_encoded.as_gadget().anchor_start.element.clone();
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
            let (stamp_action_commit, stamp_tachygram_commit, _stamp_anchor) = left.take();
            let (_, _, span_anchor_end) = right.take();
            Ok((
                (stamp_action_commit, stamp_tachygram_commit, span_anchor_end),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let fields = crate::stamp::headers::stamp::StampOutput {
            anchor: (right_encoded.as_gadget().anchor_end.element.clone()).into(),
            action_commit: (left_encoded.as_gadget().action_commit.encoding.clone()).into(),
            stamp_tg_commit: (left_encoded.as_gadget().stamp_tg_commit.encoding.clone()).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            data,
            aux,
        ))
    }
}

/// Advances action content's anchor to the end of an [`AnchorSpan`].
///
/// The actions' `anchor` must be the span's `anchor_start` or one of its
/// members.
#[derive(Debug)]
pub struct ActionLift;

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
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
            &right_encoded.as_gadget().members.encoding.limbs,
            "ActionLift: members do not match header",
        )?;
        let anchor = left_encoded.as_gadget().anchor.element.clone();
        let anchor_start = right_encoded.as_gadget().anchor_start.element.clone();
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
            let (actions_action_commit, actions_tachygram_commit, _actions_anchor) = left.take();
            let (_, _, span_anchor_end) = right.take();
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
        let fields = crate::stamp::headers::stamp::ActionsOutput {
            anchor: (right_encoded.as_gadget().anchor_end.element.clone()).into(),
            action_commit: (left_encoded.as_gadget().action_commit.encoding.clone()).into(),
            stamp_tg_commit: (left_encoded.as_gadget().stamp_tg_commit.encoding.clone()).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            data,
            aux,
        ))
    }
}

/// Turns [`Actions`] into a [`Stamp`] by adding the fee digest and fee change
/// note's commitment to the action and tachygram sets.
#[derive(Debug)]
pub struct FeeFuse;

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
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
            &left_encoded.as_gadget().action_commit.encoding.limbs,
            "FeeFuse: left action accumulator must commit to header commit",
        )?;
        bind_poly_handle(
            ctx,
            &left_tachygram_handle,
            &left_encoded.as_gadget().stamp_tg_commit.encoding.limbs,
            "FeeFuse: left tachygram accumulator must commit to header commit",
        )?;
        let maximum = Element::alloc(
            ctx.dr,
            &mut (),
            witness
                .as_ref()
                .map(|data| Fp::from(u64::from(data.0.value))),
        )?;
        circuit::bounded::<D, 51>(ctx.dr, &maximum, MAX_MONEY).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeFuse: maximum fee exceeds MAX_MONEY".into())
        })?;
        let fee = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(u64::from(data.1))),
        )?;
        circuit::bounded::<D, 51>(ctx.dr, &fee, MAX_MONEY)?;
        let change = maximum.sub(ctx.dr, &fee);
        circuit::bounded::<D, 51>(ctx.dr, &change, MAX_MONEY).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeFuse: change is out of range".into())
        })?;
        let pk = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.pk)),
        )?;
        let psi = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.psi)),
        )?;
        let rcm = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.rcm)),
        )?;
        let blind = poseidon::fee_blind_circuit(ctx.dr, &[pk.clone(), psi.clone(), rcm.clone()])?;
        let maximum_bits = circuit::bits::<D, 51>(ctx.dr, &maximum)?;
        let blind_bits = circuit::bits::<D, 255>(ctx.dr, &blind)?;
        let value_generator = crate::gadgets::point::CurvePoint::constant(
            ctx.dr,
            (-*value::VALUE_COMMIT_V).to_affine(),
        )?;
        let blind_generator =
            crate::gadgets::point::CurvePoint::constant(ctx.dr, value::VALUE_COMMIT_R.to_affine())?;
        let value_point =
            crate::gadgets::point::CurvePoint::scale(ctx.dr, &value_generator, &maximum_bits)?;
        let blind_point =
            crate::gadgets::point::CurvePoint::scale(ctx.dr, &blind_generator, &blind_bits)?;
        let cv = crate::gadgets::point::CurvePoint::add(ctx.dr, &value_point, &blind_point)?;
        cv.enforce_nonidentity(ctx.dr)?;
        let fee_digest = poseidon::fee_digest_circuit(ctx.dr, &[cv.x, cv.y, fee])?;
        let fee_change = poseidon::note_commitment_circuit(ctx.dr, &[rcm, pk, change, psi])?;
        fee_change.clone().enforce_nonzero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeFuse: fee change note commitment is zero".into())
        })?;
        enforce_poly_roots(
            ctx,
            &fee_action_handle,
            &[fee_digest],
            "FeeFuse: fee action set does not commit to the fee digest",
        )?;
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
        let output = D::just(|| {
            let (_, _, _, (actions, tachygrams), _) = witness.take();
            (actions.commit(), tachygrams.commit(), left.take().2)
        });
        let fields = crate::stamp::headers::stamp::StampOutput {
            anchor: (left_encoded.as_gadget().anchor.element.clone()).into(),
            action_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &output_action_handle)?,
            })
            .into(),
            stamp_tg_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &output_tachygram_handle)?,
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

/// Proves a zero-action bundle's zero fee.
#[derive(Debug)]
pub struct FeeSeed;

#[expect(
    clippy::pattern_type_mismatch,
    reason = "Maybe projections borrow fixed witness tuples without moving polynomial wrappers"
)]
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
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left)?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
        let anchor_element = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.1)),
        )?;
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
        let maximum = Element::alloc(
            ctx.dr,
            &mut (),
            witness
                .as_ref()
                .map(|data| Fp::from(u64::from(data.0.value))),
        )?;
        maximum.enforce_zero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeSeed: maximum fee must be zero".into())
        })?;
        let pk = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.pk)),
        )?;
        let psi = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.psi)),
        )?;
        let rcm = Element::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Fp::from(data.0.rcm)),
        )?;
        let blind = poseidon::fee_blind_circuit(ctx.dr, &[pk.clone(), psi.clone(), rcm.clone()])?;
        let blind_bits = circuit::bits::<D, 255>(ctx.dr, &blind)?;
        let blind_generator =
            crate::gadgets::point::CurvePoint::constant(ctx.dr, value::VALUE_COMMIT_R.to_affine())?;
        let cv = crate::gadgets::point::CurvePoint::scale(ctx.dr, &blind_generator, &blind_bits)?;
        cv.enforce_nonidentity(ctx.dr)?;
        let zero = Element::constant(ctx.dr, Fp::ZERO);
        let fee_digest = poseidon::fee_digest_circuit(ctx.dr, &[cv.x, cv.y, zero.clone()])?;
        let fee_change = poseidon::note_commitment_circuit(ctx.dr, &[rcm, pk, zero, psi])?;
        fee_change.clone().enforce_nonzero(ctx.dr).map_err(|_err| {
            ragu_core::Error::InvalidWitness("FeeSeed: fee change note commitment is zero".into())
        })?;
        enforce_poly_roots(
            ctx,
            &action_handle,
            &[fee_digest],
            "FeeSeed: fee action set does not commit to the fee digest",
        )?;
        enforce_poly_roots(
            ctx,
            &tachygram_handle,
            &[fee_change],
            "FeeSeed: fee tachygram set does not commit to the fee change note",
        )?;
        let output = witness.map(|(_, anchor, actions, tachygrams)| {
            (actions.commit(), tachygrams.commit(), anchor)
        });
        let fields = crate::stamp::headers::stamp::StampOutput {
            anchor: (anchor_element).into(),
            action_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &action_handle)?,
            })
            .into(),
            stamp_tg_commit: (crate::gadgets::commitment::HostCommitment {
                limbs: poly_handle_limbs(ctx.dr, &tachygram_handle)?,
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

pub use crate::stamp::headers::stamp::{Actions, Stamp};
