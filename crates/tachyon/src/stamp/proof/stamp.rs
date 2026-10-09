//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use super::{output::OutputHeader, pool::AnchorSpan, spend::SpendHeader};
use crate::{
    ActionSetPoly, TachygramSetPoly,
    entropy::ActionEntropy,
    keys::{ProofAuthorizingKey, private},
    note,
    primitives::{
        ActionDigest, ActionSetCommit, Anchor, AnchorSetPoly, TachygramSetCommit, effect,
    },
    ragu_constraint::{enforce_equal_point, enforce_zero},
    relations::enforce::{enforce_poly_product, enforce_poly_roots},
};

/// Header for a stamp, representing either a single action or many
/// transactions.
///
/// `action_commit` and `stamp_tg_commit` are Pedersen commitments to
/// the action-digest and tachygram sets. Each leaf step
/// ([`OutputStamp`], [`SpendStamp`]) witnesses both set polynomials
/// and enforces them against their roots at a Fiat-Shamir challenge.
/// The action set is enforced against the action the step derives,
/// the tachygram set against the pair bound on the left bind header.
/// [`StampMerge`] binds its witnessed input sets to the child headers
/// and enforces each output commitment as the product of its inputs.
///
/// `anchor` is freely witnessed at [`OutputStamp`]; at [`SpendStamp`]
/// it threads from the left [`SpendHeader`]; at [`StampMerge`]
/// the step constrains `left.anchor == right.anchor`; at
/// [`StampLift`] it advances to the right [`AnchorSpan`]'s `anchor_end`
/// after constraining `stamp.anchor` to the span's start or a member.
#[derive(Debug)]
pub struct Stamp;

impl Header for Stamp {
    /// `(action_commit, stamp_tg_commit, anchor)`
    type Data = (ActionSetCommit, TachygramSetCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        (
            vec![Fp::from(data.2)],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(data.0), Eq::from(data.1)],
        )
    }
}

/// Proves an output's action and publishes its stamp.
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
/// Three permutations (`alpha`, the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set polynomials.
#[derive(Debug)]
pub struct OutputStamp;

impl Step for OutputStamp {
    type Aux<'source> = ();
    type Left = OutputHeader;
    type Output = Stamp;
    type Right = ();
    /// `(theta, anchor, action_set, tachygram_set)`
    type Witness<'source> = (ActionEntropy, Anchor, ActionSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (theta, anchor, action_set, tachygram_set): Self::Witness<'source>,
        (cm, pad, cv): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // TODO: a real circuit squeezes alpha in Fp and needs its bit
        // decomposition to use it as an Fq scalar (p < q, so no reduction);
        // mock ragu embeds it natively.
        let alpha = theta.randomizer::<effect::Output>(note::Commitment::from(Fp::from(cm)));

        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        let action_digest = ActionDigest::new(cv, rk).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "OutputStamp: action digest construction failed".into(),
            )
        })?;

        // The action-set commitment commits to exactly the one action this
        // step derives. `cv` carries the note's value; `rk` derives from
        // `alpha`, and so from `cm`.
        enforce_poly_roots(
            ctx,
            action_set.as_ref(),
            &[Fp::from(action_digest)],
            "OutputStamp: action set does not commit to the action",
        )?;

        // The stamp accumulator commits to exactly the tachygram pair on the
        // bind header, both roots fixed by the recursive verification of the
        // left PCD.
        enforce_poly_roots(
            ctx,
            tachygram_set.as_ref(),
            &[Fp::from(cm), Fp::from(pad)],
            "OutputStamp: tachygram set does not commit to the bound pair",
        )?;

        Ok(((action_set.commit(), tachygram_set.commit(), anchor), ()))
    }
}

/// Proves a spend's action and publishes its stamp.
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
/// Four permutations (`pk`, `alpha`, the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set
/// polynomials.
#[derive(Debug)]
pub struct SpendStamp;

impl Step for SpendStamp {
    type Aux<'source> = ();
    type Left = SpendHeader;
    type Output = Stamp;
    type Right = ();
    /// `(theta, pak, action_set, tachygram_set)`
    type Witness<'source> = (
        ActionEntropy,
        ProofAuthorizingKey,
        ActionSetPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (theta, pak, action_set, tachygram_set): Self::Witness<'source>,
        (cm, nf_current, nf_next, anchor, pk, cv): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(pk) - Fp::from(pak.derive_payment_key()),
            "SpendStamp: pak not related to note",
        )?;

        // TODO: a real circuit squeezes alpha in Fp and needs its bit
        // decomposition to use it as an Fq scalar (p < q, so no reduction);
        // mock ragu embeds it natively.
        let alpha = theta.randomizer::<effect::Spend>(cm);

        let rk = pak.ak.derive_action_public(&alpha);
        let action_digest = ActionDigest::new(cv, rk).map_err(|_err| {
            ragu_core::Error::InvalidWitness("SpendStamp: action digest construction failed".into())
        })?;

        // The action-set commitment commits to exactly the one action this
        // step derives; the root is in-circuit from the certified note.
        enforce_poly_roots(
            ctx,
            action_set.as_ref(),
            &[Fp::from(action_digest)],
            "SpendStamp: action set does not commit to the action",
        )?;

        // The stamp accumulator commits to exactly the nullifier pair on the
        // bind header, both roots fixed by the recursive verification of the
        // left PCD.
        enforce_poly_roots(
            ctx,
            tachygram_set.as_ref(),
            &[Fp::from(nf_current), Fp::from(nf_next)],
            "SpendStamp: tachygram set does not commit to the nullifier pair",
        )?;

        Ok(((action_set.commit(), tachygram_set.commit(), anchor), ()))
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
    /// `(left, merged, right)`, each an `(action_set, tachygram_set)` pair.
    type Witness<'source> = (
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
    );

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (
            (left_action_set, left_tachygram_set),
            (merged_action_set, merged_tachygram_set),
            (right_action_set, right_tachygram_set),
        ): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, left_anchor): <Self::Left as Header>::Data,
        (right_action_commit, right_tachygram_commit, right_anchor): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Same-anchor constraint.
        enforce_zero(
            Fp::from(left_anchor) - Fp::from(right_anchor),
            "StampMerge: anchors must match",
        )?;

        // Bind the witnessed left/right input sets to the public commitments on
        // the headers.
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

        // Confirm union via product-opening relation.
        enforce_poly_product(
            ctx,
            left_action_set.as_ref(),
            right_action_set.as_ref(),
            merged_action_set.as_ref(),
            "StampMerge: merged action set must be the product of left and right action sets",
        )?;
        enforce_poly_product(
            ctx,
            left_tachygram_set.as_ref(),
            right_tachygram_set.as_ref(),
            merged_tachygram_set.as_ref(),
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        )?;

        Ok((
            (
                merged_action_set.commit(),
                merged_tachygram_set.commit(),
                left_anchor,
            ),
            (),
        ))
    }
}

/// Advance a stamp's anchor along an [`AnchorSpan`]: the stamp's `anchor` is
/// the span's `anchor_start` or a member, and the new anchor is the span's
/// `anchor_end`.
///
/// $$
///   M(\mathsf{anchor}) \cdot (\mathsf{anchor} - \mathsf{anchor\_start}) = 0
/// $$
///
/// The target is always `anchor_end`: a root set orders nothing between
/// members. A stamp at `anchor_end` lifts to itself.
///
/// # Soundness
///
/// $M$ is bound to the header by commit-equality, so its opening at the
/// stamp's anchor needs no challenge. An anchor outside the span needs an
/// anchor collision.
#[derive(Debug)]
pub struct StampLift;

impl Step for StampLift {
    type Aux<'source> = ();
    type Left = Stamp;
    type Output = Stamp;
    type Right = AnchorSpan;
    /// `(members)`
    type Witness<'source> = (AnchorSetPoly,);

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (members,): Self::Witness<'source>,
        (stamp_action_commit, stamp_tachygram_commit, stamp_anchor): <Self::Left as Header>::Data,
        (span_anchor_start, span_members, span_anchor_end): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(members.commit()),
            Eq::from(span_members),
            "StampLift: members do not match header",
        )?;

        let anchor_eval = members.eval(Fp::from(stamp_anchor));
        enforce_zero(
            anchor_eval * (Fp::from(stamp_anchor) - Fp::from(span_anchor_start)),
            "StampLift: stamp anchor is neither the span's start nor a member",
        )?;
        ctx.enforce_poly_query(Eq::from(span_members), Fp::from(stamp_anchor), anchor_eval)?;

        let data = (stamp_action_commit, stamp_tachygram_commit, span_anchor_end);
        Ok((data, ()))
    }
}
