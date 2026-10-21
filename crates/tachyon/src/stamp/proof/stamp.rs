//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use alloc::{vec, vec::Vec};

use ff::PrimeField as _;
use pasta_curves::{Ep, EpAffine, Eq, Fp, Fq, arithmetic::CurveAffine as _};
use ragu::{Header, Index, Step, Suffix};

use super::{output::OutputHeader, pool::AnchorSpan, spend::SpendHeader};
use crate::{
    ActionSetPoly, TachygramSetPoly,
    constants::MAX_MONEY,
    digest::poseidon,
    entropy::ActionEntropy,
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    primitives::{
        ActionDigest, ActionSetCommit, Anchor, AnchorSetPoly, TachygramSetCommit, effect,
    },
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
    relations::enforce::{enforce_poly_product, enforce_poly_roots},
    value,
};

/// Non-empty proven action content with no fee in its lineage.
///
/// `action_commit` and `stamp_tg_commit` are Pedersen commitments to
/// the action-digest and tachygram sets. Each leaf step
/// ([`OutputAction`], [`SpendAction`]) witnesses both set polynomials
/// and enforces them against their roots at a Fiat-Shamir challenge.
/// The action set is enforced against the action the step derives,
/// the tachygram set against the pair bound on the left bind header.
/// [`ActionMerge`] binds its witnessed input sets to the child headers
/// and enforces each output commitment as the product of its inputs.
///
/// `anchor` is a free witness at [`OutputAction`]. At [`SpendAction`] it comes
/// from the left [`SpendHeader`]. At [`ActionMerge`] the step requires
/// `left.anchor == right.anchor`. At [`ActionLift`] the step checks that
/// `anchor` is the right [`AnchorSpan`]'s `anchor_start` or a member, and moves
/// it to the span's `anchor_end`.
#[derive(Debug)]
pub struct Actions;

impl Header for Actions {
    /// `(action_commit, stamp_tg_commit, anchor)`
    type Data = (ActionSetCommit, TachygramSetCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(15);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        Stamp::encode(data)
    }
}

/// Header for one or more fee-bearing lineages.
///
/// `action_commit` and `stamp_tg_commit` are Pedersen commitments to
/// the action-digest and tachygram sets.
/// [`StampMerge`] binds its witnessed input sets to the child headers
/// and enforces each output commitment as the product of its inputs.
///
/// [`FeeFuse`] multiplies each set polynomial by a fee singleton set
/// polynomial. [`FeeSeed`] directly produces a stamp with fee singleton sets.
///
/// `anchor` is a free witness at [`FeeSeed`]. At [`FeeFuse`] it comes from
/// the left [`Actions`]. At [`StampMerge`] the step requires
/// `left.anchor == right.anchor`. At [`StampLift`] the step checks that
/// `stamp.anchor` is the right [`AnchorSpan`]'s `anchor_start` or a member,
/// and moves it to the span's `anchor_end`.
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
/// Three permutations (`alpha`, the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set polynomials.
#[derive(Debug)]
pub struct OutputAction;

impl Step for OutputAction {
    type Aux<'source> = ();
    type Left = OutputHeader;
    type Output = Actions;
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
                "OutputAction: action digest construction failed".into(),
            )
        })?;

        // The action-set commitment commits to exactly the one action this
        // step derives. `cv` carries the note's value; `rk` derives from
        // `alpha`, and so from `cm`.
        enforce_poly_roots(
            ctx,
            action_set.as_ref(),
            &[Fp::from(action_digest)],
            "OutputAction: action set does not commit to the action",
        )?;

        // The stamp accumulator commits to exactly the tachygram pair on the
        // bind header, both roots fixed by the recursive verification of the
        // left PCD.
        enforce_poly_roots(
            ctx,
            tachygram_set.as_ref(),
            &[Fp::from(cm), Fp::from(pad)],
            "OutputAction: tachygram set does not commit to the bound pair",
        )?;

        Ok(((action_set.commit(), tachygram_set.commit(), anchor), ()))
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
/// Four permutations (`pk`, `alpha`, the action digest) and one scalar
/// multiplication (`rk`); opens the action-set and tachygram-set
/// polynomials.
#[derive(Debug)]
pub struct SpendAction;

impl Step for SpendAction {
    type Aux<'source> = ();
    type Left = SpendHeader;
    type Output = Actions;
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

        // The action-set commitment commits to exactly the one action this
        // step derives; the root is in-circuit from the certified note.
        enforce_poly_roots(
            ctx,
            action_set.as_ref(),
            &[Fp::from(action_digest)],
            "SpendAction: action set does not commit to the action",
        )?;

        // The stamp accumulator commits to exactly the nullifier pair on the
        // bind header, both roots fixed by the recursive verification of the
        // left PCD.
        enforce_poly_roots(
            ctx,
            tachygram_set.as_ref(),
            &[Fp::from(nf_current), Fp::from(nf_next)],
            "SpendAction: tachygram set does not commit to the nullifier pair",
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

/// Merges action content.
#[derive(Debug)]
pub struct ActionMerge;

impl Step for ActionMerge {
    type Aux<'source> = ();
    type Left = Actions;
    type Output = Actions;
    type Right = Actions;
    /// `(left, merged, right)`, each an `(action_set, tachygram_set)` pair.
    type Witness<'source> = (
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
    );

    const INDEX: Index = Index::new(34);

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
            "ActionMerge: anchors must match",
        )?;

        // Bind the witnessed left/right input sets to the public commitments on
        // the headers.
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

        // Confirm union via product-opening relation.
        enforce_poly_product(
            ctx,
            left_action_set.as_ref(),
            right_action_set.as_ref(),
            merged_action_set.as_ref(),
            "ActionMerge: merged action set must be the product of left and right action sets",
        )?;
        enforce_poly_product(
            ctx,
            left_tachygram_set.as_ref(),
            right_tachygram_set.as_ref(),
            merged_tachygram_set.as_ref(),
            "ActionMerge: merged tachygram set must be the product of left and right tachygram sets",
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
    /// `(members)`
    type Witness<'source> = (AnchorSetPoly,);

    const INDEX: Index = Index::new(35);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (members,): Self::Witness<'source>,
        (actions_action_commit, actions_tachygram_commit, actions_anchor): <Self::Left as Header>::Data,
        (span_anchor_start, span_members, span_anchor_end): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(members.commit()),
            Eq::from(span_members),
            "ActionLift: members do not match header",
        )?;

        let anchor_eval = members.eval(Fp::from(actions_anchor));
        enforce_zero(
            anchor_eval * (Fp::from(actions_anchor) - Fp::from(span_anchor_start)),
            "ActionLift: actions anchor is neither the span's start nor a member",
        )?;
        ctx.enforce_poly_query(
            Eq::from(span_members),
            Fp::from(actions_anchor),
            anchor_eval,
        )?;

        let data = (
            actions_action_commit,
            actions_tachygram_commit,
            span_anchor_end,
        );
        Ok((data, ()))
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
    type Witness<'source> = (
        Note,
        value::Positive,
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
    );

    const INDEX: Index = Index::new(33);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (
            max_fee_note,
            fee,
            (left_action_set, left_tachygram_set),
            (output_action_set, output_tachygram_set),
            (fee_action_set, fee_tachygram_set),
        ): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, left_anchor): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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

        // `maxfee` and `fee` are below 2^64, far below the field modulus, so the
        // field difference lies in [0, MAX_MONEY] exactly when the integer
        // difference does.
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
        let cv_max_fee = value::Trapdoor::from_scalar(
            Option::from(Fq::from_repr(blind.to_repr())).expect("p < q"),
        )
        .commit(-max_fee_note.value);
        let cv_max_fee_coords = EpAffine::from(cv_max_fee)
            .coordinates()
            .into_option()
            .ok_or_else(|| {
                ragu_core::Error::InvalidWitness("FeeFuse: fee commitment is the identity".into())
            })?;
        let fee_digest = poseidon::fee_digest(cv_max_fee_coords, u64::from(fee));

        // A zero root leaves the set polynomial factor `(X - tg)` trivial.
        let fee_change_commitment = enforce_nonzero(
            poseidon::note_commitment(rcm, pk, change, psi),
            "FeeFuse: fee change note commitment is zero",
        )?;

        enforce_poly_roots(
            ctx,
            fee_action_set.as_ref(),
            &[fee_digest],
            "FeeFuse: fee action set does not commit to the fee digest",
        )?;

        enforce_poly_roots(
            ctx,
            fee_tachygram_set.as_ref(),
            &[fee_change_commitment],
            "FeeFuse: fee tachygram set does not commit to the fee change note",
        )?;

        enforce_poly_product(
            ctx,
            left_action_set.as_ref(),
            fee_action_set.as_ref(),
            output_action_set.as_ref(),
            "FeeFuse: output action set must be the product of left and fee action sets",
        )?;
        enforce_poly_product(
            ctx,
            left_tachygram_set.as_ref(),
            fee_tachygram_set.as_ref(),
            output_tachygram_set.as_ref(),
            "FeeFuse: output tachygram set must be the product of left and fee tachygram sets",
        )?;

        Ok((
            (
                output_action_set.commit(),
                output_tachygram_set.commit(),
                left_anchor,
            ),
            (),
        ))
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
    /// `(max_fee_note, anchor, fee_action_set, fee_tachygram_set)`
    type Witness<'source> = (Note, Anchor, ActionSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(36);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (max_fee_note, anchor, fee_action_set, fee_tachygram_set): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
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
        let cv_max_fee = value::Trapdoor::from_scalar(
            Option::from(Fq::from_repr(blind.to_repr())).expect("p < q"),
        )
        .commit(-max_fee_note.value);
        let cv_max_fee_coords = EpAffine::from(cv_max_fee)
            .coordinates()
            .into_option()
            .ok_or_else(|| {
                ragu_core::Error::InvalidWitness("FeeSeed: fee commitment is the identity".into())
            })?;
        let fee_digest = poseidon::fee_digest(cv_max_fee_coords, 0);

        // A zero root leaves the set polynomial factor `(X - tg)` trivial.
        let fee_change_commitment = enforce_nonzero(
            poseidon::note_commitment(rcm, pk, 0, psi),
            "FeeSeed: fee change note commitment is zero",
        )?;

        enforce_poly_roots(
            ctx,
            fee_action_set.as_ref(),
            &[fee_digest],
            "FeeSeed: fee action set does not commit to the fee digest",
        )?;

        enforce_poly_roots(
            ctx,
            fee_tachygram_set.as_ref(),
            &[fee_change_commitment],
            "FeeSeed: fee tachygram set does not commit to the fee change note",
        )?;

        Ok((
            (fee_action_set.commit(), fee_tachygram_set.commit(), anchor),
            (),
        ))
    }
}
