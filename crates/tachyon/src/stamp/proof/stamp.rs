//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use super::{delegation::NoteMaster, pool::AnchorChain, spend::SpendHeader};
use crate::{
    ActionSetPoly, Tachygram, TachygramSetPoly,
    constants::MAX_MONEY,
    digest::poseidon,
    entropy::ActionRandomizer,
    keys::{ProofAuthorizingKey, private},
    note::Note,
    primitives::{ActionDigest, ActionSetCommit, Anchor, TachygramSetCommit, effect},
    ragu_constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
    relations::enforce::{enforce_poly_product, enforce_poly_roots},
    value,
};

/// Header for a stamp, representing either a single action or many
/// transactions.
///
/// `action_commit` and `stamp_tg_commit` are Pedersen commitments to
/// the action-digest and tachygram sets. Each leaf step
/// ([`OutputAction`], [`SpendAction`]) witnesses both set polynomials
/// and enforces them against their roots at a Fiat-Shamir challenge.
/// The action set is enforced against the action the step derives,
/// the tachygram set against the pair bound on the left bind header.
/// [`StampMerge`] binds its witnessed input sets to the child headers
/// and enforces each output commitment as the product of its inputs.
///
/// `anchor` is freely witnessed at [`OutputAction`]; at [`SpendAction`]
/// it threads from the left [`SpendHeader`]; at [`StampMerge`]
/// the step constrains `left.anchor == right.anchor`; at
/// [`StampLift`] it advances to the right [`AnchorChain`] path's
/// `anchor_last` after constraining `chain.anchor_first == stamp.anchor`.
#[derive(Debug)]
pub struct Stamp;

impl Header for Stamp {
    /// `(action_commit, stamp_tg_commit, anchor)`
    type Data = (ActionSetCommit, TachygramSetCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(7);

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
/// A seed: the sender holds no `pak` for the recipient's note, so nothing
/// upstream can certify it. The step witnesses the note, derives its
/// tachygram pair `{cm, pad}` under two domains, derives the value commitment
/// `cv` and the randomized action key `rk`, and enforces the one-action set
/// plus the stamp accumulator over the pair.
///
/// Deriving the pair here rather than on a preceding bind header is what
/// makes the commitment a single hash: a bind would compute `cm` and this
/// step would recompute it to bind the note against it.
#[derive(Debug)]
pub struct OutputAction;

impl Step for OutputAction {
    type Aux<'source> = ();
    type Left = ();
    type Output = Stamp;
    type Right = ();
    /// `(rcv, alpha, note, anchor, action_set, tachygram_set)`.
    type Witness<'source> = (
        value::Trapdoor,
        ActionRandomizer<effect::Output>,
        Note,
        Anchor,
        ActionSetPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (rcv, alpha, note, anchor, action_set, tachygram_set): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if u64::from(note.value) > MAX_MONEY {
            return Err(ragu_core::Error::InvalidWitness(
                "OutputAction: note value exceeds maximum".into(),
            ));
        }

        let (rcm, pk, value, psi) = (
            Fp::from(note.rcm),
            Fp::from(note.pk),
            u64::from(note.value),
            Fp::from(note.psi),
        );
        let cm = Tachygram::from(poseidon::note_commitment(rcm, pk, value, psi));
        let pad = Tachygram::from(poseidon::pad_tachygram(rcm, pk, value, psi));

        // Two zero tachygrams collide whatever they were meant to be, and a
        // zero root leaves the accumulator factor `(X - tg)` trivial.
        enforce_nonzero(Fp::from(cm), "OutputAction: note commitment is zero")?;
        enforce_nonzero(Fp::from(pad), "OutputAction: padding tachygram is zero")?;

        let cv = rcv.commit(-note.value);
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        let action_digest = ActionDigest::new(cv, rk).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "OutputAction: action digest construction failed".into(),
            )
        })?;

        // The action-set commitment commits to exactly the one action this
        // step derives. `cv` carries the note's value; `rk` derives from
        // `alpha` alone.
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

/// Proves a spend's action and publishes its stamp.
///
/// Focused on the action: the spent note arrives already certified on the
/// right [`NoteMaster`], so the step binds it to the [`SpendHeader`] by one
/// field equality rather than recomputing the commitment. It derives the
/// value commitment `cv` and the randomized action key `rk`, and enforces the
/// one-action set plus the stamp accumulator over the two-element tachygram
/// set `{nf_current, nf_next}` (the pair
/// [`SpendBind`](super::spend::SpendBind) already confirmed against the
/// covering derivation).
///
/// `pak.derive_payment_key()` still runs: `pk = payment_key(ak, nk)` is the
/// only thing tying `ak`, and so `rk`, to the note.
#[derive(Debug)]
pub struct SpendAction;

impl Step for SpendAction {
    type Aux<'source> = ();
    type Left = SpendHeader;
    type Output = Stamp;
    type Right = NoteMaster;
    /// `(rcv, alpha, pak, action_set, tachygram_set)`
    type Witness<'source> = (
        value::Trapdoor,
        ActionRandomizer<effect::Spend>,
        ProofAuthorizingKey,
        ActionSetPoly,
        TachygramSetPoly,
    );

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (rcv, alpha, pak, action_set, tachygram_set): Self::Witness<'source>,
        (cm, nf_current, nf_next, anchor): <Self::Left as Header>::Data,
        (master_cm, note, _mk): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if u64::from(note.value) > MAX_MONEY {
            return Err(ragu_core::Error::InvalidWitness(
                "SpendAction: note value exceeds maximum".into(),
            ));
        }
        enforce_zero(
            Fp::from(note.pk) - Fp::from(pak.derive_payment_key()),
            "SpendAction: pak not related to note",
        )?;
        enforce_zero(
            Fp::from(master_cm) - Fp::from(cm),
            "SpendAction: note does not match the spend",
        )?;

        let cv = rcv.commit(note.value);
        let rk = pak.ak.derive_action_public(&alpha);
        let action_digest = ActionDigest::new(cv, rk).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "SpendAction: action digest construction failed".into(),
            )
        })?;

        // The action-set commitment commits to exactly the one action this
        // step derives; the root is in-circuit from the witnessed note above.
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

    const INDEX: Index = Index::new(13);

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

/// Advance a stamp's anchor by absorbing an [`AnchorChain`]: the path's
/// `anchor_first` must equal the stamp's `anchor`, and the new anchor is the
/// path's `anchor_last`.
#[derive(Debug)]
pub struct StampLift;

impl Step for StampLift {
    type Aux<'source> = ();
    type Left = Stamp;
    type Output = Stamp;
    type Right = AnchorChain;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, stamp_anchor): <Self::Left as Header>::Data,
        (chain_anchor_first, chain_anchor_last): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // The path must start at the position the stamp already holds.
        enforce_zero(
            Fp::from(chain_anchor_first) - Fp::from(stamp_anchor),
            "StampLift: chain's first anchor must equal stamp anchor",
        )?;

        let data = (left_action_commit, left_tachygram_commit, chain_anchor_last);
        Ok((data, ()))
    }
}
