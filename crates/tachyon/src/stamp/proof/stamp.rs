//! Stamp header and stamp-producing/transforming steps.

extern crate alloc;

use alloc::{vec, vec::Vec};

use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Step, Suffix,
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

use crate::{
    ActionSetPoly, NfEmitterSpectrum, TachygramSetPoly,
    constants::{NF_DOMAIN, NF_EMITTERS, NOTE_VALUE_MAX},
    entropy::ActionRandomizer,
    keys::private,
    note::Note,
    primitives::{ActionDigest, ActionSetCommit, Anchor, TachygramSetCommit, effect},
    relations::enforce::{enforce_geometric_opening_pair, enforce_poly_product},
    stamp::proof::{delegation::NullifierDerivation, pool::AnchorChain, spend::SpendHeader},
    value,
};

/// Header for a stamp, representing either a single action or many
/// transactions.
///
/// `action_commit` and `stamp_tg_commit` are Pedersen commitments to
/// the action-digest and tachygram sets. Each producing step computes
/// them from the actions and tachygrams the step witnesses.
///
/// `anchor` is freely witnessed at [`OutputStamp`]; at [`SpendStamp`]
/// it threads from the left [`SpendHeader`]; at [`MergeStamp`]
/// the step constrains `left.anchor == right.anchor`; at
/// [`StampLift`] it advances to the right [`AnchorChain`] segment's
/// `end` after constraining `segment.start == old_anchor`.
#[derive(Debug)]
pub struct StampHeader;

impl Header for StampHeader {
    /// `(action_commit, stamp_tg_commit, anchor)`. The two commitments
    /// are computed at each producing step from the actions and
    /// tachygrams that step witnesses. `anchor` is freely witnessed at
    /// [`OutputStamp`], threaded from the left [`SpendHeader`] at
    /// [`SpendStamp`], equality-constrained at [`MergeStamp`], or
    /// advanced over an [`AnchorChain`] at [`StampLift`].
    type Data = (ActionSetCommit, TachygramSetCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(11);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        (
            vec![Fp::from(data.2)],
            Vec::new(),
            Vec::new(),
            vec![Eq::from(data.0), Eq::from(data.1)],
        )
    }
}

/// Derives commitment, proves action, stamps an output.
#[derive(Debug)]
pub struct OutputStamp;

impl Step for OutputStamp {
    type Aux<'source> = ();
    type Left = ();
    type Output = StampHeader;
    type Right = ();
    /// `(rcv, alpha, note, anchor)`.
    type Witness<'source> = (
        value::CommitmentTrapdoor,
        ActionRandomizer<effect::Output>,
        Note,
        Anchor,
    );

    const INDEX: Index = Index::new(13);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (rcv, alpha, note, anchor): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        #[expect(clippy::expect_used, reason = "constant size")]
        let &[g0, g1] = Pasta::host_generators(Pasta::baked())
            .g()
            .split_first_chunk::<2>()
            .expect("at least two generators")
            .0;

        enforce_nonzero(
            Fp::from(u64::from(note.value)),
            "OutputStamp: zero-value note",
        )?;
        if u64::from(note.value) > NOTE_VALUE_MAX {
            return Err(ragu::Error::InvalidWitness(
                "OutputStamp: note value exceeds maximum".into(),
            ));
        }
        let cv = rcv.commit(-i64::from(note.value));
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        let action_digest = ActionDigest::new(cv, rk).map_err(|_err| {
            ragu::Error::InvalidWitness("OutputStamp: action digest construction failed".into())
        })?;

        // Set commitment to one action.
        let action_commit = {
            let a0 = Fp::from(action_digest);
            ActionSetCommit::from(g0 * (-a0) + g1)
        };

        // Set commitment to one note commitment.
        let tachygram_commit = {
            let t0 = Fp::from(note.commitment());
            TachygramSetCommit::from(g0 * (-t0) + g1)
        };

        Ok(((action_commit, tachygram_commit, anchor), ()))
    }
}

/// Composes a [`SpendHeader`] with the note's certified
/// [`NullifierDerivation`] and stamps the spend.
///
/// Witnesses the `N` derivation polynomials, reads the threaded spend offset
/// `d = present_epoch − E_0` from the [`SpendHeader`] (the difference of two
/// anchor-bound lineage epochs, derived at
/// [`SpendBind`](super::spend::SpendBind), range-limited to the query coset by
/// the relation), computes the nullifier pair `(nf_d, nf_{d+1})` off the
/// certified derivation at consecutive coset points, checks `nf_d` against the
/// lineage's `present_nf` (an additional consistency bind on the threaded
/// offset), and publishes both nullifiers as the spend's tachygrams.
#[derive(Debug)]
pub struct SpendStamp;

impl Step for SpendStamp {
    type Aux<'source> = ();
    type Left = SpendHeader;
    type Output = StampHeader;
    type Right = NullifierDerivation;
    /// `(emitters,)`.
    type Witness<'source> = ([NfEmitterSpectrum; NF_EMITTERS],);

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (emitters,): Self::Witness<'source>,
        (cm, (cv, rk), present_nf, anchor, offset): <Self::Left as Header>::Data,
        (emitter_commits, _digest, derivation_cm, shift, ratios): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // The certified derivation must be this note's.
        enforce_zero(
            Fp::from(derivation_cm) - Fp::from(cm),
            "SpendStamp: derivation does not certify the note",
        )?;

        // Offset query: the present-epoch nullifier `nf_d` and its successor
        // `nf_{d+1}`, read off the certified polys at consecutive coset points
        // with the cm-bound shift and ratios. The offset is a threaded header
        // value (lineage-bound at SpendBind) and range-limited to the query
        // coset by the relation.
        let (nf_now, nf_next) = enforce_geometric_opening_pair::<NF_EMITTERS, NF_DOMAIN>(
            ctx,
            &emitter_commits.map(|commit| commit.0),
            &emitters.map(|poly| poly.0),
            shift.0,
            &ratios.0,
            u64::from(offset),
        )?;

        // Continuity: the present-epoch query must equal the lineage tip, an
        // additional consistency bind on the already-threaded offset.
        enforce_zero(
            nf_now - Fp::from(present_nf),
            "SpendStamp: query does not match the lineage nullifier",
        )?;

        enforce_nonzero(nf_now, "SpendStamp: present-epoch nullifier is zero")?;
        enforce_nonzero(nf_next, "SpendStamp: next-epoch nullifier is zero")?;

        let action_digest = ActionDigest::new(cv, rk).map_err(|_err| {
            ragu::Error::InvalidWitness("SpendStamp: action digest construction failed".into())
        })?;

        // Homomorphic set commitments (a step cannot construct a polynomial):
        // the singleton action set {ad} = (X - ad) = [-ad, 1]; the tachygram
        // pair {t0, t1} = (X - t0)(X - t1) = [t0·t1, -(t0+t1), 1]. These
        // reproduce `…SetPoly::from(slice).commit()` without an in-step
        // `from_roots`.
        #[expect(clippy::expect_used, reason = "constant size")]
        let &[g0, g1, g2] = Pasta::host_generators(Pasta::baked())
            .g()
            .split_first_chunk::<3>()
            .expect("at least three generators")
            .0;

        // Set commitment to one action.
        let action_commit = {
            let a0 = Fp::from(action_digest);
            ActionSetCommit::from(g0 * (-a0) + g1)
        };

        // Set commitment to two nullifiers.
        let tachygram_commit = {
            let (t0, t1) = (nf_now, nf_next);
            TachygramSetCommit::from(g0 * (t0 * t1) + g1 * (-(t0 + t1)) + g2)
        };

        Ok(((action_commit, tachygram_commit, anchor), ()))
    }
}

/// Universal merge — transaction assembly and aggregation.
#[derive(Debug)]
pub struct MergeStamp;

impl Step for MergeStamp {
    type Aux<'source> = ();
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = StampHeader;
    /// `(left, merged, right)`, each an `(action_set, tachygram_set)` pair.
    type Witness<'source> = (
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
        (ActionSetPoly, TachygramSetPoly),
    );

    const INDEX: Index = Index::new(16);

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
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Same-anchor constraint.
        enforce_zero(
            Fp::from(left_anchor) - Fp::from(right_anchor),
            "MergeStamp: anchors must match",
        )?;

        // Bind the witnessed left/right input sets to the public commitments on
        // the headers.
        enforce_equal_point(
            Eq::from(left_action_set.commit()),
            Eq::from(left_action_commit),
            "MergeStamp: left action accumulator must commit to header commit",
        )?;
        enforce_equal_point(
            Eq::from(right_action_set.commit()),
            Eq::from(right_action_commit),
            "MergeStamp: right action accumulator must commit to header commit",
        )?;
        enforce_equal_point(
            Eq::from(left_tachygram_set.commit()),
            Eq::from(left_tachygram_commit),
            "MergeStamp: left tachygram accumulator must commit to header commit",
        )?;
        enforce_equal_point(
            Eq::from(right_tachygram_set.commit()),
            Eq::from(right_tachygram_commit),
            "MergeStamp: right tachygram accumulator must commit to header commit",
        )?;

        let merged_action_set_commit = merged_action_set.commit();
        let merged_tachygram_set_commit = merged_tachygram_set.commit();

        // The merged sets are witnessed; confirm each is the `left · right`
        // union of its halves via the product-opening relation, never built
        // in-step.
        enforce_poly_product(
            ctx,
            &left_action_set.into(),
            &right_action_set.into(),
            &merged_action_set.into(),
        )?;
        enforce_poly_product(
            ctx,
            &left_tachygram_set.into(),
            &right_tachygram_set.into(),
            &merged_tachygram_set.into(),
        )?;

        Ok((
            (
                merged_action_set_commit,
                merged_tachygram_set_commit,
                left_anchor,
            ),
            (),
        ))
    }
}

/// Advance a stamp's anchor by absorbing an [`AnchorChain`]: the
/// segment's `start` must equal the stamp's `old_anchor`, and the new
/// anchor is the segment's `end`.
#[derive(Debug)]
pub struct StampLift;

impl Step for StampLift {
    type Aux<'source> = ();
    type Left = StampHeader;
    type Output = StampHeader;
    type Right = AnchorChain;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(17);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (): Self::Witness<'source>,
        (left_action_commit, left_tachygram_commit, old_anchor): <Self::Left as Header>::Data,
        (segment_start, segment_end): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // The anchor segment must root at the stamp's old anchor.
        enforce_zero(
            Fp::from(segment_start) - Fp::from(old_anchor),
            "StampLift: segment start must equal stamp old_anchor",
        )?;

        let data = (left_action_commit, left_tachygram_commit, segment_end);
        Ok((data, ()))
    }
}
