//! Anchor-bound primitives over consensus state.
//!
//! Hosts the nf-free anchor segment ([`AnchorChain`]) used by
//! [`super::stamp::StampLift`] to advance a stamp's anchor, and the
//! multi-stamp / multi-epoch exclusion proof ([`Unspent`]) used by
//! [`super::spendable::SpendableLift`] to advance a spendable.
//!
//! Anchor advances are single-level: every link absorbs one stamp's
//! tachygram-set commitment into the running [`Anchor`] via
//! [`Anchor::next_stamp`]. There is no per-block hash domain — block
//! alignment is a consensus convention (validators check that anchor
//! endpoints belong to the published per-block anchor sequence).

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use group::{Curve as _, GroupEncoding as _};
use pasta_curves::{Eq, Fp, arithmetic::CurveAffine as _};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Polynomial, Step, Suffix,
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

use crate::{
    NfEmitterPoly,
    constants::{NF_DOMAIN, NF_EMITTERS},
    digest::poseidon,
    note::{self, Nullifier},
    primitives::{
        Anchor, EpochIndex, NfSeqCommit, NfSeqPoly, TachygramSetCommit, TachygramSetPoly,
    },
    relations::{
        enforce::{
            enforce_accumulator_recurrence, enforce_lift_match, enforce_poly_concat,
            enforce_poly_splice, enforce_weight_recurrence,
        },
        quotient::LIFT_SPLITS,
        subgroup_generator,
    },
    stamp::proof::delegation::NullifierDerivation,
};

/// Anchor segment between two endpoints. Composable via [`AnchorFuse`].
///
/// Direction-agnostic: `start` and `end` are both anchors. Two consumers:
/// [`super::stamp::StampLift`] advances a stamp's anchor, and
/// [`super::spendable::SpendableInit`] consumes a boundary-rooted segment (from
/// the epoch boundary through the cm-stamp) to pin a spendable's starting
/// epoch. Extending an *existing* spendable's anchor must instead go through
/// [`Unspent`] so each step proves nf-exclusion.
///
/// Structurally intra-epoch: the builders ([`AnchorSeed`] / [`EmptyBlockSeed`])
/// invoke only [`Anchor::next_stamp`] / [`Anchor::next_empty`]. The
/// [`Anchor::next_epoch`] boundary domain is never a chain link; it is folded
/// at a crossing by [`UnspentEpochFuse`] and checked against a chain's `start`
/// by [`super::spendable::SpendableInit`].
///
/// The within-epoch property pairs with a consensus-side two-epoch
/// tachygram scan that catches any tachygram already published earlier
/// in the epoch a stamp is lifted across. See the Tachygrams book chapter.
///
/// `start` at the seed steps ([`AnchorSeed`] / [`EmptyBlockSeed`]) has
/// PCD lineage rooted in an unbound `start: Anchor` witness, so a
/// standalone segment proves nothing about real coverage. Final binding
/// closes through a consensus-published stamp's anchor membership:
/// [`super::stamp::StampLift`] emits that stamp directly, while a segment
/// consumed by [`super::spendable::SpendableInit`] binds only once the
/// resulting (private) spendable is spent into a stamp.
#[derive(Clone, Debug)]
pub struct AnchorChain;

impl Header for AnchorChain {
    /// `(start, end)`. `start` roots in an unbound witness at [`AnchorSeed`] or
    /// [`EmptyBlockSeed`] and flows to [`super::stamp::StampLift`] which must
    /// ultimately be checked by consensus. `end` is always computed in-circuit
    /// as `start.next_stamp(...)` or `start.next_empty()`.
    type Data = (Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Multi-stamp / multi-epoch nf-exclusion proof
///
/// An `elapsed` polynomial holds one nullifier per crossed epoch boundary over
/// `[epoch_start, epoch_end)`.
///
/// `nf_start` is the range's first tested nullifier (the leaf at `epoch_start`);
/// the in-progress `nf_end` corresponds to `epoch_end` and is folded
/// into `elapsed` when its epoch completes. [`VerifyUnspent`] binds both
/// endpoints to the note's genuine derivation nullifiers.
#[derive(Clone, Debug)]
pub struct Unspent;

impl Header for Unspent {
    /// `(anchor_prev, (epoch_start, nf_start), elapsed,
    /// (epoch_end, nf_end), anchor_last)`.
    type Data = (
        Anchor,
        (EpochIndex, Nullifier),
        NfSeqCommit,
        (EpochIndex, Nullifier),
        Anchor,
    );

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 32 + 32 + 4 + 32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&data.1.0.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.1.1).to_repr());
        let elapsed_bytes: [u8; 32] = Eq::from(data.2).to_affine().to_bytes();
        out.extend_from_slice(&elapsed_bytes);
        out.extend_from_slice(&data.3.0.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.3.1).to_repr());
        out.extend_from_slice(&Fp::from(data.4).to_repr());
        out
    }
}

/// An [`Unspent`] bound to a note's genuine derivation nullifiers by
/// [`VerifyUnspent`], collapsed to boundary scalars.
#[derive(Clone, Debug)]
pub struct VerifiedUnspent;

impl Header for VerifiedUnspent {
    /// `(cm, anchor_prev, (epoch_start, nf_start), (epoch_end, end_nf),
    /// anchor_last, creation_epoch)`. `creation_epoch` is the certified offset
    /// origin `E_0` carried from the derivation;
    /// [`super::spendable::SpendableLift`] reconciles it against the spendable
    /// lineage's `E_0` so the lift's offset arc cannot be shifted.
    /// `epoch_start` and `epoch_end` are the verified range's start and
    /// tip absolute epochs (bound to `nf_start` / `end_nf` by the
    /// lift-match); the lift checks `epoch_start` against the lineage and
    /// advances to `epoch_end`.
    type Data = (
        note::Commitment,
        Anchor,
        (EpochIndex, Nullifier),
        (EpochIndex, Nullifier),
        Anchor,
        EpochIndex,
    );

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 4 + 32 + 4 + 32 + 32 + 4);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&data.2.0.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.2.1).to_repr());
        out.extend_from_slice(&data.3.0.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.3.1).to_repr());
        out.extend_from_slice(&Fp::from(data.4).to_repr());
        out.extend_from_slice(&data.5.0.to_le_bytes());
        out
    }
}

/// Single-stamp [`AnchorChain`] seed. Witness `(start, stamp_commit)`;
/// emit `(start, start.next_stamp(&stamp_commit))`.
///
/// Used for forward extension (consumed by `StampLift`'s span builder).
#[derive(Debug)]
pub struct AnchorSeed;

impl Step for AnchorSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorChain;
    type Right = ();
    /// `(start, stamp_commit)`.
    type Witness<'source> = (Anchor, TachygramSetCommit);

    const INDEX: Index = Index::new(3);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (start, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let end = start.next_stamp(&stamp_commit);
        Ok(((start, end), ()))
    }
}

/// One-empty-block [`AnchorChain`] seed. Witness `(start,)`; emit
/// `(start, start.next_empty())`.
///
/// Advances the anchor through one block that contains zero stamps.
/// Used alongside [`AnchorSeed`] when an anchor segment must traverse
/// a mix of empty and non-empty blocks.
#[derive(Debug)]
pub struct EmptyBlockSeed;

impl Step for EmptyBlockSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = AnchorChain;
    type Right = ();
    /// `(start,)`.
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(4);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (start,): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok(((start, start.next_empty()), ()))
    }
}

/// Compose two adjacent [`AnchorChain`] segments — `left.end ==
/// right.start`.
#[derive(Debug)]
pub struct AnchorFuse;

impl Step for AnchorFuse {
    type Aux<'source> = ();
    type Left = AnchorChain;
    type Output = AnchorChain;
    type Right = AnchorChain;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(5);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (left_start, left_end): <Self::Left as Header>::Data,
        (right_start, right_end): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_end) - Fp::from(right_start),
            "AnchorFuse: segments not adjacent",
        )?;
        Ok(((left_start, right_end), ()))
    }
}

/// Per-stamp exclusion seed.
///
/// Verify `nf ∉ stamp_tg_set` and use the stamp's commit to produce the
/// appropriate anchor. The `elapsed` sequence is empty, since we have not
/// progressed past any nullifiers yet.
#[derive(Debug)]
pub struct UnspentSeed;

impl Step for UnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Unspent;
    type Right = ();
    /// `(anchor_prev, epoch, stamp_tg_set, nf)`.
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetPoly, Nullifier);

    const INDEX: Index = Index::new(6);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, epoch, stamp_tg_set, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Exclusion: nf ∉ set ⇔ the set polynomial is nonzero at nf.
        let nf_point = Fp::from(nf);
        let eval = stamp_tg_set.eval(nf_point);
        ctx.enforce_poly_query(stamp_tg_set.commit().into(), nf_point, eval)?;
        enforce_nonzero(eval, "UnspentSeed: found nullifier in set")?;
        let stamp_commit = stamp_tg_set.commit();
        let tested_anchor = anchor_prev.next_stamp(&stamp_commit);
        Ok((
            (
                anchor_prev,
                (epoch, nf),
                NfSeqCommit::identity(),
                (epoch, nf),
                tested_anchor,
            ),
            (),
        ))
    }
}

/// One-empty-block [`Unspent`] seed: emit a one-block segment that crosses no
/// epoch boundary (an empty block trivially excludes any nf, so no set check).
#[derive(Debug)]
pub struct EmptyBlockUnspentSeed;

impl Step for EmptyBlockUnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Unspent;
    type Right = ();
    /// `(anchor_prev, epoch, nf)`.
    type Witness<'source> = (Anchor, EpochIndex, Nullifier);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (anchor_prev, epoch, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let tested_anchor = anchor_prev.next_empty();
        Ok((
            (
                anchor_prev,
                (epoch, nf),
                NfSeqCommit::identity(),
                (epoch, nf),
                tested_anchor,
            ),
            (),
        ))
    }
}

/// Extend an [`Unspent`] within its tip epoch
///
/// The forwards half crosses no boundary, both halves share the tip
/// `nf_end` at adjacent anchors, and the output keeps `left`'s span while
/// only extending the anchor.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = Unspent;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (
            left_anchor_prev,
            (left_epoch_start, left_nf_start),
            left_elapsed,
            (left_epoch_end, left_nf_end),
            left_anchor_last,
        ): <Self::Left as Header>::Data,
        (
            right_anchor_prev,
            (right_epoch_start, _right_nf_start),
            right_elapsed,
            (right_epoch_end, right_nf_end),
            right_anchor_last,
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(right_epoch_end) - Fp::from(right_epoch_start),
            "UnspentFuse: forwards half must stay within one epoch",
        )?;
        enforce_equal_point(
            Eq::from(right_elapsed),
            Eq::from(NfSeqCommit::identity()),
            "UnspentFuse: zero-crossing forwards half must have empty elapsed",
        )?;
        enforce_zero(
            Fp::from(left_nf_end) - Fp::from(right_nf_end),
            "UnspentFuse: left and right must share the same nf",
        )?;
        enforce_zero(
            Fp::from(left_anchor_last) - Fp::from(right_anchor_prev),
            "UnspentFuse: left.anchor_last must equal right.anchor_prev",
        )?;
        enforce_zero(
            Fp::from(right_epoch_start) - Fp::from(left_epoch_end),
            "UnspentFuse: forwards half must sit in left's tip epoch",
        )?;
        Ok((
            (
                left_anchor_prev,
                (left_epoch_start, left_nf_start),
                left_elapsed,
                (left_epoch_end, left_nf_end),
                right_anchor_last,
            ),
            (),
        ))
    }
}

/// Cross-epoch [`Unspent`] composition. This is the only step that grows
/// `elapsed`.
///
/// At the boundary, left's tip epoch completes
/// (`left.anchor_last.next_epoch(new_epoch) == right.anchor_prev`) and is
/// folded into `elapsed`.
#[derive(Debug)]
pub struct UnspentEpochFuse;

impl Step for UnspentEpochFuse {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = Unspent;
    type Right = Unspent;
    /// `(left_elapsed_poly, right_elapsed_poly,
    /// combined_elapsed_poly)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_elapsed_poly, right_elapsed_poly, combined_elapsed_poly): Self::Witness<'source>,
        (
            left_anchor_prev,
            (left_epoch_start, left_nf_start),
            left_elapsed,
            (left_epoch_end, left_nf_end),
            left_anchor_last,
        ): <Self::Left as Header>::Data,
        (
            right_anchor_prev,
            (right_epoch_start, _right_nf_start),
            right_elapsed,
            (right_epoch_end, right_nf_end),
            right_anchor_last,
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(left_elapsed_poly.commit()),
            Eq::from(left_elapsed),
            "UnspentEpochFuse: left polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(right_elapsed_poly.commit()),
            Eq::from(right_elapsed),
            "UnspentEpochFuse: right polynomial does not match header",
        )?;
        enforce_zero(
            Fp::from(right_epoch_start) - Fp::from(left_epoch_end.next()),
            "UnspentEpochFuse: right epoch must be one past left's tip",
        )?;
        enforce_zero(
            Fp::from(left_anchor_last.next_epoch(right_epoch_start)) - Fp::from(right_anchor_prev),
            "UnspentEpochFuse: boundary anchor does not match right.anchor_prev",
        )?;
        let combined_commit = combined_elapsed_poly.commit();
        let offset = usize::try_from(left_epoch_end.0 - left_epoch_start.0).map_err(
            |_too_many_epochs| {
                ragu::Error::InvalidWitness("UnspentEpochFuse: crossing count exceeds usize".into())
            },
        )?;
        enforce_poly_splice(
            ctx,
            &Polynomial::from(left_elapsed_poly),
            Fp::from(left_nf_end),
            &Polynomial::from(right_elapsed_poly),
            offset,
            &Polynomial::from(combined_elapsed_poly),
        )
        .map_err(|_relation_err| {
            ragu::Error::InvalidWitness(
                "UnspentEpochFuse: combined is not the splice of the halves".into(),
            )
        })?;
        Ok((
            (
                left_anchor_prev,
                (left_epoch_start, left_nf_start),
                combined_commit,
                (right_epoch_end, right_nf_end),
                right_anchor_last,
            ),
            (),
        ))
    }
}

/// Bind an [`Unspent`]'s free-witness nullifiers via the homomorphic range lift
///
/// Reconstructs the sync-tested polynomial `q = elapsed ++ [nf_end]` over
/// `[epoch_start, epoch_end + 1)`, then proves every tested value is the
/// note's genuine derivation nullifier with the running-sum argument: per poly
/// the geometric weight `w_j(p_d) = (rho_j·β)^d`
/// ([`enforce_weight_recurrence`]), the exclusive-prefix accumulator `A(p_d) =
/// Σ_{k<d} β^k·nf_k` ([`enforce_accumulator_recurrence`]), and the
/// offset-indexed match `q(β)·β^{start − E_0} == A(p_{end − E_0}) − A(p_{start
/// − E_0})` ([`enforce_lift_match`]). Emits a [`VerifiedUnspent`] carrying the
/// boundary nullifiers, the `cm`, and the certified offset origin `E_0`.
///
/// The lift challenge `β = Poseidon(derivation_digest, commit(q), start, end)`
/// is derived after `q` is committed, so the prover builds `w_j`/`A` for this
/// `β`; `derivation_digest` binds all `N` certified `commit(T_j)`, and the
/// witnessed `T_j` are bound to those commitments here.
#[derive(Debug)]
pub struct VerifyUnspent;

impl Step for VerifyUnspent {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = VerifiedUnspent;
    type Right = NullifierDerivation;
    /// `(elapsed_poly, tip_poly, range_poly, trace_polys, weights, accumulator,
    /// weight_quotients, accumulator_quotient)`: the `q`-reconstruction polys,
    /// the `N` derivation polys `T_j`, the `N` geometric weights `w_j`
    /// (each [`LIFT_SPLITS`] splits), the accumulator `A` (`LIFT_SPLITS`
    /// splits), the `N` weight recurrence quotients, and the accumulator
    /// recurrence quotient.
    type Witness<'source> = (
        NfSeqPoly,
        NfSeqPoly,
        NfSeqPoly,
        [NfEmitterPoly; NF_EMITTERS],
        [[Polynomial; LIFT_SPLITS]; NF_EMITTERS],
        [Polynomial; LIFT_SPLITS],
        [Polynomial; NF_EMITTERS],
        Polynomial,
    );

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (
            elapsed_poly,
            tip_poly,
            range_poly,
            polys,
            weights,
            accumulator,
            weight_quotients,
            accumulator_quotient,
        ): Self::Witness<'source>,
        (
            unspent_anchor_prev,
            (unspent_epoch_start, unspent_nf_start),
            unspent_elapsed,
            (unspent_epoch_end, unspent_nf_end),
            unspent_anchor_last,
        ): <Self::Left as Header>::Data,
        (commits, digest, cm, creation_epoch, shift, ratios): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Reconstruct the tested-value polynomial q = elapsed ++ [nf_end].
        enforce_equal_point(
            Eq::from(elapsed_poly.commit()),
            Eq::from(unspent_elapsed),
            "VerifyUnspent: elapsed polynomial does not match header",
        )?;
        let host_generators = Pasta::host_generators(Pasta::baked()).g();
        let g0 = host_generators.first().ok_or(ragu::Error::InvalidWitness(
            "VerifyUnspent: missing host generator".into(),
        ))?;
        let present_commit = NfSeqCommit::from(g0 * Fp::from(unspent_nf_end));
        enforce_equal_point(
            Eq::from(tip_poly.commit()),
            Eq::from(present_commit),
            "VerifyUnspent: tip polynomial does not match present nullifier",
        )?;
        let range_commit = range_poly.commit();
        let offset = usize::try_from(unspent_epoch_end.0 - unspent_epoch_start.0).map_err(
            |_too_many_epochs| {
                ragu::Error::InvalidWitness("VerifyUnspent: crossing count exceeds usize".into())
            },
        )?;
        let range = Polynomial::from(range_poly);
        enforce_poly_concat(
            ctx,
            &Polynomial::from(elapsed_poly),
            &Polynomial::from(tip_poly),
            offset,
            &range,
        )
        .map_err(|_relation_err| {
            ragu::Error::InvalidWitness(
                "VerifyUnspent: range is not elapsed followed by the tip".into(),
            )
        })?;

        // Bind each witnessed T_j to its certified derivation commitment.
        for (trace, commit) in polys.iter().zip(&commits) {
            enforce_equal_point(
                trace.0.commit(),
                commit.0,
                "VerifyUnspent: derivation polynomial does not match the certified commitment",
            )?;
        }

        // Lift challenge β over the certified digest, the tested q, and the range.
        let end_epoch = unspent_epoch_end.next();
        let range_coords = Eq::from(range_commit)
            .to_affine()
            .coordinates()
            .expect("range commitment is not identity");
        let beta = poseidon::lift_challenge(digest.0, range_coords, unspent_epoch_start, end_epoch);
        let coset_gen = subgroup_generator::<NF_DOMAIN>();

        // Per-poly geometric weight w_j(p_d) = (ρ_j·β)^d.
        for (weight, (ratio, quotient)) in
            weights.iter().zip(ratios.0.iter().zip(&weight_quotients))
        {
            enforce_weight_recurrence::<NF_DOMAIN, LIFT_SPLITS>(
                ctx,
                weight,
                quotient,
                ratio * beta,
                shift.0,
            )?;
        }

        // Exclusive-prefix accumulator A(p_d) = Σ_{k<d} β^k·nf_k.
        enforce_accumulator_recurrence::<NF_DOMAIN, LIFT_SPLITS, NF_EMITTERS>(
            ctx,
            &accumulator,
            &accumulator_quotient,
            &weights,
            &polys.map(|poly| poly.0),
            shift.0,
        )?;

        // Offset-indexed range match against the certified origin E_0.
        let start_offset = u64::from(unspent_epoch_start.0 - creation_epoch.0);
        let end_offset = u64::from(end_epoch.0 - creation_epoch.0);
        enforce_lift_match::<LIFT_SPLITS>(
            ctx,
            &accumulator,
            &range,
            range_commit.into(),
            shift.0,
            coset_gen,
            beta,
            start_offset,
            end_offset,
        )?;

        // nf_start is q's degree-0 coefficient (the tested value at epoch_start).
        let nf_start_val = range.eval(Fp::ZERO);
        ctx.enforce_poly_query(range_commit.into(), Fp::ZERO, nf_start_val)?;
        // Bind the Unspent's carried nf_start to the genuine range-start leaf,
        // mirroring the tip binding above (`nf_end`).
        enforce_zero(
            Fp::from(unspent_nf_start) - nf_start_val,
            "VerifyUnspent: header nf_start does not match the verified range start",
        )?;
        let nf_start = Nullifier::from(nf_start_val);

        Ok((
            (
                cm,
                unspent_anchor_prev,
                (unspent_epoch_start, nf_start),
                (unspent_epoch_end, unspent_nf_end),
                unspent_anchor_last,
                creation_epoch,
            ),
            (),
        ))
    }
}
