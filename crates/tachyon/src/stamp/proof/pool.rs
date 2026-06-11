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
/// `[start_epoch, present_epoch)`.
///
/// The in-progress `present_nf` corresponds to `present_epoch`. It will be
/// folded into `elapsed` when its epoch completes.
#[derive(Clone, Debug)]
pub struct Unspent;

impl Header for Unspent {
    /// `((elapsed, present_epoch), prev_anchor, last_anchor, present_nf,
    /// start_epoch)`.
    type Data = (
        (NfSeqCommit, EpochIndex),
        Anchor,
        Anchor,
        Nullifier,
        EpochIndex,
    );

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + 32 + 32 + 32 + 4);
        let elapsed_bytes: [u8; 32] = Eq::from(data.0.0).to_affine().to_bytes();
        out.extend_from_slice(&elapsed_bytes);
        out.extend_from_slice(&data.0.1.0.to_le_bytes());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
        out.extend_from_slice(&data.4.0.to_le_bytes());
        out
    }
}

/// An [`Unspent`] bound to a note's genuine derivation nullifiers by
/// [`VerifyUnspent`], collapsed to boundary scalars.
#[derive(Clone, Debug)]
pub struct VerifiedUnspent;

impl Header for VerifiedUnspent {
    /// `(prev_anchor, start_nf, last_anchor, end_nf, cm, creation_epoch,
    /// start_epoch, present_epoch)`. `creation_epoch` is the certified offset
    /// origin `E_0` carried from the derivation;
    /// [`super::spendable::SpendableLift`] reconciles it against the spendable
    /// lineage's `E_0` so the lift's offset arc cannot be shifted.
    /// `start_epoch` and `present_epoch` are the verified range's start and
    /// tip absolute epochs (bound to `start_nf` / `end_nf` by the
    /// lift-match); the lift checks `start_epoch` against the lineage and
    /// advances to `present_epoch`.
    type Data = (
        Anchor,
        Nullifier,
        Anchor,
        Nullifier,
        note::Commitment,
        EpochIndex,
        EpochIndex,
        EpochIndex,
    );

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 32 + 32 + 4 + 4 + 4);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
        out.extend_from_slice(&Fp::from(data.4).to_repr());
        out.extend_from_slice(&data.5.0.to_le_bytes());
        out.extend_from_slice(&data.6.0.to_le_bytes());
        out.extend_from_slice(&data.7.0.to_le_bytes());
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
    /// `(prev_anchor, epoch, stamp_tg_set, nf)`.
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetPoly, Nullifier);

    const INDEX: Index = Index::new(6);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (prev_anchor, epoch, stamp_tg_set, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Exclusion: nf ∉ set ⇔ the set polynomial is nonzero at nf.
        let nf_point = Fp::from(nf);
        let eval = stamp_tg_set.eval(nf_point);
        ctx.enforce_poly_query(stamp_tg_set.commit().into(), nf_point, eval)?;
        enforce_nonzero(eval, "UnspentSeed: found nullifier in set")?;
        let stamp_commit = stamp_tg_set.commit();
        let tested_anchor = prev_anchor.next_stamp(&stamp_commit);
        Ok((
            (
                (NfSeqCommit::identity(), epoch),
                prev_anchor,
                tested_anchor,
                nf,
                epoch,
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
    /// `(prev_anchor, epoch, nf)`.
    type Witness<'source> = (Anchor, EpochIndex, Nullifier);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (prev_anchor, epoch, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let tested_anchor = prev_anchor.next_empty();
        Ok((
            (
                (NfSeqCommit::identity(), epoch),
                prev_anchor,
                tested_anchor,
                nf,
                epoch,
            ),
            (),
        ))
    }
}

/// Extend an [`Unspent`] within its tip epoch
///
/// The forwards half crosses no boundary, both halves share the tip
/// `present_nf` at adjacent anchors, and the output keeps `left`'s span while
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
            (left_elapsed, left_present_epoch),
            left_prev_anchor,
            left_last_anchor,
            left_present_nf,
            left_start_epoch,
        ): <Self::Left as Header>::Data,
        (
            (right_elapsed, right_present_epoch),
            right_prev_anchor,
            right_last_anchor,
            right_present_nf,
            right_start_epoch,
        ): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(right_present_epoch) - Fp::from(right_start_epoch),
            "UnspentFuse: forwards half must stay within one epoch",
        )?;
        enforce_equal_point(
            Eq::from(right_elapsed),
            Eq::from(NfSeqCommit::identity()),
            "UnspentFuse: zero-crossing forwards half must have empty elapsed",
        )?;
        enforce_zero(
            Fp::from(left_present_nf) - Fp::from(right_present_nf),
            "UnspentFuse: left and right must share the same nf",
        )?;
        enforce_zero(
            Fp::from(left_last_anchor) - Fp::from(right_prev_anchor),
            "UnspentFuse: left.last_anchor must equal right.prev_anchor",
        )?;
        enforce_zero(
            Fp::from(right_start_epoch) - Fp::from(left_present_epoch),
            "UnspentFuse: forwards half must sit in left's tip epoch",
        )?;
        Ok((
            (
                (left_elapsed, left_present_epoch),
                left_prev_anchor,
                right_last_anchor,
                left_present_nf,
                left_start_epoch,
            ),
            (),
        ))
    }
}

/// Cross-epoch [`Unspent`] composition. This is the only step that grows
/// `elapsed`.
///
/// At the boundary, left's tip epoch completes
/// (`left.last_anchor.next_epoch(new_epoch) == right.prev_anchor`) and is
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
            (left_elapsed, left_present_epoch),
            left_prev_anchor,
            left_last_anchor,
            left_present_nf,
            left_start_epoch,
        ): <Self::Left as Header>::Data,
        (
            (right_elapsed, right_present_epoch),
            right_prev_anchor,
            right_last_anchor,
            right_present_nf,
            right_start_epoch,
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
            Fp::from(right_start_epoch) - Fp::from(left_present_epoch.next()),
            "UnspentEpochFuse: right epoch must be one past left's tip",
        )?;
        enforce_zero(
            Fp::from(left_last_anchor.next_epoch(right_start_epoch)) - Fp::from(right_prev_anchor),
            "UnspentEpochFuse: boundary anchor does not match right.prev_anchor",
        )?;
        let combined_commit = combined_elapsed_poly.commit();
        let offset = usize::try_from(left_present_epoch.0 - left_start_epoch.0).map_err(
            |_too_many_epochs| {
                ragu::Error::InvalidWitness("UnspentEpochFuse: crossing count exceeds usize".into())
            },
        )?;
        enforce_poly_splice(
            ctx,
            &Polynomial::from(left_elapsed_poly),
            Fp::from(left_present_nf),
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
                (combined_commit, right_present_epoch),
                left_prev_anchor,
                right_last_anchor,
                right_present_nf,
                left_start_epoch,
            ),
            (),
        ))
    }
}

/// Bind an [`Unspent`]'s free-witness nullifiers via the homomorphic range lift
///
/// Reconstructs the sync-tested polynomial `q = elapsed ++ [present_nf]` over
/// `[start_epoch, present_epoch + 1)`, then proves every tested value is the
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
            (unspent_elapsed, unspent_present_epoch),
            unspent_prev_anchor,
            unspent_last_anchor,
            unspent_present_nf,
            unspent_start_epoch,
        ): <Self::Left as Header>::Data,
        (commits, digest, cm, creation_epoch, shift, ratios): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Reconstruct the tested-value polynomial q = elapsed ++ [present_nf].
        enforce_equal_point(
            Eq::from(elapsed_poly.commit()),
            Eq::from(unspent_elapsed),
            "VerifyUnspent: elapsed polynomial does not match header",
        )?;
        let host_generators = Pasta::host_generators(Pasta::baked()).g();
        let g0 = host_generators.first().ok_or(ragu::Error::InvalidWitness(
            "VerifyUnspent: missing host generator".into(),
        ))?;
        let present_commit = NfSeqCommit::from(g0 * Fp::from(unspent_present_nf));
        enforce_equal_point(
            Eq::from(tip_poly.commit()),
            Eq::from(present_commit),
            "VerifyUnspent: tip polynomial does not match present nullifier",
        )?;
        let range_commit = range_poly.commit();
        let offset = usize::try_from(unspent_present_epoch.0 - unspent_start_epoch.0).map_err(
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
        let end_epoch = unspent_present_epoch.next();
        let range_coords = Eq::from(range_commit)
            .to_affine()
            .coordinates()
            .expect("range commitment is not identity");
        let beta = poseidon::lift_challenge(digest.0, range_coords, unspent_start_epoch, end_epoch);
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
        let start_offset = u64::from(unspent_start_epoch.0 - creation_epoch.0);
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

        // start_nf is q's degree-0 coefficient (the tested value at start_epoch).
        let start_nf_val = range.eval(Fp::ZERO);
        ctx.enforce_poly_query(range_commit.into(), Fp::ZERO, start_nf_val)?;
        let start_nf = Nullifier::from(start_nf_val);

        Ok((
            (
                unspent_prev_anchor,
                start_nf,
                unspent_last_anchor,
                unspent_present_nf,
                cm,
                creation_epoch,
                unspent_start_epoch,
                unspent_present_epoch,
            ),
            (),
        ))
    }
}
