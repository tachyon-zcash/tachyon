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
use pasta_curves::{Eq, Fp};
use ragu::{
    Cycle as _, FixedGenerators as _, Header, Index, Pasta, Polynomial, Step, Suffix,
    constraint::{enforce_equal_point, enforce_nonzero, enforce_zero},
};

use super::delegation::NullifierHeader;
use crate::{
    note::{self, Nullifier},
    primitives::{
        Anchor, EpochIndex, NfSeqCommit, NfSeqPoly, TachygramSetCommit, TachygramSetPoly,
    },
    relations::{enforce_poly_concat, enforce_poly_splice},
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
/// An `elapsed` polynomial of one nullifier per crossed epoch boundary over
/// `[start_epoch, present_epoch)`, plus the in-progress tip `present_nf`
/// spliced in when its epoch completes.
#[derive(Clone, Debug)]
pub struct Unspent;

impl Header for Unspent {
    /// `((elapsed, present_epoch), prev_anchor, end_anchor, present_nf,
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

/// An [`Unspent`] bound to a note's genuine `GGM(mk, ·)` leaves by
/// [`VerifyUnspent`], collapsed to boundary scalars.
#[derive(Clone, Debug)]
pub struct VerifiedUnspent;

impl Header for VerifiedUnspent {
    /// `(start_anchor, start_nf, end_anchor, end_nf, cm, epoch)`.
    type Data = (
        Anchor,
        Nullifier,
        Anchor,
        Nullifier,
        note::Commitment,
        EpochIndex,
    );

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 32 + 32 + 4);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
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

    const INDEX: Index = Index::new(4);

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

    const INDEX: Index = Index::new(5);

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

    const INDEX: Index = Index::new(6);

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

/// Per-stamp exclusion seed: verify `nf ∉ stamp_tg_set` and absorb the stamp's
/// commit at `start`, in absolute epoch `epoch` (crosses no boundary).
#[derive(Debug)]
pub struct UnspentSeed;

impl Step for UnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Unspent;
    type Right = ();
    /// `(start, epoch, stamp_tg_set, nf)`.
    type Witness<'source> = (Anchor, EpochIndex, TachygramSetPoly, Nullifier);

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (start, epoch, stamp_tg_set, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Exclusion: nf ∉ set ⇔ the set polynomial is nonzero at nf.
        let nf_point = Fp::from(nf);
        let eval = stamp_tg_set.eval(nf_point);
        ctx.enforce_poly_query(stamp_tg_set.commit().into(), nf_point, eval)?;
        enforce_nonzero(eval, "UnspentSeed: found nullifier in set")?;
        let stamp_commit = stamp_tg_set.commit();
        let end = start.next_stamp(&stamp_commit);
        Ok((
            ((NfSeqCommit::identity(), epoch), start, end, nf, epoch),
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
    /// `(start, epoch, nf)`.
    type Witness<'source> = (Anchor, EpochIndex, Nullifier);

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (start, epoch, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        Ok((
            (
                (NfSeqCommit::identity(), epoch),
                start,
                start.next_empty(),
                nf,
                epoch,
            ),
            (),
        ))
    }
}

/// Extend an [`Unspent`] within its tip epoch.
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

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        ((left_elapsed, left_present_epoch), left_start, left_end, left_pnf, left_epoch): <Self::Left as Header>::Data,
        ((right_elapsed, right_present_epoch), right_start, right_end, right_pnf, right_epoch): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(right_present_epoch) - Fp::from(right_epoch),
            "UnspentFuse: forwards half must stay within one epoch",
        )?;
        enforce_equal_point(
            Eq::from(right_elapsed),
            Eq::from(NfSeqCommit::identity()),
            "UnspentFuse: zero-crossing forwards half must have empty elapsed",
        )?;
        enforce_zero(
            Fp::from(left_pnf) - Fp::from(right_pnf),
            "UnspentFuse: left and right must share the same nf",
        )?;
        enforce_zero(
            Fp::from(left_end) - Fp::from(right_start),
            "UnspentFuse: left.end must equal right.start",
        )?;
        enforce_zero(
            Fp::from(right_epoch) - Fp::from(left_present_epoch),
            "UnspentFuse: forwards half must sit in left's tip epoch",
        )?;
        Ok((
            (
                (left_elapsed, left_present_epoch),
                left_start,
                right_end,
                left_pnf,
                left_epoch,
            ),
            (),
        ))
    }
}

/// Cross-epoch [`Unspent`] composition
///
/// At the boundary left's tip epoch completes `left.end.next_epoch(new_epoch)
/// == right.start` and splices in as `combined = left ++ [left.present_nf] ++
/// right`, with `new_epoch == left.present_epoch + 1`. The only step that grows
/// `elapsed`.
#[derive(Debug)]
pub struct UnspentEpochFuse;

impl Step for UnspentEpochFuse {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = Unspent;
    type Right = Unspent;
    /// `(left_poly, right_poly, combined)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (left_poly, right_poly, combined): Self::Witness<'source>,
        ((left_elapsed, left_present_epoch), left_start, left_end, left_pnf, left_epoch): <Self::Left as Header>::Data,
        ((right_elapsed, right_present_epoch), right_start, right_end, right_pnf, right_epoch): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_equal_point(
            Eq::from(left_poly.commit()),
            Eq::from(left_elapsed),
            "UnspentEpochFuse: left polynomial does not match header",
        )?;
        enforce_equal_point(
            Eq::from(right_poly.commit()),
            Eq::from(right_elapsed),
            "UnspentEpochFuse: right polynomial does not match header",
        )?;
        enforce_zero(
            Fp::from(right_epoch) - Fp::from(left_present_epoch.next()),
            "UnspentEpochFuse: right epoch must be one past left's tip",
        )?;
        enforce_zero(
            Fp::from(left_end.next_epoch(right_epoch)) - Fp::from(right_start),
            "UnspentEpochFuse: boundary anchor does not match right.prev_anchor",
        )?;
        let combined_commit = combined.commit();
        let offset =
            usize::try_from(left_present_epoch.0 - left_epoch.0).map_err(|_too_many_epochs| {
                ragu::Error::InvalidWitness("UnspentEpochFuse: crossing count exceeds usize".into())
            })?;
        enforce_poly_splice(
            ctx,
            &Polynomial::from(left_poly),
            Fp::from(left_pnf),
            &Polynomial::from(right_poly),
            offset,
            &Polynomial::from(combined),
        )
        .map_err(|_relation_err| {
            ragu::Error::InvalidWitness(
                "UnspentEpochFuse: combined is not the splice of the halves".into(),
            )
        })?;
        Ok((
            (
                (combined_commit, right_present_epoch),
                left_start,
                right_end,
                right_pnf,
                left_epoch,
            ),
            (),
        ))
    }
}

/// Bind an [`Unspent`]'s free-witness nullifiers to a
/// note's genuine nullifiers.
///
/// Proves `range == elapsed ++ [present_nf]` against the derived
/// [`NullifierHeader`], emitting a [`VerifiedUnspent`] with the `cm`.
#[derive(Debug)]
pub struct VerifyUnspent;

impl Step for VerifyUnspent {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = VerifiedUnspent;
    type Right = NullifierHeader;
    /// `(elapsed_poly, tip_poly, range_poly)`.
    type Witness<'source> = (NfSeqPoly, NfSeqPoly, NfSeqPoly);

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (elapsed_poly, tip_poly, range_poly): Self::Witness<'source>,
        ((elapsed, present_epoch), prev_anchor, end_anchor, present_nf, start_epoch): <Self::Left as Header>::Data,
        (range_commit, range_start, range_end, cm): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(range_start) - Fp::from(start_epoch),
            "VerifyUnspent: derived range does not start at the elapsed epoch",
        )?;
        enforce_zero(
            Fp::from(range_end) - Fp::from(present_epoch.next()),
            "VerifyUnspent: derived range does not span the crossings plus the tip",
        )?;
        enforce_equal_point(
            Eq::from(elapsed_poly.commit()),
            Eq::from(elapsed),
            "VerifyUnspent: elapsed polynomial does not match header",
        )?;

        let generators = Pasta::host_generators(Pasta::baked()).g();

        #[expect(clippy::expect_used, reason = "constant size")]
        let g0 = generators.first().expect("at least one generator");

        let present_commit = NfSeqCommit::from(g0 * Fp::from(present_nf));
        enforce_equal_point(
            Eq::from(tip_poly.commit()),
            Eq::from(present_commit),
            "VerifyUnspent: tip polynomial does not match present nullifier",
        )?;
        enforce_equal_point(
            Eq::from(range_poly.commit()),
            Eq::from(range_commit),
            "VerifyUnspent: range polynomial does not match header",
        )?;
        let offset =
            usize::try_from(present_epoch.0 - start_epoch.0).map_err(|_too_many_epochs| {
                ragu::Error::InvalidWitness("VerifyUnspent: crossing count exceeds usize".into())
            })?;
        enforce_poly_concat(
            ctx,
            &Polynomial::from(elapsed_poly),
            &Polynomial::from(tip_poly),
            offset,
            &Polynomial::from(range_poly.clone()),
        )
        .map_err(|_relation_err| {
            ragu::Error::InvalidWitness(
                "VerifyUnspent: range is not elapsed followed by the tip".into(),
            )
        })?;
        // `start_nf` is the range's degree-0 coefficient, pinned by opening at zero.
        let start_nf_val = range_poly.eval(Fp::ZERO);
        ctx.enforce_poly_query(range_commit.into(), Fp::ZERO, start_nf_val)?;
        let start_nf = Nullifier::from(start_nf_val);
        Ok((
            (
                prev_anchor,
                start_nf,
                end_anchor,
                present_nf,
                cm,
                present_epoch,
            ),
            (),
        ))
    }
}
