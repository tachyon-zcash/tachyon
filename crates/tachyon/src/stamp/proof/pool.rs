//! Anchor-bound primitives over consensus state.
//!
//! Hosts the nf-free anchor segment ([`AnchorChain`]) used by
//! [`super::stamp::StampLift`] to advance a stamp's anchor, and the
//! multi-stamp exclusion proof ([`Unspent`]) used by
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
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::spendable::NullifierRolloverHeader;
use crate::{
    note::Nullifier,
    primitives::{Anchor, TachygramSetCommit, TachygramSetGadget},
};

/// Anchor segment between two endpoints. Composable via [`AnchorFuse`].
///
/// Direction-agnostic: `start` and `end` are both anchors. Consumed only
/// by [`super::stamp::StampLift`] — extending a spendable's anchor must
/// instead go through [`Unspent`] so each step proves nf-exclusion.
///
/// Structurally intra-epoch because only intra-epoch [`Anchor::next_stamp`]
/// is invoked anywhere in the [`AnchorChain`] builders — crossing an
/// epoch boundary requires the [`Anchor::next_epoch`] domain only
/// emitted by [`UnspentRollover`] in the [`Unspent`] lineage.
///
/// The within-epoch property pairs with a consensus-side two-epoch
/// tachygram scan that catches any tachygram already published earlier
/// in the epoch a stamp is lifted across. See the Tachygrams book chapter.
///
/// `start` at the seed steps ([`AnchorSeed`] / [`EmptyBlockSeed`]) has
/// PCD lineage rooted in an unbound `start: Anchor` witness, so a
/// standalone segment proves nothing about real coverage. Final binding
/// closes when [`super::stamp::StampLift`] consumes the segment and the
/// resulting stamp is accepted by consensus (anchor membership).
#[derive(Clone, Debug)]
pub struct AnchorChain;

impl Header for AnchorChain {
    /// `(start, end)`. `start` roots in an unbound witness at [`AnchorSeed`] or
    /// [`EmptyBlockSeed`] and flows to [`super::stamp::StampLift`] which must
    /// ultimately be checked by consensus. `end` is always computed in-circuit
    /// as `start.next_stamp(...)` or `start.next_empty()`.
    type Data<'source> = (Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(5);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Per-nf range exclusion proof, possibly spanning an epoch boundary.
///
/// The covered note's nullifier is absent from every stamp on the anchor
/// segment from `start` to `end`. `start_nf` is the nullifier excluded at
/// `start`'s epoch and `end_nf` at `end`'s epoch; for an intra-epoch
/// segment they are equal, and a segment that crosses one boundary rotates
/// `start_nf = nf_E` to `end_nf = nf_{E+1}` at [`UnspentRollover`]. Built
/// per-stamp at seed and fused with adjacent fragments; fusion spans both
/// block and (via [`UnspentRollover`]) epoch boundaries.
///
/// Within each single-epoch run the nf is GGM-bound to that one epoch and
/// advances run through the intra-epoch-only `Anchor::next_stamp` /
/// `Anchor::next_empty`; the sole cross-epoch transition is
/// [`UnspentRollover`]'s `Anchor::next_epoch`, which rotates the nf using a
/// lineage-bound [`NullifierRolloverHeader`].
///
/// At the seed steps the PCD lineage of `start_nf` and `start` roots in
/// freely-chosen witnesses. `start_nf`'s binding closes at the consumer
/// ([`super::spendable::SpendableLift`] checks `unspent.start_nf ==
/// spendable.nf`; the spendable's `nf` is itself bound upstream at
/// [`super::delegation::NullifierHeader`]); `start`'s binding closes
/// through the spendable lineage plus consensus anchor membership.
#[derive(Clone, Debug)]
pub struct Unspent;

impl Header for Unspent {
    /// `(start_nf, end_nf, start, end)`. `start_nf` is the nf excluded at
    /// `start`'s epoch (roots in a seed witness, bound by the consumer
    /// [`super::spendable::SpendableLift`]); `end_nf` is the nf at
    /// `end`'s epoch (equal to `start_nf` within an epoch, rotated at
    /// [`UnspentRollover`] across a boundary). `start` roots in a seed
    /// witness, bound through the spendable lineage plus consensus anchor
    /// membership. `end` is always computed in-circuit as
    /// `start.next_stamp(...)`, `start.next_empty()`, or
    /// `prev.next_epoch(...)`.
    type Data<'source> = (Nullifier, Nullifier, Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out.extend_from_slice(&Fp::from(data.3).to_repr());
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

    const INDEX: Index = Index::new(7);

    fn witness<'source>(
        &self,
        (start, stamp_commit): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
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

    const INDEX: Index = Index::new(8);

    fn witness<'source>(
        &self,
        (start,): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
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

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_start, left_end): <Self::Left as Header>::Data<'source>,
        (right_start, right_end): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_end != right_start {
            return Err(mock_ragu::Error("AnchorFuse: segments not adjacent"));
        }
        Ok(((left_start, right_end), ()))
    }
}

/// Per-stamp exclusion seed: verify `nf ∉ stamp_tg_set` and absorb the
/// stamp's commit at `start`, producing a one-stamp [`Unspent`].
///
/// `start` is freely witnessed — the seed proves nothing about real
/// coverage on its own. Final binding happens transitively through the
/// spendable lineage plus consensus-side anchor membership.
#[derive(Debug)]
pub struct UnspentSeed;

impl Step for UnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Unspent;
    type Right = ();
    /// `(start, stamp_tg_set, nf)`.
    type Witness<'source> = (Anchor, TachygramSetGadget, Nullifier);

    const INDEX: Index = Index::new(10);

    fn witness<'source>(
        &self,
        (start, stamp_tg_set, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Exclusion: nf ∉ set ⇔ query(nf) != 0.
        if stamp_tg_set.0.query(Fp::from(nf)) == Fp::ZERO {
            return Err(mock_ragu::Error("UnspentSeed: found nullifier in set"));
        }
        let stamp_commit = TachygramSetCommit::from(stamp_tg_set);
        let end = start.next_stamp(&stamp_commit);
        // A single stamp is within one epoch, so start_nf == end_nf.
        Ok(((nf, nf, start, end), ()))
    }
}

/// One-empty-block [`Unspent`] seed for any `nf`. No exclusion check is
/// needed — an empty block contains no stamps, so any nf is trivially
/// absent.
///
/// Witness `(start, nf)`; emit `(nf, start, start.next_empty())`. An
/// attacker can claim any nf at an empty-block segment, but the consumer
/// (`SpendableLift`) checks `unspent.nf == spendable.nf` and the
/// spendable's nf is GGM-bound upstream — so a fake-nf empty segment can
/// only "advance" a non-existent fake spendable.
#[derive(Debug)]
pub struct EmptyBlockUnspentSeed;

impl Step for EmptyBlockUnspentSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = Unspent;
    type Right = ();
    /// `(start, nf)`.
    type Witness<'source> = (Anchor, Nullifier);

    const INDEX: Index = Index::new(11);

    fn witness<'source>(
        &self,
        (start, nf): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // An empty block is within one epoch, so start_nf == end_nf.
        Ok(((nf, nf, start, start.next_empty()), ()))
    }
}

/// Compose two adjacent [`Unspent`] segments.
///
/// Verify nf continuity at the join (`left.end_nf == right.start_nf`,
/// which equates the shared nf within an epoch and chains a rotation
/// across a boundary) and anchor continuity (`left.end == right.start`).
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = Unspent;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(12);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_start_nf, left_end_nf, left_start, left_end): <Self::Left as Header>::Data<'source>,
        (right_start_nf, right_end_nf, right_start, right_end): <Self::Right as Header>::Data<
            'source,
        >,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_end_nf != right_start_nf {
            return Err(mock_ragu::Error(
                "UnspentFuse: left.end_nf must equal right.start_nf",
            ));
        }
        if left_end != right_start {
            return Err(mock_ragu::Error(
                "UnspentFuse: left.end must equal right.start",
            ));
        }
        Ok(((left_start_nf, right_end_nf, left_start, right_end), ()))
    }
}

/// Cross-epoch [`Unspent`] rollover seed: a zero-stamp segment that crosses
/// one epoch boundary, rotating the exclusion nullifier.
///
/// Witnesses the pre-boundary `start` anchor (freely chosen, bound at the
/// consumer like other seeds) and consumes a lineage-bound
/// [`super::spendable::NullifierRolloverHeader`] `(old_nf, new_nf,
/// new_epoch)`. Emits `Unspent(old_nf, new_nf, start,
/// start.next_epoch(new_epoch))`. The segment excludes nothing itself (the
/// boundary link absorbs no stamps); it carries the nf rotation and the
/// sole [`Anchor::next_epoch`] advance in the proof tree. Fuse a
/// prior-epoch segment (ending at `start`, nf `old_nf`) and a new-epoch
/// segment (starting at the boundary, nf `new_nf`) onto it with
/// [`UnspentFuse`]; when the spendable already sits at the epoch-final
/// anchor, the prior-epoch segment is empty and this seed's `start` binds
/// directly to the spendable's anchor at [`super::spendable::SpendableLift`].
///
/// `new_epoch` enters the boundary hash directly; its binding to a real
/// published anchor closes at consensus when the consuming spend's stamp is
/// accepted (anchor membership), exactly as the spendable lineage's anchors
/// do. The rotation's lineage (same note, consecutive epochs) is carried by
/// the [`super::spendable::NullifierRolloverHeader`].
#[derive(Debug)]
pub struct UnspentRollover;

impl Step for UnspentRollover {
    type Aux<'source> = ();
    type Left = NullifierRolloverHeader;
    type Output = Unspent;
    type Right = ();
    /// `(start,)` — the pre-boundary anchor.
    type Witness<'source> = (Anchor,);

    const INDEX: Index = Index::new(13);

    fn witness<'source>(
        &self,
        (start,): Self::Witness<'source>,
        (old_nf, new_nf, new_epoch): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let boundary = start.next_epoch(new_epoch);
        Ok(((old_nf, new_nf, start, boundary), ()))
    }
}
