//! Spendable bootstrap, lift, and cross-epoch rollover.
//!
//! Bootstrap runs entirely on the user device. The wallet's
//! [`NullifierHeader`] carries `(cm, nf, epoch)`; [`SpendableInitRange`]
//! fuses it with a [`RangeSummary`] that covers the cm-stamp,
//! verifying `cm ∈ range.tg_set` and `nf ∉ range.tg_set`, and emits a
//! [`SpendableHeader`] carrying `(nf, range.end)` — the running anchor
//! at the end of the input range. The cm↔nf binding is structurally
//! inherited through the [`NullifierHeader`] (GGM-bound). Because the
//! range may cover many stamps, the bootstrap checks nf-exclusion the
//! same way every downstream lift does.
//!
//! `start` of the range is freely witnessed at the seed steps; the
//! spendable reaches a real published anchor only by extending through
//! [`SpendableLift`] over [`Unspent`] segments, which by construction
//! prove nf-exclusion at every covered stamp. There is no path that
//! advances a spendable's anchor without a per-stamp nf-check.
//!
//! [`SpendableInitStamp`] is the one-step counterpart for the common
//! case: the wallet seeds a spendable from a single freely-witnessed
//! cm-stamp without first building a [`RangeSummary`]. It omits the
//! nf-exclusion check, sound because a single cm-stamp cannot contain
//! the note's own `nf`.
//!
//! Sync services update spendables via lifts ([`SpendableLift`]) and
//! cross-epoch rollovers ([`SpendableRollover`] →
//! [`SpendableEpochLift`]). [`SpendableRollover`] is the only step that
//! emits the [`Anchor::next_epoch`] boundary domain — it lifts the old
//! epoch's terminal anchor into the new epoch's initial anchor, which
//! the new-epoch [`Unspent`] then extends with ordinary per-stamp
//! advances.

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::{
    delegation::{DelegateNullifierHeader, NullifierHeader},
    pool::RangeSummary,
};
use crate::{
    note::Nullifier,
    primitives::{Anchor, EpochIndex, TachygramSetCommit, TachygramSetGadget},
};

/// Per-nf range exclusion proof.
///
/// `nf` is absent from every stamp covered by the anchor segment from
/// `start` to `end`. Built from a [`RangeSummary`] via
/// [`UnspentFromRange`] and fused with adjacent fragments via
/// [`UnspentFuse`] — fusion spans block boundaries because anchor
/// advances are continuous.
///
/// Same-epoch is structurally guaranteed by GGM-binding of `nf` to one
/// epoch and by the intra-epoch-only `Anchor::next_stamp` advances —
/// crossing an epoch boundary requires matching a boundary anchor that
/// no [`Unspent`] builder ever emits.
///
/// `nf`'s binding closes at the consumer ([`SpendableLift`] checks
/// `unspent.nf == spendable.nf`; the spendable's `nf` is itself bound
/// upstream at [`super::delegation::NullifierHeader`]); `start`'s
/// binding closes through the spendable lineage plus consensus anchor
/// membership.
///
/// `Unspent` is the natural transition point from bounded
/// [`RangeSummary`] segments to unbounded long-range proofs: above the
/// per-step multiset budget the proof carries an `Unspent` (no set)
/// rather than a `RangeSummary` (with set).
#[derive(Clone, Debug)]
pub struct Unspent;

impl Header for Unspent {
    /// `(nf, start, end)`. `nf` roots in a [`UnspentFromRange`] witness,
    /// bound by the consumer ([`SpendableLift`] checks `unspent.nf ==
    /// spendable.nf`, and the spendable's `nf` is GGM-bound upstream).
    /// `start` and `end` are inherited from the consumed [`RangeSummary`].
    type Data<'source> = (Nullifier, Anchor, Anchor);

    const SUFFIX: Suffix = Suffix::new(6);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&Fp::from(data.2).to_repr());
        out
    }
}

/// Per-nf exclusion bridge from a [`RangeSummary`] to an [`Unspent`].
///
/// Witnesses `(nf, tg_gadget)`; binds the gadget to the segment's
/// `tg_set` (so the merged commitment is real), proves `nf ∉ tg_set`
/// via a multiset query, and emits `Unspent { nf, start: range.start,
/// end: range.end }`. The empty-block case is folded in naturally —
/// the empty multiset's `query(x)` is non-zero for every x, so an
/// empty-block summary trivially excludes any nf.
///
/// This is the transition step from bounded [`RangeSummary`] segments
/// (set-bearing, multiset-budget-bounded) to set-free [`Unspent`]
/// segments (composable to arbitrary length via [`UnspentFuse`]).
#[derive(Debug)]
pub struct UnspentFromRange;

impl Step for UnspentFromRange {
    type Aux<'source> = ();
    type Left = RangeSummary;
    type Output = Unspent;
    type Right = ();
    /// `(nf, tg_gadget)`.
    type Witness<'source> = (Nullifier, TachygramSetGadget);

    const INDEX: Index = Index::new(13);

    fn witness<'source>(
        &self,
        (nf, tg_gadget): Self::Witness<'source>,
        (start, end, tg_commit): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if tg_gadget.0.commit() != tg_commit.0 {
            return Err(mock_ragu::Error(
                "UnspentFromRange: witness gadget must commit to range tg_set",
            ));
        }
        // Exclusion: nf ∉ set ⇔ query(nf) != 0.
        if tg_gadget.0.query(Fp::from(nf)) == Fp::ZERO {
            return Err(mock_ragu::Error("UnspentFromRange: found nullifier in set"));
        }
        Ok(((nf, start, end), ()))
    }
}

/// Compose two adjacent [`Unspent`] segments for the same `nf`.
/// Verify same `nf` and `left.end == right.start`.
#[derive(Debug)]
pub struct UnspentFuse;

impl Step for UnspentFuse {
    type Aux<'source> = ();
    type Left = Unspent;
    type Output = Unspent;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_nf, left_start, left_end): <Self::Left as Header>::Data<'source>,
        (right_nf, right_start, right_end): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_nf != right_nf {
            return Err(mock_ragu::Error(
                "UnspentFuse: left and right must share the same nf",
            ));
        }
        if left_end != right_start {
            return Err(mock_ragu::Error(
                "UnspentFuse: left.end must equal right.start",
            ));
        }
        Ok(((left_nf, left_start, right_end), ()))
    }
}

/// Wallet's spendable position. Identified by `nf` alone — `nf` uniquely
/// encodes `(key, epoch)` via GGM determinism, so sync services can update
/// a spendable by `nf` without knowing `delegation_id`.
///
/// `anchor` at [`SpendableInitRange`] is inherited as the `end` of the
/// consumed [`RangeSummary`], but its PCD lineage roots in the
/// freely-witnessed `start` at the [`RangeSummary`] seed steps.
/// Binding closes only through subsequent [`SpendableLift`] steps over
/// [`Unspent`] segments (each `Unspent` proves nf-exclusion at a real
/// stamp), plus consensus anchor membership. There is no path that
/// advances a spendable's anchor without a per-stamp nf-check.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    /// `(nf, anchor)`. `nf` is GGM-bound to `(note, epoch)` upstream
    /// in [`super::delegation::NullifierHeader`]. `anchor` is inherited
    /// at [`SpendableInitRange`] as the `end` of a [`RangeSummary`] whose
    /// `tg_set` contains the note's commitment and excludes the
    /// nullifier, then advanced over [`Unspent`] segments at
    /// [`SpendableLift`] / [`SpendableEpochLift`].
    type Data<'source> = (Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Cross-epoch nf rotation pair.
///
/// `nfs[0]` is the old-epoch `nf`, `nfs[1]` the new-epoch `nf`; the new
/// epoch index is exposed for downstream consumers (specifically
/// [`SpendableRollover`]'s boundary hash). Consecutive epochs are
/// verified at construction.
///
/// Produced by either [`RolloverFuse`] (user device, lineage = `cm`
/// equality) or [`DelegateRolloverFuse`] (sync service, lineage =
/// `delegation_id` equality); the resulting header is identical either
/// way.
#[derive(Clone, Debug)]
pub struct NullifierRolloverHeader;

impl Header for NullifierRolloverHeader {
    /// `(old_nf, new_nf, new_epoch)`. Produced by [`RolloverFuse`]
    /// (user device, lineage by `cm` equality) or
    /// [`DelegateRolloverFuse`] (sync service, lineage by
    /// `delegation_id` equality); both verify consecutive epochs.
    type Data<'source> = (Nullifier, Nullifier, EpochIndex);

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 4);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out.extend_from_slice(&data.2.0.to_le_bytes());
        out
    }
}

/// A spendable rolled forward through an nf rotation, awaiting a
/// new-epoch anchor from [`SpendableEpochLift`].
///
/// Carries `new_nf` (which the new-epoch [`Unspent`] must cover) and
/// `boundary_anchor` (output of [`Anchor::next_epoch`] applied to the
/// old epoch's terminal anchor — i.e., the new epoch's initial
/// anchor). The new-epoch `Unspent`'s `prev_anchor` must equal this
/// boundary anchor. The old-epoch nullifier is dropped: [`SpendableRollover`]
/// has already discharged it against the input spendable's `nf`.
#[derive(Clone, Debug)]
pub struct SpendableRolloverHeader;

impl Header for SpendableRolloverHeader {
    /// `(new_nf, boundary_anchor)`. `boundary_anchor` is computed at
    /// [`SpendableRollover`] via `Anchor::next_epoch` on the
    /// spendable's prior anchor, the only place the `Tachyon-EpochStp`
    /// domain is invoked. The new-epoch [`Unspent`]'s `prev_anchor` is
    /// the only way to discharge it.
    type Data<'source> = (Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Bootstrap a [`SpendableHeader`] from the wallet's [`NullifierHeader`]
/// and a [`RangeSummary`] covering the cm-stamp.
///
/// Witness `(tg_gadget,)` that commits to `range.tg_set`; verifies
/// `cm ∈ range.tg_set` and `nf ∉ range.tg_set`, and emits
/// `(nf, range.end)`.
///
/// The nf-exclusion check matches the one [`SpendableLift`] performs
/// on each downstream `Unspent` — without it, the bootstrap could
/// land past a spend already made within the range.
#[derive(Debug)]
pub struct SpendableInitRange;

impl Step for SpendableInitRange {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableHeader;
    type Right = RangeSummary;
    /// `(tg_gadget,)` — the multiset gadget binding to `range.tg_set`.
    type Witness<'source> = (TachygramSetGadget,);

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        (tg_gadget,): Self::Witness<'source>,
        (cm, nf, _nf_epoch): <Self::Left as Header>::Data<'source>,
        (_start, end, tg_commit): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if tg_gadget.0.commit() != tg_commit.0 {
            return Err(mock_ragu::Error(
                "SpendableInitRange: witness gadget must commit to range tg_set",
            ));
        }
        // Inclusion: cm ∈ set ⇔ query(cm) == 0.
        if tg_gadget.0.query(Fp::from(cm)) != Fp::ZERO {
            return Err(mock_ragu::Error(
                "SpendableInitRange: commitment not in set",
            ));
        }
        // Exclusion: nf ∉ set ⇔ query(nf) != 0. The note must not have
        // already been spent within the range.
        if tg_gadget.0.query(Fp::from(nf)) == Fp::ZERO {
            return Err(mock_ragu::Error(
                "SpendableInitRange: nullifier found in set",
            ));
        }
        Ok(((nf, end), ()))
    }
}

/// Bootstrap a [`SpendableHeader`] directly from the wallet's
/// [`NullifierHeader`] and a single freely-witnessed cm-stamp.
///
/// The one-step counterpart to [`SpendableInitRange`]: where `SpendableInitRange`
/// consumes a [`RangeSummary`] covering the cm-stamp, this step takes
/// the cm-stamp's tachygram set as a bare witness, so the wallet can
/// seed a spendable from its note's creation stamp without first
/// building a [`RangeSummary`] PCD.
///
/// Witness `(pre_cm_anchor, stamp_tg_set)`: verifies `cm ∈ stamp_tg_set`
/// (cm comes from the left header) and emits a [`SpendableHeader`]
/// carrying `(nf, pre_cm_anchor.next_stamp(commit))` — the running
/// anchor immediately after the cm-stamp's absorption (an intra-block
/// state, lifted to a block boundary downstream).
///
/// Field roles: `nf` is threaded from the [`NullifierHeader`] and
/// GGM-bound to `(note, epoch)` upstream; `pre_cm_anchor` and
/// `stamp_tg_set` are freely witnessed; the output anchor is derived in
/// circuit.
///
/// Unlike [`SpendableInitRange`], this step performs **no** nf-exclusion
/// check, and it is sound to omit precisely because the witnessed set
/// is a single cm-stamp:
///
/// - `cm ∈ stamp_tg_set` pins the set to the note's creation stamp (a `cm`
///   appears in exactly one stamp chain-wide).
/// - A note's `nf` cannot appear in its own creation block: a shielded spend
///   references a prior finalized anchor, so a note can never be created and
///   spent in the same block.
/// - `pre_cm_anchor` is freely witnessed; its binding closes only downstream
///   through [`SpendableLift`] over [`Unspent`] segments (each proving
///   per-stamp nf-exclusion) plus consensus anchor membership. A prover who
///   witnesses a multi-stamp union as `stamp_tg_set` produces a `commit` that
///   no real single published stamp matches, so the resulting anchor can never
///   reach a real consensus anchor and the spendable can never be spent.
///
/// That single-block argument is what fails for a [`RangeSummary`] (a
/// range can mint at its start and spend later within the same range),
/// which is why [`SpendableInitRange`] keeps the `nf ∉ tg_set` check.
#[derive(Debug)]
pub struct SpendableInitStamp;

impl Step for SpendableInitStamp {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = SpendableHeader;
    type Right = ();
    /// `(pre_cm_anchor, stamp_tg_set)`.
    type Witness<'source> = (Anchor, TachygramSetGadget);

    const INDEX: Index = Index::new(26);

    fn witness<'source>(
        &self,
        (pre_cm_anchor, stamp_tg_set): Self::Witness<'source>,
        (cm, nf, _nf_epoch): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Inclusion: cm ∈ set ⇔ query(cm) == 0.
        if stamp_tg_set.0.query(Fp::from(cm)) != Fp::ZERO {
            return Err(mock_ragu::Error(
                "SpendableInitStamp: commitment not in set",
            ));
        }
        let stamp_commit = TachygramSetCommit::from(stamp_tg_set);
        Ok(((nf, pre_cm_anchor.next_stamp(&stamp_commit)), ()))
    }
}

/// Advance a [`SpendableHeader`]'s `anchor` along an [`Unspent`]
/// segment whose `prev_anchor` equals the spendable's current anchor.
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(16);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (spendable_nf, spendable_anchor): <Self::Left as Header>::Data<'source>,
        (unspent_nf, unspent_prev_anchor, unspent_end_anchor): <Self::Right as Header>::Data<
            'source,
        >,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if unspent_nf != spendable_nf {
            return Err(mock_ragu::Error(
                "SpendableLift: unspent does not relate to spendable",
            ));
        }
        if unspent_prev_anchor != spendable_anchor {
            return Err(mock_ragu::Error(
                "SpendableLift: unspent not adjacent to spendable",
            ));
        }
        Ok(((spendable_nf, unspent_end_anchor), ()))
    }
}

/// Combine two [`NullifierHeader`]s into a [`NullifierRolloverHeader`] via
/// lineage-bound `cm` equality. **User device.**
#[derive(Debug)]
pub struct RolloverFuse;

impl Step for RolloverFuse {
    type Aux<'source> = ();
    type Left = NullifierHeader;
    type Output = NullifierRolloverHeader;
    type Right = NullifierHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(17);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_cm, left_nf, left_epoch): <Self::Left as Header>::Data<'source>,
        (right_cm, right_nf, right_epoch): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_cm != right_cm {
            return Err(mock_ragu::Error("RolloverFuse: nullifiers not related"));
        }
        if right_epoch.0 != left_epoch.0 + 1 {
            return Err(mock_ragu::Error("RolloverFuse: nullifiers not adjacent"));
        }
        Ok(((left_nf, right_nf, right_epoch), ()))
    }
}

/// Combine two [`DelegateNullifierHeader`]s into a
/// [`NullifierRolloverHeader`] via `delegation_id` equality. **Sync service
/// or user.**
#[derive(Debug)]
pub struct DelegateRolloverFuse;

impl Step for DelegateRolloverFuse {
    type Aux<'source> = ();
    type Left = DelegateNullifierHeader;
    type Output = NullifierRolloverHeader;
    type Right = DelegateNullifierHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_nf, left_epoch, left_delegation_id): <Self::Left as Header>::Data<'source>,
        (right_nf, right_epoch, right_delegation_id): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_delegation_id != right_delegation_id {
            return Err(mock_ragu::Error(
                "DelegateRolloverFuse: nullifiers not related",
            ));
        }
        if right_epoch.0 != left_epoch.0 + 1 {
            return Err(mock_ragu::Error(
                "DelegateRolloverFuse: nullifiers not adjacent",
            ));
        }
        Ok(((left_nf, right_nf, right_epoch), ()))
    }
}

/// Lift a [`SpendableHeader`] across an epoch boundary.
///
/// Checks `spendable.nf == old_nf` from the [`NullifierRolloverHeader`],
/// then applies [`Anchor::next_epoch`] to the spendable's current anchor
/// to produce the new epoch's `boundary_anchor`. Emits `(new_nf,
/// boundary_anchor)` for [`SpendableEpochLift`] to consume against a
/// new-epoch [`Unspent`] whose `prev_anchor` equals this boundary.
///
/// This is the only step in the proof tree that invokes the
/// [`Anchor::next_epoch`] domain. `new_epoch` enters the boundary hash
/// directly, so any tampered value diverges from the published anchor.
#[derive(Debug)]
pub struct SpendableRollover;

impl Step for SpendableRollover {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableRolloverHeader;
    type Right = NullifierRolloverHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(19);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (spendable_nf, spendable_anchor): <Self::Left as Header>::Data<'source>,
        (rollover_old_nf, rollover_new_nf, rollover_new_epoch): <Self::Right as Header>::Data<
            'source,
        >,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if spendable_nf != rollover_old_nf {
            return Err(mock_ragu::Error(
                "SpendableRollover: nullifiers don't match",
            ));
        }
        let boundary_anchor = spendable_anchor.next_epoch(rollover_new_epoch);
        Ok(((rollover_new_nf, boundary_anchor), ()))
    }
}

/// Land a rolled-over spendable on a new-epoch anchor.
///
/// Merges with a new-epoch [`Unspent`] whose `prev_anchor` equals the
/// rollover's `boundary_anchor`. The boundary anchor cryptographically
/// binds `new_epoch` via [`Anchor::next_epoch`], and the new-epoch
/// [`Unspent`] is bound to the wallet's new-epoch identity via
/// `unspent.nf == new_nf` (GGM-bound upstream in the NullifierHeader).
/// Together these pin the wallet to the real E→E+1 epoch transition.
#[derive(Debug)]
pub struct SpendableEpochLift;

impl Step for SpendableEpochLift {
    type Aux<'source> = ();
    type Left = SpendableRolloverHeader;
    type Output = SpendableHeader;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(20);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (rollover_new_nf, rollover_boundary_anchor): <Self::Left as Header>::Data<'source>,
        (unspent_nf, unspent_prev_anchor, unspent_end_anchor): <Self::Right as Header>::Data<
            'source,
        >,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if unspent_nf != rollover_new_nf {
            return Err(mock_ragu::Error(
                "SpendableEpochLift: nullifiers not related",
            ));
        }
        if unspent_prev_anchor != rollover_boundary_anchor {
            return Err(mock_ragu::Error(
                "SpendableEpochLift: unspent prev_anchor must equal rollover boundary_anchor",
            ));
        }
        Ok(((rollover_new_nf, unspent_end_anchor), ()))
    }
}
