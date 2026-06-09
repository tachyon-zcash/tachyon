//! Spendable bootstrap, lift, and cross-epoch rollover.
//!
//! Bootstrap runs entirely on the user device. The wallet's
//! [`NullifierHeader`] carries `(cm, nf, epoch)`; [`SpendableInit`]
//! fuses it with a freely-witnessed `(pre_cm_anchor, stamp_tg_set)`,
//! verifying `cm ∈ stamp_tg_set`, and emits a [`SpendableHeader`]
//! carrying `(nf, post_cm_anchor)` — the running anchor immediately
//! after the cm-stamp's absorption. The cm↔nf binding is structurally
//! inherited through the [`NullifierHeader`] (GGM-bound). The wallet's
//! epoch claim flows through `nf` itself, so no epoch alignment check
//! is needed here.
//!
//! `pre_cm_anchor` is freely witnessed at this step; the spendable
//! reaches a real published anchor only by extending through
//! [`SpendableLift`] over [`Unspent`] segments, which by construction
//! prove nf-exclusion at every covered stamp. There is no path that
//! advances a spendable's anchor without a per-stamp nf-check.
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
use pasta_curves::Fp;
use ragu::{Header, Index, Step, Suffix};

use super::{
    delegation::{DelegateNullifierHeader, NullifierHeader},
    pool::{AnchorChain, Unspent},
};
use crate::{
    note::Nullifier,
    primitives::{Anchor, EpochIndex, TachygramSetPoly},
};

/// Wallet's spendable position. Identified by `nf` alone — `nf` uniquely
/// encodes `(key, epoch)` via GGM determinism, so sync services can update
/// a spendable by `nf` without knowing `delegation_id`.
///
/// `anchor` at [`SpendableInit`] is computed in-circuit as
/// `pre_cm_anchor.next_stamp(stamp_commit)`, but its PCD lineage roots
/// in `SpendableInit`'s unbound `pre_cm_anchor: Anchor` witness.
/// Binding on that witness closes only through subsequent
/// [`SpendableLift`] steps over [`Unspent`] segments (each `Unspent`
/// proves nf-exclusion at a real stamp), plus consensus anchor
/// membership. There is no path that advances a spendable's anchor
/// without a per-stamp nf-check.
#[derive(Clone, Debug)]
pub struct SpendableHeader;

impl Header for SpendableHeader {
    /// `(nf, anchor)`. `nf` is GGM-bound to `(note, epoch)` upstream
    /// in [`super::delegation::NullifierHeader`]. `anchor` is computed
    /// at [`SpendableInit`] as `pre_cm_anchor.next_stamp(stamp_commit)`
    /// over a freely-witnessed `pre_cm_anchor`, then advanced over
    /// [`Unspent`] segments at [`SpendableLift`] /
    /// [`SpendableEpochLift`].
    type Data = (Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(7);

    fn encode(data: &Self::Data) -> Vec<u8> {
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
    type Data = (Nullifier, Nullifier, EpochIndex);

    const SUFFIX: Suffix = Suffix::new(8);

    fn encode(data: &Self::Data) -> Vec<u8> {
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
    type Data = (Nullifier, Anchor);

    const SUFFIX: Suffix = Suffix::new(9);

    fn encode(data: &Self::Data) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32);
        out.extend_from_slice(&Fp::from(data.0).to_repr());
        out.extend_from_slice(&Fp::from(data.1).to_repr());
        out
    }
}

/// Bootstrap a [`SpendableHeader`] from the wallet's [`NullifierHeader`].
///
/// Witness `(pre_cm_anchor, stamp_tg_set)`: verifies `cm ∈ stamp_tg_set`
/// (cm comes from the left header) and emits a [`SpendableHeader`]
/// carrying `(nf, pre_cm_anchor.next_stamp(commit))` — the running
/// anchor immediately after the cm-stamp's absorption.
///
/// `pre_cm_anchor` is freely witnessed; the spendable reaches a real
/// published anchor only by extending through [`SpendableLift`] over
/// [`Unspent`] segments built from real stamps. The cm-block itself
/// cannot contain the wallet's `nf` (`nf` is GGM-bound to `cm`), so no
/// nf-exclusion check is needed at the cm-stamp; the wallet's epoch
/// claim flows through `nf` (GGM-bound at the [`NullifierHeader`]).
#[derive(Debug)]
pub struct SpendableInit;

impl Step for SpendableInit {
    type Aux<'source> = ();
    type Left = AnchorChain;
    type Output = SpendableHeader;
    type Right = NullifierHeader;
    /// `(pre_epoch_anchor, pre_cm_anchor, stamp_tg_set)`. `pre_epoch_anchor` is
    /// the prior epoch's terminal anchor (folded into the boundary);
    /// `pre_cm_anchor` is the anchor immediately before the cm-stamp (the
    /// chain's penultimate state).
    type Witness<'source> = (Anchor, Anchor, TachygramSetPoly);

    const INDEX: Index = Index::new(13);

    fn witness<'source>(
        &self,
        ctx: &mut ragu::StepCtx<'_>,
        (pre_epoch_anchor, pre_cm_anchor, stamp_tg_set): Self::Witness<'source>,
        (chain_start, chain_end): <Self::Left as Header>::Data,
        (cm, nf, epoch): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // Inclusion: cm ∈ set ⇔ the set polynomial vanishes at cm.
        let cm_point = Fp::from(cm);
        let eval = stamp_tg_set.eval(cm_point);
        ctx.enforce_poly_query(stamp_tg_set.commit().into(), cm_point, eval)?;
        if eval != Fp::ZERO {
            return Err(ragu::Error("SpendableInit: commitment not in set"));
        }
        let stamp_commit = stamp_tg_set.commit();

        // Pin the lineage's starting epoch to consensus. The boundary-rooted
        // `AnchorChain` must root at the epoch boundary for the GGM-derived
        // `epoch` (no longer discarded). `next_epoch` (`Tachyon-EpochStp`) is
        // the sole epoch-folding domain and `AnchorChain` is intra-epoch by
        // construction, so once consensus accepts the eventual spend anchor as a
        // real epoch-E published value, collision/preimage resistance forces
        // `epoch == E` (the same pin `SpendableRollover` applies at a crossing).
        if chain_start != pre_epoch_anchor.next_epoch(epoch) {
            return Err(ragu::Error(
                "SpendableInit: chain not rooted at epoch boundary",
            ));
        }

        // The cm-stamp is the chain's final link: `chain_end ==
        // pre_cm_anchor.next_stamp(cm_commit)`. This ties the cm-inclusion to a
        // real, consensus-pinned stamp and yields `post_cm_anchor` as the chain
        // end, so a note created first-in-epoch needs only a single-link chain
        // (`B_E -> B_E.next_stamp(cm)`) with no zero-length segment.
        let post_cm_anchor = pre_cm_anchor.next_stamp(&stamp_commit);
        if chain_end != post_cm_anchor {
            return Err(ragu::Error(
                "SpendableInit: cm-stamp is not the chain's final link",
            ));
        }

        Ok(((nf, post_cm_anchor), ()))
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

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (spendable_nf, spendable_anchor): <Self::Left as Header>::Data,
        (unspent_nf, unspent_prev_anchor, unspent_end_anchor): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if unspent_nf != spendable_nf {
            return Err(ragu::Error(
                "SpendableLift: unspent does not relate to spendable",
            ));
        }
        if unspent_prev_anchor != spendable_anchor {
            return Err(ragu::Error(
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

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (left_cm, left_nf, left_epoch): <Self::Left as Header>::Data,
        (right_cm, right_nf, right_epoch): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if left_cm != right_cm {
            return Err(ragu::Error("RolloverFuse: nullifiers not related"));
        }
        if right_epoch.0 != left_epoch.0 + 1 {
            return Err(ragu::Error("RolloverFuse: nullifiers not adjacent"));
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

    const INDEX: Index = Index::new(16);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (left_nf, left_epoch, left_delegation_id): <Self::Left as Header>::Data,
        (right_nf, right_epoch, right_delegation_id): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if left_delegation_id != right_delegation_id {
            return Err(ragu::Error("DelegateRolloverFuse: nullifiers not related"));
        }
        if right_epoch.0 != left_epoch.0 + 1 {
            return Err(ragu::Error("DelegateRolloverFuse: nullifiers not adjacent"));
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

    const INDEX: Index = Index::new(17);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (spendable_nf, spendable_anchor): <Self::Left as Header>::Data,
        (rollover_old_nf, rollover_new_nf, rollover_new_epoch): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if spendable_nf != rollover_old_nf {
            return Err(ragu::Error("SpendableRollover: nullifiers don't match"));
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

    const INDEX: Index = Index::new(18);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        _witness: Self::Witness<'source>,
        (rollover_new_nf, rollover_boundary_anchor): <Self::Left as Header>::Data,
        (unspent_nf, unspent_prev_anchor, unspent_end_anchor): <Self::Right as Header>::Data,
    ) -> ragu::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        if unspent_nf != rollover_new_nf {
            return Err(ragu::Error("SpendableEpochLift: nullifiers not related"));
        }
        if unspent_prev_anchor != rollover_boundary_anchor {
            return Err(ragu::Error(
                "SpendableEpochLift: unspent prev_anchor must equal rollover boundary_anchor",
            ));
        }
        Ok(((rollover_new_nf, unspent_end_anchor), ()))
    }
}
