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
//! Sync services update spendables entirely through lifts
//! ([`SpendableLift`]) over [`Unspent`] segments, which may themselves
//! span an epoch boundary: a cross-epoch [`Unspent`] rotates its
//! exclusion nf and applies the [`Anchor::next_epoch`] boundary domain at
//! [`super::pool::UnspentRollover`], so the spendable advances across a
//! boundary in a single ordinary lift.

extern crate alloc;

use alloc::vec::Vec;

use ff::{Field as _, PrimeField as _};
use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::Fp;

use super::{
    delegation::{DelegateNullifierHeader, NullifierHeader},
    pool::Unspent,
};
use crate::{
    note::Nullifier,
    primitives::{Anchor, EpochIndex, TachygramSetCommit, TachygramSetGadget},
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
    /// [`Unspent`] segments at [`SpendableLift`] (a cross-epoch
    /// [`Unspent`] also rotates `nf` across a boundary).
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
/// epoch index is exposed for the downstream consumer
/// ([`super::pool::UnspentRollover`]'s boundary hash). Consecutive epochs
/// are verified at construction.
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
    type Left = NullifierHeader;
    type Output = SpendableHeader;
    type Right = ();
    /// `(pre_cm_anchor, stamp_tg_set)`.
    type Witness<'source> = (Anchor, TachygramSetGadget);

    const INDEX: Index = Index::new(14);

    fn witness<'source>(
        &self,
        (pre_cm_anchor, stamp_tg_set): Self::Witness<'source>,
        (cm, nf, _epoch): <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        // Inclusion: cm ∈ set ⇔ query(cm) == 0.
        if stamp_tg_set.0.query(Fp::from(cm)) != Fp::ZERO {
            return Err(mock_ragu::Error("SpendableInit: commitment not in set"));
        }
        let stamp_commit = TachygramSetCommit::from(stamp_tg_set);
        let post_cm_anchor = pre_cm_anchor.next_stamp(&stamp_commit);
        Ok(((nf, post_cm_anchor), ()))
    }
}

/// Advance a [`SpendableHeader`] along an [`Unspent`] segment whose
/// `start` equals the spendable's current anchor.
///
/// The segment may be intra-epoch (`start_nf == end_nf`) or cross-epoch
/// (the [`Unspent`] rotated `start_nf -> end_nf` at
/// [`super::pool::UnspentRollover`]); either way the spendable adopts the
/// segment's `end_nf` and `end`. The `start_nf == spendable.nf` check is
/// where the [`Unspent`]'s freely-witnessed `start_nf` binds to the
/// GGM-bound spendable nf.
#[derive(Debug)]
pub struct SpendableLift;

impl Step for SpendableLift {
    type Aux<'source> = ();
    type Left = SpendableHeader;
    type Output = SpendableHeader;
    type Right = Unspent;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(15);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (spendable_nf, spendable_anchor): <Self::Left as Header>::Data<'source>,
        (unspent_start_nf, unspent_end_nf, unspent_start, unspent_end): <Self::Right as Header>::Data<
            'source,
        >,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if unspent_start_nf != spendable_nf {
            return Err(mock_ragu::Error(
                "SpendableLift: unspent does not relate to spendable",
            ));
        }
        if unspent_start != spendable_anchor {
            return Err(mock_ragu::Error(
                "SpendableLift: unspent not adjacent to spendable",
            ));
        }
        Ok(((unspent_end_nf, unspent_end), ()))
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

    const INDEX: Index = Index::new(16);

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

    const INDEX: Index = Index::new(17);

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
