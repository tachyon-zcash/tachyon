//! Utilities for preparing step witnesses.
//!
//! One function per [`Step`] with a non-empty witness: it assembles the step's
//! [`Witness`](ragu::Step::Witness) tuple from raw inputs (interpolating
//! nullifiers and tachygrams into the polynomials the step opens against),
//! ready to seed or fuse through `PROOF_SYSTEM`. Functions are named after the
//! step they serve. Steps with an empty `()` witness need no utility.

use alloc::vec::Vec;

use ragu::{Header, Step};

use crate::{
    note::Nullifier,
    primitives::{
        ActionDigest, ActionSetPoly, Anchor, EpochIndex, NfSeqPoly, Tachygram, TachygramSetPoly,
    },
    stamp::proof::{
        delegation::NullifierFuse,
        pool::{AnchorSeed, UnspentEpochFuse, UnspentSeed, VerifyUnspent},
        spendable::SpendableInit,
        stamp::MergeStamp,
    },
};

type StepLeft<S> = <<S as Step>::Left as Header>::Data;

type StepRight<S> = <<S as Step>::Right as Header>::Data;

type StepWitness<'src, S> = <S as Step>::Witness<'src>;

/// Prepare the witness for [`NullifierFuse`]: `(left, merged, leaf)`.
#[must_use]
pub fn nullifier_fuse(
    (_left, _right): (StepLeft<NullifierFuse>, StepRight<NullifierFuse>),
    left: &[Nullifier],
    leaf: Nullifier,
) -> StepWitness<'static, NullifierFuse> {
    let mut merged: Vec<Nullifier> = left.to_vec();
    merged.push(leaf);
    (
        left.iter().copied().collect::<NfSeqPoly>(),
        merged.into_iter().collect::<NfSeqPoly>(),
        NfSeqPoly::from_iter([leaf]),
    )
}

/// Prepare the witness for [`UnspentSeed`]: `(anchor_prev, (epoch, nf),
/// tg_set)`.
#[must_use]
pub fn unspent_seed(
    (_left, _right): (StepLeft<UnspentSeed>, StepRight<UnspentSeed>),
    anchor_prev: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
    nf: Nullifier,
) -> StepWitness<'static, UnspentSeed> {
    (
        anchor_prev,
        (epoch, nf),
        tgs.iter().copied().collect::<TachygramSetPoly>(),
    )
}

/// Prepare the witness for [`UnspentEpochFuse`]:
/// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
#[must_use]
pub fn unspent_epoch_fuse(
    (left, _right): (StepLeft<UnspentEpochFuse>, StepRight<UnspentEpochFuse>),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentEpochFuse> {
    let (_, _, _, (_, nf_end), _) = left;
    let mut combined: Vec<Nullifier> = left_elapsed.to_vec();
    combined.push(nf_end);
    combined.extend_from_slice(right_elapsed);
    (
        left_elapsed.iter().copied().collect::<NfSeqPoly>(),
        combined.into_iter().collect::<NfSeqPoly>(),
        right_elapsed.iter().copied().collect::<NfSeqPoly>(),
    )
}

/// Prepare the witness for [`VerifyUnspent`]: `(elapsed, nf_seq)`.
///
/// The range appends the tip `nf_end` from the left
/// [`Unspent`](crate::stamp::proof::pool::Unspent) header:
/// `nf_seq = elapsed ++ [nf_end]`.
#[must_use]
pub fn verify_unspent(
    (left, _right): (StepLeft<VerifyUnspent>, StepRight<VerifyUnspent>),
    elapsed: &[Nullifier],
) -> StepWitness<'static, VerifyUnspent> {
    let (_, _, _, (_, nf_end), _) = left;
    let mut nf_seq: Vec<Nullifier> = elapsed.to_vec();
    nf_seq.push(nf_end);
    (
        elapsed.iter().copied().collect::<NfSeqPoly>(),
        nf_seq.into_iter().collect::<NfSeqPoly>(),
    )
}

/// Prepare the witness for [`SpendableInit`]:
/// `((pre_epoch_anchor, pre_cm_anchor), creation_set, present_nf)`.
#[must_use]
pub fn spendable_init(
    (_left, _right): (StepLeft<SpendableInit>, StepRight<SpendableInit>),
    pre_epoch_anchor: Anchor,
    pre_cm_anchor: Anchor,
    creation_tgs: &[Tachygram],
    present_nf: Nullifier,
) -> StepWitness<'static, SpendableInit> {
    (
        (pre_epoch_anchor, pre_cm_anchor),
        creation_tgs.iter().copied().collect::<TachygramSetPoly>(),
        present_nf,
    )
}

/// Prepare the witness for [`AnchorSeed`]: `(start, stamp_commit)`.
#[must_use]
pub fn anchor_seed(
    (_left, _right): (StepLeft<AnchorSeed>, StepRight<AnchorSeed>),
    start: Anchor,
    tgs: &[Tachygram],
) -> StepWitness<'static, AnchorSeed> {
    (
        start,
        tgs.iter().copied().collect::<TachygramSetPoly>().commit(),
    )
}

/// Prepare the witness for [`MergeStamp`]: `((left_action_set, left_tg_set),
/// (merged_action_set, merged_tg_set), (right_action_set, right_tg_set))`.
#[must_use]
pub fn merge_stamp(
    (_left, _right): (StepLeft<MergeStamp>, StepRight<MergeStamp>),
    left_actions: &[ActionDigest],
    left_tgs: &[Tachygram],
    right_actions: &[ActionDigest],
    right_tgs: &[Tachygram],
) -> StepWitness<'static, MergeStamp> {
    let merged_action_set = left_actions
        .iter()
        .copied()
        .chain(right_actions.iter().copied())
        .collect::<ActionSetPoly>();
    let merged_tg_set = left_tgs
        .iter()
        .copied()
        .chain(right_tgs.iter().copied())
        .collect::<TachygramSetPoly>();
    (
        (
            left_actions.iter().copied().collect::<ActionSetPoly>(),
            left_tgs.iter().copied().collect::<TachygramSetPoly>(),
        ),
        (merged_action_set, merged_tg_set),
        (
            right_actions.iter().copied().collect::<ActionSetPoly>(),
            right_tgs.iter().copied().collect::<TachygramSetPoly>(),
        ),
    )
}
