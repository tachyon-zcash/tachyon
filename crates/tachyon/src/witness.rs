//! Utilities for preparing step witnesses.
//!
//! One function per [`Step`] with a non-empty witness: it assembles the step's
//! [`Witness`](Step::Witness) tuple from raw inputs (interpolating
//! nullifiers and tachygrams into the polynomials the step opens against),
//! ready to seed or fuse through `PROOF_SYSTEM`. Functions are named after the
//! step they serve. Steps with an empty `()` witness need no utility.

use ragu::{Header, Step};

use crate::{
    digest::poseidon::NF_GROUP,
    keys::ProofAuthorizingKey,
    note::Note,
    nullifier::Nullifier,
    primitives::{
        ActionDigest, ActionSetPoly, Anchor, EpochIndex, NfMarginPoly, NfSeqPoly, NfTailPoly,
        Tachygram, TachygramSetPoly,
    },
    stamp::proof::{
        delegation::{NfDerive, NfMasterSeed, NullifierFuse},
        pool::{AnchorSeed, EndEpochUnspentSeed, UnspentBind, UnspentFuse, UnspentSeed},
        spend::SpendBind,
        spendable::SpendableInit,
        stamp::MergeStamp,
    },
};

type StepLeft<S> = <<S as Step>::Left as Header>::Data;

type StepRight<S> = <<S as Step>::Right as Header>::Data;

type StepWitness<'src, S> = <S as Step>::Witness<'src>;

/// Prepare the witness for [`NfMasterSeed`]: `(note, pak)`.
#[must_use]
pub const fn nf_master_seed(
    (_left, _right): (StepLeft<NfMasterSeed>, StepRight<NfMasterSeed>),
    note: Note,
    pak: ProofAuthorizingKey,
) -> StepWitness<'static, NfMasterSeed> {
    (note, pak)
}

/// Prepare the witness for [`NfDerive`]:
/// `(group_base, epoch_start, epoch_end, seq)`.
///
/// Reads `mk` off the seed header, derives the window covering `epoch_start`,
/// and lays the requested `[epoch_start, epoch_end)` sub-range out as the
/// sequence. The range must fit inside the covering window; a longer span
/// fuses ranges via [`NullifierFuse`].
#[must_use]
pub fn nf_derive(
    (left, _right): (StepLeft<NfDerive>, StepRight<NfDerive>),
    epoch_start: EpochIndex,
    epoch_end: EpochIndex,
) -> StepWitness<'static, NfDerive> {
    let (_cm, mk) = left;
    let group_base = covering_group(epoch_start);
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "the group width is a small constant"
    )]
    let base = group_base * NF_GROUP as u32;
    #[expect(
        clippy::indexing_slicing,
        clippy::as_conversions,
        reason = "the caller requests a range inside the covering window"
    )]
    let seq = mk.derive_window(group_base)
        [(epoch_start.0 - base) as usize..(epoch_end.0 - base) as usize]
        .iter()
        .copied()
        .collect::<NfSeqPoly>();
    (group_base, epoch_start, epoch_end, seq)
}

/// The group base of the window covering `epoch`.
///
/// Windows are group-aligned, so a covering window starts at the epoch's own
/// group and runs `NF_DERIVATION_WIDTH` epochs from there.
#[must_use]
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "the group width is a small constant, and flooring to the \
              containing group is the intended index"
)]
pub const fn covering_group(epoch: EpochIndex) -> u32 {
    epoch.0 / NF_GROUP as u32
}

/// Prepare the witness for [`NullifierFuse`]:
/// `(left_seq, merged_seq, right_seq)`.
#[must_use]
pub fn nullifier_fuse(
    (_left, _right): (StepLeft<NullifierFuse>, StepRight<NullifierFuse>),
    left_nfs: &[Nullifier],
    right_nfs: &[Nullifier],
) -> StepWitness<'static, NullifierFuse> {
    let merged = [left_nfs, right_nfs].concat();
    (
        left_nfs.iter().copied().collect::<NfSeqPoly>(),
        merged.into_iter().collect::<NfSeqPoly>(),
        right_nfs.iter().copied().collect::<NfSeqPoly>(),
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

/// Prepare the witness for [`EndEpochUnspentSeed`]:
/// `(anchor_prev, (epoch_prev, nf_prev), nf)`.
#[must_use]
pub const fn end_epoch_unspent_seed(
    (_left, _right): (
        StepLeft<EndEpochUnspentSeed>,
        StepRight<EndEpochUnspentSeed>,
    ),
    anchor_prev: Anchor,
    epoch_prev: EpochIndex,
    nf_prev: Nullifier,
    nf: Nullifier,
) -> StepWitness<'static, EndEpochUnspentSeed> {
    (anchor_prev, (epoch_prev, nf_prev), nf)
}

/// Prepare the witness for [`UnspentFuse`]:
/// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
///
/// `left_elapsed` and `right_elapsed` are the halves' member lists, one per
/// covered epoch. Both include the junction epoch's member, which the
/// combined sequence keeps once.
#[must_use]
pub fn unspent_fuse(
    (_left, _right): (StepLeft<UnspentFuse>, StepRight<UnspentFuse>),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentFuse> {
    #[expect(clippy::expect_used, reason = "member lists are nonempty")]
    let (_junction, right_tail) = right_elapsed
        .split_first()
        .expect("right members include the junction");
    let combined = [left_elapsed, right_tail].concat();
    (
        left_elapsed.iter().copied().collect::<NfSeqPoly>(),
        combined.into_iter().collect::<NfSeqPoly>(),
        right_elapsed.iter().copied().collect::<NfSeqPoly>(),
    )
}

/// Prepare the witness for [`UnspentBind`]: `(elapsed_seq, g, older, tail)`.
///
/// `elapsed` is the unspent's member list, one per covered epoch. `window`
/// is the complete covering sequence, one member per epoch of the
/// derivation header's range; the read of the unspent's span and its
/// margins are segmented from it.
#[must_use]
#[expect(
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "the window covers the derivation header's range"
)]
pub fn unspent_bind(
    (unspent, deriv): (StepLeft<UnspentBind>, StepRight<UnspentBind>),
    window: &[Nullifier],
    elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentBind> {
    let (_, (epoch_start, _), _, (epoch_last, _), _) = unspent;
    let (_, (deriv_start, _), ..) = deriv;
    let lo = (epoch_start.0 - deriv_start.0) as usize;
    let hi = (epoch_last.next().0 - deriv_start.0) as usize;
    (
        elapsed.iter().copied().collect::<NfSeqPoly>(),
        window.iter().copied().collect::<NfSeqPoly>(),
        NfMarginPoly::new(&window[..lo]),
        NfTailPoly::new(&window[hi..]),
    )
}

/// Prepare the witness for [`SpendableInit`]:
/// `(pre_cm_anchor, creation_set, creation_epoch, present_nf, g, older,
/// tail)`.
///
/// `window` is the complete covering sequence, one member per epoch of the
/// derivation header's range; the 1-wide read at `creation_epoch` and its
/// margins are segmented from it, `present_nf` the member the read forces.
#[must_use]
#[expect(
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "the window covers the derivation header's range"
)]
pub fn spendable_init(
    (deriv, _right): (StepLeft<SpendableInit>, StepRight<SpendableInit>),
    pre_cm_anchor: Anchor,
    creation_tgs: &[Tachygram],
    creation_epoch: EpochIndex,
    window: &[Nullifier],
) -> StepWitness<'static, SpendableInit> {
    let (_, (deriv_start, _), ..) = deriv;
    let lo = (creation_epoch.0 - deriv_start.0) as usize;
    (
        pre_cm_anchor,
        creation_tgs.iter().copied().collect::<TachygramSetPoly>(),
        creation_epoch,
        window[lo],
        window.iter().copied().collect::<NfSeqPoly>(),
        NfMarginPoly::new(&window[..lo]),
        NfTailPoly::new(&window[lo + 1..]),
    )
}

/// Prepare the witness for [`SpendBind`]: `(g, older, tail, nf_next)`.
///
/// `window` is the complete covering sequence, one member per epoch of the
/// derivation header's range; the 2-wide read at the lineage's epoch and
/// its margins are segmented from it, `nf_next` the next epoch's member.
#[must_use]
#[expect(
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "the window covers the derivation header's range"
)]
pub fn spend_bind(
    (spendable, deriv): (StepLeft<SpendBind>, StepRight<SpendBind>),
    window: &[Nullifier],
) -> StepWitness<'static, SpendBind> {
    let (_, (epoch, _), _) = spendable;
    let (_, (deriv_start, _), ..) = deriv;
    let lo = (epoch.0 - deriv_start.0) as usize;
    (
        window.iter().copied().collect::<NfSeqPoly>(),
        NfMarginPoly::new(&window[..lo]),
        NfTailPoly::new(&window[lo + 2..]),
        window[lo + 1],
    )
}

/// Prepare the witness for [`AnchorSeed`]: `(start, epoch, stamp_commit)`.
#[must_use]
pub fn anchor_seed(
    (_left, _right): (StepLeft<AnchorSeed>, StepRight<AnchorSeed>),
    start: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
) -> StepWitness<'static, AnchorSeed> {
    (
        start,
        epoch,
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
