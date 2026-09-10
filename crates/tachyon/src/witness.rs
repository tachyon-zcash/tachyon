//! Utilities for preparing step witnesses.
//!
//! One function per [`Step`] with a non-empty witness: it assembles the step's
//! [`Witness`](Step::Witness) tuple from raw inputs (interpolating
//! nullifiers and tachygrams into the polynomials the step opens against),
//! ready to seed or fuse through `PROOF_SYSTEM`. Functions are named after the
//! step they serve. Steps with an empty `()` witness need no utility.

use pasta_curves::Fp;
use ragu::{Header, Step};

use crate::{
    collections,
    keys::ProofAuthorizingKey,
    note::Note,
    nullifier::Nullifier,
    primitives::{
        ActionDigest, ActionSetPoly, Anchor, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant,
        Tachygram, TachygramSetPoly,
    },
    stamp::proof::{
        delegation::{NfDerive, NfMasterSeed, NullifierFuse},
        pool::{
            AnchorSeed, EndEpochUnspentSeed, SummaryUnspentInit, UnspentBind, UnspentFuse,
            UnspentSeed,
        },
        qr::{
            QrBucketSeal, QrIntakeMerge, QrIntakeSplit, QrSideDescend, QrStampIntakeSeed,
            QrSummaryIntakeInit, QrUnspentInit,
        },
        spend::SpendBind,
        spendable::{QrSpendableInit, SpendableInit, SummarySpendableInit},
        stamp::MergeStamp,
        summary::{SummaryAdvance, SummarySeed},
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

/// Prepare the witness for [`NfDerive`]: `(epoch_start, seq)`.
///
/// Reads `mk` off the seed header and lays the whole window out as the
/// sequence. `epoch_start` must be group-aligned. A longer span fuses
/// windows via [`NullifierFuse`].
#[must_use]
pub fn nf_derive(
    (left, _right): (StepLeft<NfDerive>, StepRight<NfDerive>),
    epoch_start: EpochIndex,
) -> StepWitness<'static, NfDerive> {
    let (_cm, mk) = left;
    (
        epoch_start,
        NfSeqPoly::new(epoch_start, &mk.derive_window(epoch_start)),
    )
}

/// Prepare the witness for [`NullifierFuse`]:
/// `(left_seq, merged_seq, right_seq)`.
#[must_use]
pub fn nullifier_fuse(
    (left, right): (StepLeft<NullifierFuse>, StepRight<NullifierFuse>),
    left_nfs: &[Nullifier],
    right_nfs: &[Nullifier],
) -> StepWitness<'static, NullifierFuse> {
    let (_, left_epoch_start, ..) = left;
    let (_, right_epoch_start, ..) = right;
    let merged = [left_nfs, right_nfs].concat();
    (
        NfSeqPoly::new(left_epoch_start, left_nfs),
        NfSeqPoly::new(left_epoch_start, &merged),
        NfSeqPoly::new(right_epoch_start, right_nfs),
    )
}

/// Prepare the witness for [`UnspentSeed`]: `(anchor_prev, (epoch, nf),
/// tg_set, elapsed_seq)`.
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
        NfSeqPoly::new(epoch, &[nf]),
    )
}

/// Prepare the witness for [`EndEpochUnspentSeed`]:
/// `(anchor_prev, (epoch_prev, nf_prev), nf, elapsed_seq)`.
#[must_use]
pub fn end_epoch_unspent_seed(
    (_left, _right): (
        StepLeft<EndEpochUnspentSeed>,
        StepRight<EndEpochUnspentSeed>,
    ),
    anchor_prev: Anchor,
    epoch_prev: EpochIndex,
    nf_prev: Nullifier,
    nf: Nullifier,
) -> StepWitness<'static, EndEpochUnspentSeed> {
    (
        anchor_prev,
        (epoch_prev, nf_prev),
        nf,
        NfSeqPoly::new(epoch_prev, &[nf_prev, nf]),
    )
}

/// Prepare the witness for [`UnspentFuse`]:
/// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
///
/// `left_elapsed` and `right_elapsed` are the halves' member lists, one per
/// covered epoch. Both include the junction epoch's member, which the
/// combined sequence keeps once.
#[must_use]
pub fn unspent_fuse(
    (left, right): (StepLeft<UnspentFuse>, StepRight<UnspentFuse>),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentFuse> {
    let (_, (left_epoch_start, _), ..) = left;
    let (_, (right_epoch_start, _), ..) = right;
    #[expect(clippy::expect_used, reason = "member lists are nonempty")]
    let (_junction, right_tail) = right_elapsed
        .split_first()
        .expect("right members include the junction");
    let combined = [left_elapsed, right_tail].concat();
    (
        NfSeqPoly::new(left_epoch_start, left_elapsed),
        NfSeqPoly::new(left_epoch_start, &combined),
        NfSeqPoly::new(right_epoch_start, right_elapsed),
    )
}

/// The complement's run after the covered span: the window members past
/// `span_last`, positioned one epoch after it.
///
/// An empty run is the multiplicative identity and needs no position, so
/// the span may end at the final epoch, which has no successor.
fn complement_tail(span_last: EpochIndex, tail: &[Nullifier]) -> NfSeqPoly {
    if tail.is_empty() {
        NfSeqPoly::default()
    } else {
        NfSeqPoly::new(span_last.next(), tail)
    }
}

/// Prepare the witness for [`UnspentBind`]:
/// `(elapsed_seq, nf_seq, complement_seq)`.
///
/// `elapsed` is the unspent's member list, one per covered epoch. `window`
/// is the complete covering sequence, one member per epoch of the
/// derivation header's range; the complement is the window's runs on both
/// sides of the unspent's span, multiplied.
#[must_use]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "the derivation header's range covers the window"
)]
pub fn unspent_bind(
    (unspent, deriv): (StepLeft<UnspentBind>, StepRight<UnspentBind>),
    window: &[Nullifier],
    elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentBind> {
    let (_, (epoch_start, _), _, (epoch_last, _), _) = unspent;
    let (_, deriv_start, ..) = deriv;
    let lo = (epoch_start.0 - deriv_start.0) as usize;
    let hi = (epoch_last.0 - deriv_start.0) as usize + 1;
    let complement_seq =
        NfSeqPoly::new(deriv_start, &window[..lo]) * complement_tail(epoch_last, &window[hi..]);
    (
        NfSeqPoly::new(epoch_start, elapsed),
        NfSeqPoly::new(deriv_start, window),
        complement_seq,
    )
}

/// Prepare the witness for [`SpendableInit`]:
/// `(pre_cm_anchor, creation_set, creation_epoch, present_nf, nf_seq,
/// complement_seq)`.
///
/// `window` is the complete covering sequence, one member per epoch of the
/// derivation header's range; `present_nf` is the member the read forces,
/// and the complement is the window's runs on both sides of the creation
/// epoch, multiplied.
#[must_use]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "the derivation header's range covers the window"
)]
pub fn spendable_init(
    (deriv, _right): (StepLeft<SpendableInit>, StepRight<SpendableInit>),
    pre_cm_anchor: Anchor,
    creation_tgs: &[Tachygram],
    creation_epoch: EpochIndex,
    window: &[Nullifier],
) -> StepWitness<'static, SpendableInit> {
    let (_, deriv_start, ..) = deriv;
    let lo = (creation_epoch.0 - deriv_start.0) as usize;
    let complement_seq = NfSeqPoly::new(deriv_start, &window[..lo])
        * complement_tail(creation_epoch, &window[lo + 1..]);
    (
        pre_cm_anchor,
        creation_tgs.iter().copied().collect::<TachygramSetPoly>(),
        creation_epoch,
        window[lo],
        NfSeqPoly::new(deriv_start, window),
        complement_seq,
    )
}

/// Prepare the witness for [`SpendBind`]:
/// `(nf_seq, complement_seq, nf_next)`.
///
/// `window` is the complete covering sequence, one member per epoch of the
/// derivation header's range; `nf_next` is the next epoch's member, and the
/// complement is the window's runs on both sides of the read pair,
/// multiplied. The pair read requires the derivation range to extend at
/// least one epoch past the spendable's epoch.
#[must_use]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "the derivation header's range covers the window"
)]
pub fn spend_bind(
    (spendable, deriv): (StepLeft<SpendBind>, StepRight<SpendBind>),
    window: &[Nullifier],
) -> StepWitness<'static, SpendBind> {
    let (_, (epoch, _), _) = spendable;
    let (_, deriv_start, ..) = deriv;
    let lo = (epoch.0 - deriv_start.0) as usize;
    let complement_seq = NfSeqPoly::new(deriv_start, &window[..lo])
        * complement_tail(epoch.next(), &window[lo + 2..]);
    (
        NfSeqPoly::new(deriv_start, window),
        complement_seq,
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

/// Prepare the witness for [`SummarySeed`]:
/// `(anchor_prev, epoch, stamp_commit)`.
#[must_use]
pub fn summary_seed(
    (_left, _right): (StepLeft<SummarySeed>, StepRight<SummarySeed>),
    anchor_prev: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
) -> StepWitness<'static, SummarySeed> {
    (
        anchor_prev,
        epoch,
        tgs.iter().copied().collect::<TachygramSetPoly>().commit(),
    )
}

/// Prepare the witness for [`SummaryAdvance`]: `(acc, extended, stamp)`.
#[must_use]
pub fn summary_advance(
    (_left, _right): (StepLeft<SummaryAdvance>, StepRight<SummaryAdvance>),
    acc_tgs: &[Tachygram],
    stamp_tgs: &[Tachygram],
) -> StepWitness<'static, SummaryAdvance> {
    let extended = acc_tgs
        .iter()
        .chain(stamp_tgs.iter())
        .copied()
        .collect::<TachygramSetPoly>();
    (
        acc_tgs.iter().copied().collect::<TachygramSetPoly>(),
        extended,
        stamp_tgs.iter().copied().collect::<TachygramSetPoly>(),
    )
}

/// Prepare the witness for [`SummaryUnspentInit`]:
/// `(nf, summary_set, elapsed_seq)`.
#[must_use]
pub fn summary_unspent_init(
    (summary, _right): (StepLeft<SummaryUnspentInit>, StepRight<SummaryUnspentInit>),
    summary_tgs: &[Tachygram],
    nf: Nullifier,
) -> StepWitness<'static, SummaryUnspentInit> {
    let (summary_epoch, ..) = summary;
    (
        nf,
        summary_tgs.iter().copied().collect::<TachygramSetPoly>(),
        NfSeqPoly::new(summary_epoch, &[nf]),
    )
}

/// Prepare the witness for [`SummarySpendableInit`]: `(creation_epoch,
/// present_nf, nf_seq, complement_seq, summary_set)`. `window` as at
/// [`spendable_init`].
#[must_use]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::as_conversions,
    reason = "the derivation header's range covers the window"
)]
pub fn summary_spendable_init(
    (deriv, _summary): (
        StepLeft<SummarySpendableInit>,
        StepRight<SummarySpendableInit>,
    ),
    summary_tgs: &[Tachygram],
    creation_epoch: EpochIndex,
    window: &[Nullifier],
) -> StepWitness<'static, SummarySpendableInit> {
    let (_, deriv_start, ..) = deriv;
    let lo = (creation_epoch.0 - deriv_start.0) as usize;
    let complement_seq = NfSeqPoly::new(deriv_start, &window[..lo])
        * complement_tail(creation_epoch, &window[lo + 1..]);
    (
        creation_epoch,
        window[lo],
        NfSeqPoly::new(deriv_start, window),
        complement_seq,
        summary_tgs.iter().copied().collect::<TachygramSetPoly>(),
    )
}

/// Prepare the witness for [`QrSpendableInit`]: `(contents)`.
#[must_use]
pub fn qr_spendable_init(
    (_unspent, _bucket): (StepLeft<QrSpendableInit>, StepRight<QrSpendableInit>),
    bucket_members: &[Tachygram],
) -> StepWitness<'static, QrSpendableInit> {
    (bucket_members.iter().copied().collect(),)
}

/// Prepare the witness for [`QrSummaryIntakeInit`]: `(discriminant)`.
#[must_use]
pub const fn qr_summary_intake_init(
    (_left, _right): (
        StepLeft<QrSummaryIntakeInit>,
        StepRight<QrSummaryIntakeInit>,
    ),
    discriminant: QrDiscriminant,
) -> StepWitness<'static, QrSummaryIntakeInit> {
    (discriminant,)
}

/// Prepare the witness for [`QrStampIntakeSeed`]: `(anchor_prev, epoch,
/// discriminant, stamp_commit)`.
#[must_use]
pub fn qr_stamp_intake_seed(
    (_left, _right): (StepLeft<QrStampIntakeSeed>, StepRight<QrStampIntakeSeed>),
    anchor_prev: Anchor,
    epoch: EpochIndex,
    discriminant: QrDiscriminant,
    tgs: &[Tachygram],
) -> StepWitness<'static, QrStampIntakeSeed> {
    (
        anchor_prev,
        epoch,
        discriminant,
        tgs.iter().copied().collect::<TachygramSetPoly>().commit(),
    )
}

/// Prepare the witness for [`QrIntakeMerge`]: `(left_contents,
/// right_contents, merged)`.
#[must_use]
pub fn qr_intake_merge(
    (_left, _right): (StepLeft<QrIntakeMerge>, StepRight<QrIntakeMerge>),
    left_tgs: &[Tachygram],
    right_tgs: &[Tachygram],
) -> StepWitness<'static, QrIntakeMerge> {
    (
        left_tgs.iter().copied().collect::<TachygramSetPoly>(),
        right_tgs.iter().copied().collect::<TachygramSetPoly>(),
        left_tgs
            .iter()
            .chain(right_tgs)
            .copied()
            .collect::<TachygramSetPoly>(),
    )
}

/// Prepare the witness for [`QrIntakeSplit`]: `(contents, residue,
/// non_residue)`.
#[must_use]
pub fn qr_intake_split(
    (intake, _right): (StepLeft<QrIntakeSplit>, StepRight<QrIntakeSplit>),
    members: &[Tachygram],
) -> StepWitness<'static, QrIntakeSplit> {
    let (_epoch, _anchor_prev, _anchor_last, discriminant, profile, _contents) = intake;
    let (residue, non_residue) = collections::qr::split(
        members.iter().copied().map(Fp::from),
        discriminant.at(profile.depth),
    );
    (
        members.iter().copied().collect::<TachygramSetPoly>(),
        residue
            .iter()
            .map(|&(member, _root)| Tachygram::from(member))
            .collect(),
        non_residue
            .iter()
            .map(|&(member, _root)| Tachygram::from(member))
            .collect(),
    )
}

/// Prepare the witness for [`QrSideDescend`]: `(bit, sibling_contents,
/// interpolant, quotient)`.
///
/// `members` is the whole membership [`qr_intake_split`] partitioned; `side`
/// is the residue side when set. The decomposition is the sibling's, at the
/// sibling's class multiplier.
#[must_use]
pub fn qr_side_descend(
    (sides, _right): (StepLeft<QrSideDescend>, StepRight<QrSideDescend>),
    members: &[Tachygram],
    side: bool,
) -> StepWitness<'static, QrSideDescend> {
    let (_epoch, _anchor_prev, _anchor_last, discriminant, profile, _residue, _non_residue) = sides;
    let (residue, non_residue) = collections::qr::split(
        members.iter().copied().map(Fp::from),
        discriminant.at(profile.depth),
    );
    let sibling = if side { non_residue } else { residue };
    #[expect(clippy::expect_used, reason = "members of a split are distinct")]
    let (interpolant, quotient) = collections::qr::decomposition(
        &sibling,
        collections::qr::class_multiplier(!side),
        discriminant.at(profile.depth),
    )
    .expect("members of a split are distinct");
    (
        side,
        sibling
            .iter()
            .map(|&(member, _root)| Tachygram::from(member))
            .collect(),
        interpolant.into(),
        quotient.into(),
    )
}

/// Prepare the witness for [`QrBucketSeal`]: `(prev_last)`.
///
/// `prev_last` is the terminal anchor of the preceding epoch, the zero anchor
/// for epoch zero.
#[must_use]
pub const fn qr_bucket_seal(
    (_left, _right): (StepLeft<QrBucketSeal>, StepRight<QrBucketSeal>),
    prev_last: Anchor,
) -> StepWitness<'static, QrBucketSeal> {
    (prev_last,)
}

/// Prepare the witness for [`QrUnspentInit`]: `(value, classes, mask,
/// sequence, contents)`.
///
/// # Panics
///
/// Panics when the bucket's profile depth exceeds
/// [`QrProfile::MAX_DEPTH`](crate::primitives::QrProfile::MAX_DEPTH).
#[must_use]
pub fn qr_unspent_init(
    (bucket, _right): (StepLeft<QrUnspentInit>, StepRight<QrUnspentInit>),
    value: Tachygram,
    bucket_members: &[Tachygram],
) -> StepWitness<'static, QrUnspentInit> {
    let (epoch, _anchor_prev, _anchor_last, discriminant, profile, _contents) = bucket;
    (
        value,
        QrClassRoot::along(Fp::from(value), discriminant),
        profile.depth_mask(),
        NfSeqPoly::new(epoch, &[Nullifier::from(value)]),
        bucket_members.iter().copied().collect(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::EPOCH_MAX;

    #[test]
    fn complement_tail_may_end_at_the_final_epoch() {
        let empty = complement_tail(EpochIndex(EPOCH_MAX), &[]);
        assert_eq!(empty.commit(), NfSeqPoly::default().commit());
    }

    #[test]
    fn complement_tail_positions_members_after_the_span() {
        let nf = Nullifier::from(Fp::from(7u64));
        let tail = complement_tail(EpochIndex(41), &[nf]);
        assert_eq!(tail.commit(), NfSeqPoly::new(EpochIndex(42), &[nf]).commit());
    }
}
