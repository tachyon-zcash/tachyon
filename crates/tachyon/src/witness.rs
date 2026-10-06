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
    entropy::ActionRandomizer,
    keys::{ProofAuthorizingKey, private},
    note::Note,
    nullifier::Nullifier,
    primitives::{
        ActionDigest, ActionSetPoly, Anchor, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant,
        Tachygram, TachygramSetPoly, effect,
    },
    stamp::proof::{
        delegation::{NoteSeed, NullifierDerive, NullifierFuse},
        pool::{AnchorSeed, UnspentBind, UnspentFuse, UnspentLift},
        qr::{
            QrBucketSeal, QrEmptyIntakeSeed, QrIntakeMerge, QrIntakeSplit, QrSideDescend,
            QrStampIntakeSeed, QrSummaryIntake, QrUnspentInit,
        },
        spendable::{QrSpendableInit, SpendableInit},
        stamp::{OutputStamp, SpendStamp},
        summary::{SummaryAdvance, SummarySeed},
    },
    value,
};

type StepLeft<S> = <<S as Step>::Left as Header>::Data;

type StepRight<S> = <<S as Step>::Right as Header>::Data;

type StepWitness<'src, S> = <S as Step>::Witness<'src>;

/// Prepare the witness for [`NoteSeed`]: `(value, psi, rcm, pak)`.
///
/// `note.pk` is not read; the step derives the payment key from `pak`.
#[must_use]
pub const fn note_seed(
    (_left, _right): (StepLeft<NoteSeed>, StepRight<NoteSeed>),
    note: Note,
    pak: ProofAuthorizingKey,
) -> StepWitness<'static, NoteSeed> {
    (note.value, note.psi, note.rcm, pak)
}

/// Prepare the witness for [`NullifierDerive`]: `(epoch_start, seq)`.
///
/// Reads `mk` off the seed header and lays the whole window out as the
/// sequence. `epoch_start` must be group-aligned. A longer span fuses
/// windows via [`NullifierFuse`].
#[must_use]
pub fn nullifier_derive(
    (left, _right): (StepLeft<NullifierDerive>, StepRight<NullifierDerive>),
    epoch_start: EpochIndex,
) -> StepWitness<'static, NullifierDerive> {
    let (_cm, _note, mk) = left;
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

/// Prepare the witness for [`UnspentFuse`]:
/// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
///
/// `left_elapsed` and `right_elapsed` are the halves' member lists, one per
/// covered epoch.
#[must_use]
pub fn unspent_fuse(
    (left, right): (StepLeft<UnspentFuse>, StepRight<UnspentFuse>),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentFuse> {
    let (_, left_epoch_start, ..) = left;
    let (_, right_epoch_start, ..) = right;
    let combined = [left_elapsed, right_elapsed].concat();
    (
        NfSeqPoly::new(left_epoch_start, left_elapsed),
        NfSeqPoly::new(left_epoch_start, &combined),
        NfSeqPoly::new(right_epoch_start, right_elapsed),
    )
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
    clippy::as_conversions,
    reason = "the derivation header's range covers the window"
)]
pub fn unspent_bind(
    (unspent, deriv): (StepLeft<UnspentBind>, StepRight<UnspentBind>),
    window: &[Nullifier],
    elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentBind> {
    let (_, epoch_start, _, epoch_next, _) = unspent;
    let (_, nullifiers_epoch_start, ..) = deriv;
    let lo = u32::from(epoch_start - nullifiers_epoch_start) as usize;
    let (head, from_span) = window.split_at(lo);
    let (_span, tail) = from_span.split_at(elapsed.len());
    let complement_seq =
        NfSeqPoly::new(nullifiers_epoch_start, head) * NfSeqPoly::new(epoch_next, tail);
    (
        NfSeqPoly::new(epoch_start, elapsed),
        NfSeqPoly::new(nullifiers_epoch_start, window),
        complement_seq,
    )
}

/// Prepare the witness for [`SpendableInit`]:
/// `(anchor_prev, creation_set, creation_epoch)`.
#[must_use]
pub fn spendable_init(
    (_left, _right): (StepLeft<SpendableInit>, StepRight<SpendableInit>),
    anchor_prev: Anchor,
    creation_tgs: &[Tachygram],
    creation_epoch: EpochIndex,
) -> StepWitness<'static, SpendableInit> {
    (
        anchor_prev,
        creation_tgs.iter().copied().collect::<TachygramSetPoly>(),
        creation_epoch,
    )
}

/// Prepare the witness for [`AnchorSeed`]: `(anchor_start, epoch,
/// stamp_commit)`.
#[must_use]
pub fn anchor_seed(
    (_left, _right): (StepLeft<AnchorSeed>, StepRight<AnchorSeed>),
    anchor_start: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
) -> StepWitness<'static, AnchorSeed> {
    (
        anchor_start,
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

/// Prepare the witness for [`QrSpendableInit`]: `(contents)`.
#[must_use]
pub fn qr_spendable_init(
    (_unspent, _bucket): (StepLeft<QrSpendableInit>, StepRight<QrSpendableInit>),
    bucket_members: &[Tachygram],
) -> StepWitness<'static, QrSpendableInit> {
    (bucket_members.iter().copied().collect(),)
}

/// Prepare the witness for [`QrSummaryIntake`]: `(discriminant)`.
#[must_use]
pub const fn qr_summary_intake(
    (_left, _right): (StepLeft<QrSummaryIntake>, StepRight<QrSummaryIntake>),
    discriminant: QrDiscriminant,
) -> StepWitness<'static, QrSummaryIntake> {
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

/// Prepare the witness for [`QrEmptyIntakeSeed`]: `(anchor, epoch,
/// discriminant)`.
#[must_use]
pub const fn qr_empty_intake_seed(
    (_left, _right): (StepLeft<QrEmptyIntakeSeed>, StepRight<QrEmptyIntakeSeed>),
    anchor: Anchor,
    epoch: EpochIndex,
    discriminant: QrDiscriminant,
) -> StepWitness<'static, QrEmptyIntakeSeed> {
    (anchor, epoch, discriminant)
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

/// Prepare the witness for [`QrIntakeSplit`]: `(contents, non_residue,
/// residue)`.
#[must_use]
pub fn qr_intake_split(
    (intake, _right): (StepLeft<QrIntakeSplit>, StepRight<QrIntakeSplit>),
    members: &[Tachygram],
) -> StepWitness<'static, QrIntakeSplit> {
    let (_epoch, _anchor_prev, _anchor_end, discriminant, profile, _contents) = intake;
    let (residue, non_residue) = collections::qr::split(
        members.iter().copied().map(Fp::from),
        discriminant.at(profile.depth),
    );
    (
        members.iter().copied().collect::<TachygramSetPoly>(),
        non_residue
            .iter()
            .map(|&(member, _root)| Tachygram::from(member))
            .collect(),
        residue
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
///
/// # Panics
///
/// Panics if the sibling's decomposition does not exist, which needs a
/// repeated member. A split partitions distinct tachygrams, so this is
/// unreachable.
#[must_use]
pub fn qr_side_descend(
    (sides, _right): (StepLeft<QrSideDescend>, StepRight<QrSideDescend>),
    members: &[Tachygram],
    side: bool,
) -> StepWitness<'static, QrSideDescend> {
    let (_epoch, _anchor_prev, _anchor_end, discriminant, profile, _non_residue, _residue) = sides;
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

/// Prepare the witness for [`QrBucketSeal`]: `(anchor_final_prev)`.
///
/// `anchor_final_prev` is the final anchor of the preceding epoch, or
/// the zero anchor for epoch zero.
#[must_use]
pub const fn qr_bucket_seal(
    (_left, _right): (StepLeft<QrBucketSeal>, StepRight<QrBucketSeal>),
    anchor_final_prev: Anchor,
) -> StepWitness<'static, QrBucketSeal> {
    (anchor_final_prev,)
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
    let (epoch, _anchor_start, _anchor_next, discriminant, profile, _contents) = bucket;
    (
        value,
        QrClassRoot::along(Fp::from(value), discriminant),
        profile.depth_mask(),
        NfSeqPoly::new(epoch, &[Nullifier::from(value)]),
        bucket_members.iter().copied().collect(),
    )
}

/// Prepare the witness for [`UnspentLift`]: `(value, classes, mask,
/// elapsed_seq, extended_seq, contents)`.
///
/// `elapsed` is the segment's member list, one per covered epoch; `value`
/// becomes the member at the bucket's epoch.
#[must_use]
pub fn unspent_lift(
    (unspent, bucket): (StepLeft<UnspentLift>, StepRight<UnspentLift>),
    value: Tachygram,
    elapsed: &[Nullifier],
    bucket_members: &[Tachygram],
) -> StepWitness<'static, UnspentLift> {
    let (_, epoch_start, ..) = unspent;
    let (epoch, _anchor_start, _anchor_next, discriminant, profile, _contents) = bucket;
    let elapsed_seq = NfSeqPoly::new(epoch_start, elapsed);
    (
        value,
        QrClassRoot::along(Fp::from(value), discriminant),
        profile.depth_mask(),
        elapsed_seq.clone(),
        elapsed_seq * NfSeqPoly::new(epoch, &[Nullifier::from(value)]),
        bucket_members.iter().copied().collect(),
    )
}

/// Prepare the witness for [`OutputStamp`]: `(rcv, alpha, anchor,
/// action_set, tachygram_set)`.
///
/// Reads the tachygram pair and the value off the bind header and derives the
/// action from the negated value and `alpha`.
///
/// # Panics
///
/// Panics when `rcv` or `alpha` yields an identity point, leaving the action
/// undigestible.
#[must_use]
pub fn output_stamp(
    (left, _right): (StepLeft<OutputStamp>, StepRight<OutputStamp>),
    rcv: value::Trapdoor,
    alpha: ActionRandomizer<effect::Output>,
    anchor: Anchor,
) -> StepWitness<'static, OutputStamp> {
    let (cm, pad, value) = left;

    #[expect(
        clippy::expect_used,
        reason = "identity cv or rk is a degenerate input"
    )]
    let digest = ActionDigest::new(
        rcv.commit(-value),
        private::ActionSigningKey::new(&alpha).derive_action_public(),
    )
    .expect("action digest");

    (
        rcv,
        alpha,
        anchor,
        ActionSetPoly::from_iter([digest]),
        TachygramSetPoly::from_iter([cm, pad]),
    )
}

/// Prepare the witness for [`SpendStamp`]: `(rcv, alpha, pak, action_set,
/// tachygram_set)`.
///
/// Reads the nullifier pair off the bind header and the note off the right
/// [`NoteMaster`](crate::stamp::proof::delegation::NoteMaster), and derives
/// the action from the note's value and `pak` randomized by `alpha`.
///
/// # Panics
///
/// Panics when `rcv` or `alpha` yields an identity point, leaving the action
/// undigestible.
#[must_use]
pub fn spend_stamp(
    (left, right): (StepLeft<SpendStamp>, StepRight<SpendStamp>),
    rcv: value::Trapdoor,
    alpha: ActionRandomizer<effect::Spend>,
    pak: ProofAuthorizingKey,
) -> StepWitness<'static, SpendStamp> {
    let (_cm, nf_current, nf_next, _anchor) = left;
    let (_master_cm, note, _mk) = right;

    #[expect(
        clippy::expect_used,
        reason = "identity cv or rk is a degenerate input"
    )]
    let digest = ActionDigest::new(rcv.commit(note.value), pak.ak.derive_action_public(&alpha))
        .expect("action digest");

    (
        rcv,
        alpha,
        pak,
        ActionSetPoly::from_iter([digest]),
        TachygramSetPoly::from_iter([Tachygram::from(nf_current), Tachygram::from(nf_next)]),
    )
}
