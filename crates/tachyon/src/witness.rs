//! Utilities for preparing step witnesses.
//!
//! One function per [`Step`] with a non-empty witness: it assembles the step's
//! [`Witness`](Step::Witness) tuple from raw inputs (interpolating
//! nullifiers and tachygrams into the polynomials the step opens against),
//! ready to seed or fuse through `PROOF_SYSTEM`. Functions are named after the
//! step they serve. Steps with an empty `()` witness need no utility.

use alloc::collections::BTreeSet;

use pasta_curves::Fp;
use ragu::{Header, Step};

use crate::{
    collections,
    constants::EVIDENCE_TREE_ARITY,
    entropy::ActionEntropy,
    fee,
    keys::{ProofAuthorizingKey, private},
    note::{self, Note},
    nullifier::Nullifier,
    primitives::{
        ActionDigest, ActionSetPoly, Anchor, EpochIndex, EvidenceTreeRoot, NfSeqPoly, QrClassRoot,
        QrDiscriminant, QrProfile, Tachygram, TachygramSetCommit, TachygramSetPoly, effect,
    },
    stamp::proof::{
        delegation::{NoteSeed, NullifierDerive, NullifierFuse},
        evidence::{EvidenceTreeDescend, EvidenceTreeOpen},
        pool::{AnchorSpanFuse, AnchorSpanSeed, UnspentBind, UnspentFuse, UnspentLift},
        qr::{
            QrBucketSeal, QrEmptyIntakeSeed, QrIntakeMerge, QrIntakeSplit, QrSideDescend,
            QrStampIntakeSeed, QrSummaryIntake, QrUnspentInit,
        },
        spendable::{QrSpendableInit, SpendableInit},
        stamp::{FeeFuse, FeeSeed, OutputAction, SpendAction, StampLift},
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

/// Prepare the witness for [`AnchorSpanSeed`]: `(anchor_start, epoch,
/// stamp_commit)`.
#[must_use]
pub fn anchor_span_seed(
    (_left, _right): (StepLeft<AnchorSpanSeed>, StepRight<AnchorSpanSeed>),
    anchor_start: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
) -> StepWitness<'static, AnchorSpanSeed> {
    (
        anchor_start,
        epoch,
        tgs.iter().copied().collect::<TachygramSetPoly>().commit(),
    )
}

/// Prepare the witness for [`AnchorSpanFuse`]: `(left_members, combined,
/// right_members)`.
///
/// `left_members` and `right_members` are the members polynomials of the two
/// halves.
#[must_use]
pub fn anchor_span_fuse(
    (_left, _right): (StepLeft<AnchorSpanFuse>, StepRight<AnchorSpanFuse>),
    left_members: &[Anchor],
    right_members: &[Anchor],
) -> StepWitness<'static, AnchorSpanFuse> {
    (
        left_members.iter().copied().collect(),
        left_members.iter().chain(right_members).copied().collect(),
        right_members.iter().copied().collect(),
    )
}

/// Prepare the witness for [`StampLift`]: `(members)`.
///
/// `members` is the span's members polynomial.
#[must_use]
pub fn stamp_lift(
    (_stamp, _span): (StepLeft<StampLift>, StepRight<StampLift>),
    members: &[Anchor],
) -> StepWitness<'static, StampLift> {
    (members.iter().copied().collect(),)
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

/// Prepare the witness for [`EvidenceTreeDescend`]: `(path)`.
///
/// `path` runs outermost level first, one `(sides, children)` per level.
#[must_use]
pub const fn evidence_tree_descend(
    (_tree, _right): (
        StepLeft<EvidenceTreeDescend>,
        StepRight<EvidenceTreeDescend>,
    ),
    path: [([bool; 2], [EvidenceTreeRoot; EVIDENCE_TREE_ARITY]); EvidenceTreeDescend::LEVELS],
) -> StepWitness<'static, EvidenceTreeDescend> {
    (path,)
}

/// Prepare the witness for [`EvidenceTreeOpen`]: `(profile, contents)`.
///
/// The pair is the preimage of the leaf the tree has descended to.
#[must_use]
pub const fn evidence_tree_open(
    (_tree, _right): (StepLeft<EvidenceTreeOpen>, StepRight<EvidenceTreeOpen>),
    profile: QrProfile,
    contents: TachygramSetCommit,
) -> StepWitness<'static, EvidenceTreeOpen> {
    (profile, contents)
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

/// Prepare the witness for [`OutputAction`]: `(theta, anchor, action_set,
/// tachygram_set)`.
///
/// Reads the tachygram pair and `cv` off the bind header, derives `alpha`
/// from `theta` and `cm`, and derives the action from `cv` and `alpha`.
///
/// # Panics
///
/// Panics when `cv` or `alpha` yields an identity point, leaving the action
/// undigestible.
#[must_use]
pub fn output_action(
    (left, _right): (StepLeft<OutputAction>, StepRight<OutputAction>),
    theta: ActionEntropy,
    anchor: Anchor,
) -> StepWitness<'static, OutputAction> {
    let (cm, pad, cv) = left;
    let alpha = theta.randomizer::<effect::Output>(note::Commitment::from(Fp::from(cm)));

    #[expect(
        clippy::expect_used,
        reason = "identity cv or rk is a degenerate input"
    )]
    let digest = ActionDigest::new(
        cv,
        private::ActionSigningKey::new(&alpha).derive_action_public(),
    )
    .expect("action digest");

    (
        theta,
        anchor,
        ActionSetPoly::from_iter([digest]),
        TachygramSetPoly::from_iter([cm, pad]),
    )
}

/// Prepare the witness for [`SpendAction`]: `(theta, pak, action_set,
/// tachygram_set)`.
///
/// Reads `cm`, the nullifier pair and `cv` off the bind header, derives
/// `alpha` from `theta` and `cm`, and derives the action from `cv` and `pak`
/// randomized by `alpha`.
///
/// # Panics
///
/// Panics when `cv` or `rk` is the identity, leaving the action undigestible.
#[must_use]
pub fn spend_action(
    (left, _right): (StepLeft<SpendAction>, StepRight<SpendAction>),
    theta: ActionEntropy,
    pak: ProofAuthorizingKey,
) -> StepWitness<'static, SpendAction> {
    let (cm, nf_current, nf_next, _anchor, _pk, cv) = left;
    let alpha = theta.randomizer::<effect::Spend>(cm);

    #[expect(
        clippy::expect_used,
        reason = "identity cv or rk is a degenerate input"
    )]
    let digest = ActionDigest::new(cv, pak.ak.derive_action_public(&alpha)).expect("action digest");

    (
        theta,
        pak,
        ActionSetPoly::from_iter([digest]),
        TachygramSetPoly::from_iter([Tachygram::from(nf_current), Tachygram::from(nf_next)]),
    )
}

/// Prepare the witness for [`FeeFuse`]: `(max_fee_note, fee,
/// (left_action_set, left_tachygram_set), (output_action_set,
/// output_tachygram_set), (fee_action_set, fee_tachygram_set))`.
///
/// `action_digests` and `tachygrams` are the left `Actions` sets. Each fee
/// singleton set contains one element: the fee digest or the fee change note's
/// commitment. The output set polynomials represent the unions.
///
/// # Panics
///
/// Panics if the max fee note's `rcm` is zero or the fee exceeds its value.
#[must_use]
pub fn fee_fuse(
    (_left, _right): (StepLeft<FeeFuse>, StepRight<FeeFuse>),
    max_fee_note: Note,
    fee: value::Positive,
    action_digests: &BTreeSet<ActionDigest>,
    tachygrams: &BTreeSet<Tachygram>,
) -> StepWitness<'static, FeeFuse> {
    #[expect(
        clippy::expect_used,
        reason = "a planned max fee commitment is never the identity"
    )]
    let fee_digest = fee::Descriptor {
        max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
        value: fee,
    }
    .digest()
    .expect("fee digest");
    #[expect(clippy::expect_used, reason = "the fee must not exceed the maximum")]
    let fee_change_note = Note {
        value: value::Positive::try_from(i128::from(max_fee_note.value) - i128::from(fee))
            .expect("fee should not exceed max fee"),
        ..max_fee_note
    };
    let fee_change_commitment = Tachygram::from(fee_change_note.commitment());

    let mut output_action_digests = action_digests.clone();
    output_action_digests.insert(fee_digest);
    let mut output_tachygrams = tachygrams.clone();
    output_tachygrams.insert(fee_change_commitment);

    (
        max_fee_note,
        fee,
        (
            action_digests.iter().copied().collect(),
            tachygrams.iter().copied().collect(),
        ),
        (
            output_action_digests.into_iter().collect(),
            output_tachygrams.into_iter().collect(),
        ),
        (
            ActionSetPoly::from_iter([fee_digest]),
            TachygramSetPoly::from_iter([fee_change_commitment]),
        ),
    )
}

/// Prepare the witness for [`FeeSeed`]: `(max_fee_note, anchor,
/// fee_action_set, fee_tachygram_set)`.
///
/// # Panics
///
/// Panics if the max fee note's value is nonzero or its `rcm` is zero.
#[must_use]
pub fn fee_seed(
    (_left, _right): (StepLeft<FeeSeed>, StepRight<FeeSeed>),
    max_fee_note: Note,
    anchor: Anchor,
) -> StepWitness<'static, FeeSeed> {
    assert_eq!(
        u64::from(max_fee_note.value),
        0,
        "a fee seed's max fee note must have zero value"
    );
    #[expect(
        clippy::expect_used,
        reason = "a planned max fee commitment is never the identity"
    )]
    let fee_digest = fee::Descriptor {
        max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
        value: value::Positive::ZERO,
    }
    .digest()
    .expect("fee digest");
    let fee_change_note = Note {
        value: value::Positive::ZERO,
        ..max_fee_note
    };
    let fee_change_commitment = Tachygram::from(fee_change_note.commitment());
    (
        max_fee_note,
        anchor,
        ActionSetPoly::from_iter([fee_digest]),
        TachygramSetPoly::from_iter([fee_change_commitment]),
    )
}
