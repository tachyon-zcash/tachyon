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
        stamp::{OutputStamp, SpendStamp},
        summary::{SummaryAdvance, SummarySeed},
    },
    value,
};

type StepLeft<S> = <<S as Step>::Left as Header>::Data;

type StepRight<S> = <<S as Step>::Right as Header>::Data;

type StepWitness<'src, S> = <S as Step>::Witness<'src>;

/// Prepare the witness for [`NoteSeed`]: `(note, pak)`.
#[must_use]
pub const fn note_seed(
    (_left, _right): (StepLeft<NoteSeed>, StepRight<NoteSeed>),
    note: Note,
    pak: ProofAuthorizingKey,
) -> StepWitness<'static, NoteSeed> {
    (note, pak)
}

/// Prepare the witness for [`NullifierDerive`]: `(epoch_first, seq)`.
///
/// Reads `mk` off the seed header and lays the whole window out as the
/// sequence. `epoch_first` must be group-aligned. A longer span fuses
/// windows via [`NullifierFuse`].
#[must_use]
pub fn nullifier_derive(
    (left, _right): (StepLeft<NullifierDerive>, StepRight<NullifierDerive>),
    epoch_first: EpochIndex,
) -> StepWitness<'static, NullifierDerive> {
    let (_cm, mk) = left;
    (
        epoch_first,
        NfSeqPoly::new(epoch_first, &mk.derive_window(epoch_first)),
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
    let (_, left_epoch_first, ..) = left;
    let (_, right_epoch_first, ..) = right;
    let merged = [left_nfs, right_nfs].concat();
    (
        NfSeqPoly::new(left_epoch_first, left_nfs),
        NfSeqPoly::new(left_epoch_first, &merged),
        NfSeqPoly::new(right_epoch_first, right_nfs),
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
/// `(anchor_prev, (epoch, nf), nf_next, elapsed_seq)`.
#[must_use]
pub fn end_epoch_unspent_seed(
    (_left, _right): (
        StepLeft<EndEpochUnspentSeed>,
        StepRight<EndEpochUnspentSeed>,
    ),
    anchor_prev: Anchor,
    epoch: EpochIndex,
    nf: Nullifier,
    nf_next: Nullifier,
) -> StepWitness<'static, EndEpochUnspentSeed> {
    (
        anchor_prev,
        (epoch, nf),
        nf_next,
        NfSeqPoly::new(epoch, &[nf, nf_next]),
    )
}

/// Prepare the witness for [`UnspentFuse`]:
/// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
///
/// `left_elapsed` and `right_elapsed` are the halves' member lists, one per
/// covered epoch. Both include the junction epoch's member, which the
/// combined sequence keeps once.
///
/// # Panics
///
/// Panics if `right_elapsed` is empty. Every segment covers at least its
/// junction epoch, so a caller holding a [`StepRight`] has a member for it.
#[must_use]
pub fn unspent_fuse(
    (left, right): (StepLeft<UnspentFuse>, StepRight<UnspentFuse>),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentFuse> {
    let (_, (left_epoch_first, _), ..) = left;
    let (_, (right_epoch_first, _), ..) = right;
    #[expect(clippy::expect_used, reason = "member lists are nonempty")]
    let (_junction, right_tail) = right_elapsed
        .split_first()
        .expect("right members include the junction");
    let combined = [left_elapsed, right_tail].concat();
    (
        NfSeqPoly::new(left_epoch_first, left_elapsed),
        NfSeqPoly::new(left_epoch_first, &combined),
        NfSeqPoly::new(right_epoch_first, right_elapsed),
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
    let (_, (epoch_first, _), _, (epoch_last, _), _) = unspent;
    let (_, nullifiers_epoch_first, ..) = deriv;
    let lo = u32::from(epoch_first - nullifiers_epoch_first) as usize;
    let (head, from_span) = window.split_at(lo);
    let (_span, tail) = from_span.split_at(elapsed.len());
    let complement_seq = NfSeqPoly::new(nullifiers_epoch_first, head)
        * epoch_last.next().map_or_else(
            || {
                debug_assert!(tail.is_empty(), "no tail can follow the final epoch");
                NfSeqPoly::default()
            },
            |tail_start| NfSeqPoly::new(tail_start, tail),
        );
    (
        NfSeqPoly::new(epoch_first, elapsed),
        NfSeqPoly::new(nullifiers_epoch_first, window),
        complement_seq,
    )
}

/// Prepare the witness for [`SpendableInit`]:
/// `(anchor_prev, creation_set, creation_epoch, nf_current, nf_seq,
/// complement_seq)`.
///
/// `window` is the complete covering sequence, one member per epoch of the
/// derivation header's range; `nf_current` is the member the read forces,
/// and the complement is the window's runs on both sides of the creation
/// epoch, multiplied.
#[must_use]
#[expect(
    clippy::as_conversions,
    reason = "the derivation header's range covers the window"
)]
pub fn spendable_init(
    (deriv, _right): (StepLeft<SpendableInit>, StepRight<SpendableInit>),
    anchor_prev: Anchor,
    creation_tgs: &[Tachygram],
    creation_epoch: EpochIndex,
    window: &[Nullifier],
) -> StepWitness<'static, SpendableInit> {
    let (_, nullifiers_epoch_first, ..) = deriv;
    let lo = u32::from(creation_epoch - nullifiers_epoch_first) as usize;
    let (head, from_creation) = window.split_at(lo);
    let Some((nf_current, tail)) = from_creation.split_first() else {
        unreachable!("the creation epoch's member is in the window");
    };
    let complement_seq = NfSeqPoly::new(nullifiers_epoch_first, head)
        * creation_epoch.next().map_or_else(
            || {
                debug_assert!(tail.is_empty(), "no tail can follow the final epoch");
                NfSeqPoly::default()
            },
            |tail_start| NfSeqPoly::new(tail_start, tail),
        );
    (
        anchor_prev,
        creation_tgs.iter().copied().collect::<TachygramSetPoly>(),
        creation_epoch,
        *nf_current,
        NfSeqPoly::new(nullifiers_epoch_first, window),
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
/// least one epoch past the spendable's epoch, which bounds the spendable
/// epoch at `EPOCH_MAX - 1`: the final epoch has no member to pair with.
#[must_use]
#[expect(
    clippy::as_conversions,
    reason = "the derivation header's range covers the window"
)]
pub fn spend_bind(
    (spendable, deriv): (StepLeft<SpendBind>, StepRight<SpendBind>),
    window: &[Nullifier],
) -> StepWitness<'static, SpendBind> {
    let (_, (epoch, _), _) = spendable;
    let (_, nullifiers_epoch_first, ..) = deriv;
    let lo = u32::from(epoch - nullifiers_epoch_first) as usize;
    let (head, from_spend) = window.split_at(lo);
    let (pair, tail) = from_spend.split_at(2);
    let Some(nf_next) = pair.last() else {
        unreachable!("the read pair is in the window");
    };
    let complement_seq = NfSeqPoly::new(nullifiers_epoch_first, head)
        * epoch.next().and_then(EpochIndex::next).map_or_else(
            || {
                debug_assert!(tail.is_empty(), "no tail can follow the final epoch");
                NfSeqPoly::default()
            },
            |tail_start| NfSeqPoly::new(tail_start, tail),
        );
    (
        NfSeqPoly::new(nullifiers_epoch_first, window),
        complement_seq,
        *nf_next,
    )
}

/// Prepare the witness for [`AnchorSeed`]: `(anchor_first, epoch,
/// stamp_commit)`.
#[must_use]
pub fn anchor_seed(
    (_left, _right): (StepLeft<AnchorSeed>, StepRight<AnchorSeed>),
    anchor_first: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
) -> StepWitness<'static, AnchorSeed> {
    (
        anchor_first,
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
/// nf_current, nf_seq, complement_seq, summary_set)`. `window` as at
/// [`spendable_init`].
#[must_use]
#[expect(
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
    let (_, nullifiers_epoch_first, ..) = deriv;
    let lo = u32::from(creation_epoch - nullifiers_epoch_first) as usize;
    let (head, from_creation) = window.split_at(lo);
    let Some((nf_current, tail)) = from_creation.split_first() else {
        unreachable!("the creation epoch's member is in the window");
    };
    let complement_seq = NfSeqPoly::new(nullifiers_epoch_first, head)
        * creation_epoch.next().map_or_else(
            || {
                debug_assert!(tail.is_empty(), "no tail can follow the final epoch");
                NfSeqPoly::default()
            },
            |tail_start| NfSeqPoly::new(tail_start, tail),
        );
    (
        creation_epoch,
        *nf_current,
        NfSeqPoly::new(nullifiers_epoch_first, window),
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

/// Prepare the witness for [`QrIntakeSplit`]: `(contents, non_residue,
/// residue)`.
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
    let (_epoch, _anchor_prev, _anchor_last, discriminant, profile, _non_residue, _residue) = sides;
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

/// Prepare the witness for [`QrBucketSeal`]: `(anchor_prev_prev)`.
///
/// `anchor_prev_prev` is the terminal anchor of the preceding epoch, the zero
/// anchor for epoch zero.
#[must_use]
pub const fn qr_bucket_seal(
    (_left, _right): (StepLeft<QrBucketSeal>, StepRight<QrBucketSeal>),
    anchor_prev_prev: Anchor,
) -> StepWitness<'static, QrBucketSeal> {
    (anchor_prev_prev,)
}

/// Prepare the witness for [`QrUnspentInit`]: `(value, nf_next, classes, mask,
/// sequence, contents)`.
///
/// `nf_next` is the tested note's nullifier for the epoch after the bucket's;
/// the step folds the crossing into it, so the segment it emits runs from the
/// bucket's own opening to the next epoch's entry anchor.
///
/// # Panics
///
/// Panics when the bucket's profile depth exceeds
/// [`QrProfile::MAX_DEPTH`](crate::primitives::QrProfile::MAX_DEPTH).
#[must_use]
pub fn qr_unspent_init(
    (bucket, _right): (StepLeft<QrUnspentInit>, StepRight<QrUnspentInit>),
    value: Tachygram,
    nf_next: Nullifier,
    bucket_members: &[Tachygram],
) -> StepWitness<'static, QrUnspentInit> {
    let (epoch, _anchor_prev, _anchor_last, discriminant, profile, _contents) = bucket;
    (
        value,
        nf_next,
        QrClassRoot::along(Fp::from(value), discriminant),
        profile.depth_mask(),
        NfSeqPoly::new(epoch, &[Nullifier::from(value), nf_next]),
        bucket_members.iter().copied().collect(),
    )
}

/// Prepare the witness for [`OutputStamp`]: `(rcv, alpha, note, anchor,
/// action_set, tachygram_set)`.
///
/// Reads the tachygram pair off the bind header and derives the action from
/// the note's negated value and `alpha`.
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
    note: Note,
    anchor: Anchor,
) -> StepWitness<'static, OutputStamp> {
    let (cm, pad) = left;

    #[expect(
        clippy::expect_used,
        reason = "identity cv or rk is a degenerate input"
    )]
    let digest = ActionDigest::new(
        rcv.commit(-note.value),
        private::ActionSigningKey::new(&alpha).derive_action_public(),
    )
    .expect("action digest");

    #[expect(clippy::tuple_array_conversions, reason = "required")]
    (
        rcv,
        alpha,
        note,
        anchor,
        ActionSetPoly::from_iter([digest]),
        TachygramSetPoly::from_iter([cm, pad]),
    )
}

/// Prepare the witness for [`SpendStamp`]: `(note, rcv, alpha, pak,
/// action_set, tachygram_set)`.
///
/// Reads the nullifier pair off the bind header and derives the action from
/// the note's value and `pak` randomized by `alpha`.
///
/// # Panics
///
/// Panics when `rcv` or `alpha` yields an identity point, leaving the action
/// undigestible.
#[must_use]
pub fn spend_stamp(
    (left, _right): (StepLeft<SpendStamp>, StepRight<SpendStamp>),
    note: Note,
    rcv: value::Trapdoor,
    alpha: ActionRandomizer<effect::Spend>,
    pak: ProofAuthorizingKey,
) -> StepWitness<'static, SpendStamp> {
    let (_cm, nf_current, nf_next, _anchor) = left;

    #[expect(
        clippy::expect_used,
        reason = "identity cv or rk is a degenerate input"
    )]
    let digest = ActionDigest::new(rcv.commit(note.value), pak.ak.derive_action_public(&alpha))
        .expect("action digest");

    (
        note,
        rcv,
        alpha,
        pak,
        ActionSetPoly::from_iter([digest]),
        TachygramSetPoly::from_iter([Tachygram::from(nf_current), Tachygram::from(nf_next)]),
    )
}
