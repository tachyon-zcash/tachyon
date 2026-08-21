//! Utilities for preparing step witnesses.
//!
//! One function per [`Step`] with a non-empty witness: it assembles the step's
//! [`Witness`](Step::Witness) tuple from raw inputs (interpolating
//! nullifiers and tachygrams into the polynomials the step opens against),
//! ready to seed or fuse through `PROOF_SYSTEM`. Functions are named after the
//! step they serve. Steps with an empty `()` witness need no utility.

extern crate alloc;

use alloc::collections::BTreeSet;

use pasta_curves::Fp;
use ragu::{Header, Step};

use crate::{
    digest::poseidon,
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::Note,
    nullifier::{
        NF_DERIVATION_WIDTH, NfTraceGrid, Nullifier,
        derivation::{nf_fold_accumulator, sbox_quotient, wrap_quotient},
    },
    primitives::{
        ActionDigest, ActionSetPoly, Anchor, EpochIndex, NfMarginPoly, NfSeqPoly, NfTailPoly,
        Tachygram, TachygramSetPoly,
    },
    stamp::proof::{
        delegation::{NfDerive, NfSboxStep, NfWrapStep, NullifierFuse},
        pool::{
            AnchorSeed, EndEpochUnspentSeed, UnspentAdvance, UnspentBatch, UnspentBind,
            UnspentEpochLift, UnspentFuse, UnspentSeed,
        },
        spend::SpendBind,
        spendable::{SpendableAdvance, SpendableBatch, SpendableInit},
        stamp::MergeStamp,
        summary::{SummaryAdvance, SummarySeed},
    },
};

type StepLeft<S> = <<S as Step>::Left as Header>::Data;

type StepRight<S> = <<S as Step>::Right as Header>::Data;

type StepWitness<'src, S> = <S as Step>::Witness<'src>;

/// Prepare the witness for [`NfSboxStep`]:
/// `(trace, square, quartic, quotient, mk, base)`.
///
/// Derives `base`'s window trace out of `mk`, builds the S-box intermediates
/// `(square, quartic)`, computes $\chi_A$ over their commitments (matching
/// the step), and builds the S-box/boundary quotient $Q_A$.
#[must_use]
pub fn nf_sbox_step(
    (_left, _right): (StepLeft<NfSboxStep>, StepRight<NfSboxStep>),
    mk: &NoteMasterKey,
    base: EpochIndex,
) -> StepWitness<'static, NfSboxStep> {
    let grid = NfTraceGrid::derive(mk, base);
    let trace = grid.spectrum();

    let (square, quartic, _wrap) = grid.round_binding_spectra(mk);

    let chi = poseidon::derivation_challenge(
        trace.commit().into(),
        square.commit().into(),
        quartic.commit().into(),
    );

    let quotient = sbox_quotient(&trace, &square, &quartic, mk.0, Fp::from(base), chi);

    (trace, square, quartic, quotient, *mk, base)
}

/// Prepare the witness for [`NfWrapStep`]:
/// `(trace, quartic, wrap, quotient, mk)`.
///
/// Derives `base`'s window trace out of `mk`, builds the `quartic`
/// intermediate and the wrap correction, and builds the round quotient
/// $Q_B$ (single identity, no combination challenge).
#[must_use]
pub fn nf_wrap_step(
    (_left, _right): (StepLeft<NfWrapStep>, StepRight<NfWrapStep>),
    mk: &NoteMasterKey,
    base: EpochIndex,
) -> StepWitness<'static, NfWrapStep> {
    let grid = NfTraceGrid::derive(mk, base);
    let trace = grid.spectrum();

    let (_square, quartic, wrap) = grid.round_binding_spectra(mk);

    let quotient = wrap_quotient(&trace, &quartic, &wrap, mk.0);

    (trace, quartic, wrap, quotient, *mk)
}

/// Prepare the witness for [`NfDerive`]:
/// `(note, pak, window, accumulator, seq)`.
///
/// Reads `mk` and `base` off the sbox cert, whitens the certified trace,
/// lays the window's nullifiers out as a bare Horner sequence, computes the
/// fold weight $\chi$ over the two commitments (matching the step), and
/// builds the fold accumulator for it.
#[must_use]
pub fn nf_derive(
    (left, _right): (StepLeft<NfDerive>, StepRight<NfDerive>),
    note: Note,
    pak: ProofAuthorizingKey,
) -> StepWitness<'static, NfDerive> {
    let (_, nf_commit, _, mk, base) = left;
    let grid = NfTraceGrid::derive(&mk, base);
    let window = grid.spectrum().whiten(&mk);
    let seq: NfSeqPoly = mk.derive_window(base).into_iter().collect();
    let chi = poseidon::fold_challenge(nf_commit.into(), seq.commit().into());
    let accumulator = nf_fold_accumulator(&window, chi);
    (note, pak, window, accumulator, seq)
}

/// A canonical window base covering `epoch`: the window-aligned floor.
///
/// Windows from it are shared across the epochs they cover. The base is free
/// in-circuit; alignment here is wallet policy.
#[must_use]
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "the window width is a small constant, and flooring to the \
              containing window is the intended base"
)]
pub const fn covering_base(epoch: EpochIndex) -> EpochIndex {
    EpochIndex(epoch.0 / NF_DERIVATION_WIDTH as u32 * NF_DERIVATION_WIDTH as u32)
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

/// Prepare the witness for [`UnspentBatch`]: `(nf, summary_set)`.
#[must_use]
pub fn unspent_batch(
    (_summary, _right): (StepLeft<UnspentBatch>, StepRight<UnspentBatch>),
    summary_tgs: &BTreeSet<Tachygram>,
    nf: Nullifier,
) -> StepWitness<'static, UnspentBatch> {
    (
        nf,
        summary_tgs.iter().copied().collect::<TachygramSetPoly>(),
    )
}

/// Prepare the witness for [`UnspentAdvance`]: `(summary_set,)`, the
/// re-witnessed summary accumulator.
#[must_use]
pub fn unspent_advance(
    (_unspent, _summary): (StepLeft<UnspentAdvance>, StepRight<UnspentAdvance>),
    summary_tgs: &BTreeSet<Tachygram>,
) -> StepWitness<'static, UnspentAdvance> {
    (summary_tgs.iter().copied().collect::<TachygramSetPoly>(),)
}

/// Prepare the witness for [`UnspentEpochLift`]:
/// `(summary_set, elapsed_seq, extended_seq, nf_next)`.
///
/// `elapsed` is the lineage's member list, one per covered epoch; the
/// extension appends the incoming epoch's member `nf_next`.
#[must_use]
pub fn unspent_epoch_lift(
    (_unspent, _summary): (StepLeft<UnspentEpochLift>, StepRight<UnspentEpochLift>),
    summary_tgs: &BTreeSet<Tachygram>,
    elapsed: &[Nullifier],
    nf_next: Nullifier,
) -> StepWitness<'static, UnspentEpochLift> {
    let extended: NfSeqPoly = elapsed.iter().copied().chain([nf_next]).collect();
    (
        summary_tgs.iter().copied().collect::<TachygramSetPoly>(),
        elapsed.iter().copied().collect::<NfSeqPoly>(),
        extended,
        nf_next,
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

/// Prepare the witness for [`SpendableBatch`]:
/// `(creation_epoch, present_nf, g, older, tail, summary_set)`.
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
pub fn spendable_batch(
    (deriv, _summary): (StepLeft<SpendableBatch>, StepRight<SpendableBatch>),
    summary_tgs: &BTreeSet<Tachygram>,
    creation_epoch: EpochIndex,
    window: &[Nullifier],
) -> StepWitness<'static, SpendableBatch> {
    let (_, (deriv_start, _), ..) = deriv;
    let lo = (creation_epoch.0 - deriv_start.0) as usize;
    (
        creation_epoch,
        window[lo],
        window.iter().copied().collect::<NfSeqPoly>(),
        NfMarginPoly::new(&window[..lo]),
        NfTailPoly::new(&window[lo + 1..]),
        summary_tgs.iter().copied().collect::<TachygramSetPoly>(),
    )
}

/// Prepare the witness for [`SpendableAdvance`]: `(summary_set,)`, the
/// re-witnessed summary accumulator.
#[must_use]
pub fn spendable_advance(
    (_spendable, _summary): (StepLeft<SpendableAdvance>, StepRight<SpendableAdvance>),
    summary_tgs: &BTreeSet<Tachygram>,
) -> StepWitness<'static, SpendableAdvance> {
    (summary_tgs.iter().copied().collect::<TachygramSetPoly>(),)
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
///
/// `acc_tgs` is the summary's accumulated tachygram list so far, `stamp_tgs`
/// the folded stamp's. The extended accumulator is the root polynomial of
/// their concatenation, which *is* the product `acc · stamp` (all three are
/// monic root polynomials), so no polynomial multiplication happens here.
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
