//! Utilities for preparing step witnesses.
//!
//! One function per [`Step`] with a non-empty witness: it assembles the step's
//! [`Witness`](ragu::Step::Witness) tuple from raw inputs (interpolating
//! nullifiers and tachygrams into the polynomials the step opens against),
//! ready to seed or fuse through `PROOF_SYSTEM`. Functions are named after the
//! step they serve. Steps with an empty `()` witness need no utility.

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Header, Step};

use crate::{
    digest::poseidon,
    keys::{NoteMasterKey, ProofAuthorizingKey},
    note::Note,
    nullifier::{
        NfTraceGrid, Nullifier,
        derivation::{
            NF_COSET_SHIFT, NF_EPOCH_STEP, nf_fold_accumulator, sbox_quotient, wrap_quotient,
        },
    },
    primitives::{
        ActionDigest, ActionSetPoly, Anchor, EpochIndex, NfSeqPoly, Tachygram, TachygramSetPoly,
    },
    stamp::proof::{
        delegation::{SboxStep, WrapStep},
        pool::{AnchorSeed, UnspentBind, UnspentEpochFuse, UnspentFuse, UnspentSeed},
        spend::SpendBind,
        spendable::SpendableInit,
        stamp::MergeStamp,
    },
};

type StepLeft<S> = <<S as Step>::Left as Header>::Data;

type StepRight<S> = <<S as Step>::Right as Header>::Data;

type StepWitness<'src, S> = <S as Step>::Witness<'src>;

/// Prepare the witness for [`SboxStep`].
///
/// Derives `base`'s window trace out of `mk`, builds the S-box intermediates
/// `(square, quartic)`, computes $\chi_A$ over their commitments (matching
/// the step), and builds the S-box/boundary quotient $Q_A$.
#[must_use]
pub fn sbox_boundary(
    (_left, _right): (StepLeft<SboxStep>, StepRight<SboxStep>),
    mk: &NoteMasterKey,
    base: EpochIndex,
) -> StepWitness<'static, SboxStep> {
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

/// Prepare the witness for [`WrapStep`].
///
/// Reads `mk` and `base` off the cert header, derives the window trace,
/// builds the `quartic` intermediate and the wrap correction, and builds the
/// round quotient `Q_B` (single identity, no combination challenge).
#[must_use]
pub fn recurrence(
    (left, _right): (StepLeft<WrapStep>, StepRight<WrapStep>),
    note: Note,
    pak: ProofAuthorizingKey,
) -> StepWitness<'static, WrapStep> {
    let (_, _, _, mk, base) = left;
    let grid = NfTraceGrid::derive(&mk, base);
    let trace = grid.spectrum();

    let (_square, quartic, wrap) = grid.round_binding_spectra(&mk);

    let quotient = wrap_quotient(&trace, &quartic, &wrap, mk.0);

    (trace, quartic, wrap, quotient, note, pak)
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

/// Prepare the witness for [`UnspentFuse`]:
/// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
#[must_use]
pub fn unspent_fuse(
    (_left, _right): (StepLeft<UnspentFuse>, StepRight<UnspentFuse>),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentFuse> {
    let combined = [left_elapsed, right_elapsed].concat();
    (
        left_elapsed.iter().copied().collect::<NfSeqPoly>(),
        combined.into_iter().collect::<NfSeqPoly>(),
        right_elapsed.iter().copied().collect::<NfSeqPoly>(),
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
    let combined = [left_elapsed, &[nf_end], right_elapsed].concat();
    (
        left_elapsed.iter().copied().collect::<NfSeqPoly>(),
        combined.into_iter().collect::<NfSeqPoly>(),
        right_elapsed.iter().copied().collect::<NfSeqPoly>(),
    )
}

/// Prepare the witness for [`UnspentBind`]:
/// `(elapsed_seq, nf_spectrum, accumulator)`.
///
/// `elapsed` is the unspent's per-crossing history. Derives the covering
/// window's whitened trace $W$ out of `mk`, computes the fold weight $\chi$
/// over the trace and elapsed commitments (matching the step), and builds
/// the fold accumulator $A$ for that $\chi$.
#[must_use]
pub fn unspent_bind(
    (_unspent, deriv): (StepLeft<UnspentBind>, StepRight<UnspentBind>),
    mk: &NoteMasterKey,
    elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentBind> {
    let (_, deriv_start, ..) = deriv;
    let elapsed_seq = elapsed.iter().copied().collect::<NfSeqPoly>();
    let nf_spectrum = NfTraceGrid::derive(mk, deriv_start).spectrum().whiten(mk.1);

    let chi = poseidon::fold_challenge(nf_spectrum.commit().into(), elapsed_seq.commit().into());
    let accumulator = nf_fold_accumulator(&nf_spectrum, chi);

    (elapsed_seq, nf_spectrum, accumulator)
}

/// Prepare the witness for [`SpendableInit`]:
/// `((pre_epoch_anchor, pre_cm_anchor), creation_set, creation_epoch,
/// nf_spectrum)`.
///
/// Derives the covering window's whitened trace $W$ out of `mk`; the step
/// reads $\mathsf{present\_nf} = W(\sigma
/// \zeta^{\mathsf{creation\_epoch} - \mathsf{deriv\_start}})$.
#[must_use]
pub fn spendable_init(
    (_chain, deriv): (StepLeft<SpendableInit>, StepRight<SpendableInit>),
    pre_epoch_anchor: Anchor,
    pre_cm_anchor: Anchor,
    creation_tgs: &[Tachygram],
    creation_epoch: EpochIndex,
    mk: &NoteMasterKey,
) -> StepWitness<'static, SpendableInit> {
    let (_, deriv_start, ..) = deriv;
    (
        (pre_epoch_anchor, pre_cm_anchor),
        creation_tgs.iter().copied().collect::<TachygramSetPoly>(),
        creation_epoch,
        NfTraceGrid::derive(mk, deriv_start).spectrum().whiten(mk.1),
    )
}

/// Prepare the witness for [`SpendBind`]: `(nf_spectrum, nf_point)`.
///
/// Derives the covering window's whitened trace $W$ out of `mk` and the
/// present epoch's nullifier point $\ell = \sigma
/// \zeta^{\mathsf{present\_epoch} - \mathsf{deriv\_start}}$; the step reads
/// $\mathsf{present\_nf} = W(\ell)$ and $\mathsf{nf\_next} = W(\zeta \ell)$.
#[must_use]
pub fn spend_bind(
    (_spendable, deriv): (StepLeft<SpendBind>, StepRight<SpendBind>),
    present_epoch: EpochIndex,
    mk: &NoteMasterKey,
) -> StepWitness<'static, SpendBind> {
    let (_, deriv_start, ..) = deriv;
    (
        NfTraceGrid::derive(mk, deriv_start).spectrum().whiten(mk.1),
        *NF_COSET_SHIFT * NF_EPOCH_STEP.pow_vartime([u64::from(present_epoch - deriv_start)]),
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
