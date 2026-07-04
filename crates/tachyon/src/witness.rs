//! Utilities for preparing step witnesses.
//!
//! One function per [`Step`] with a non-empty witness: it assembles the step's
//! [`Witness`](ragu::Step::Witness) tuple from raw inputs (interpolating
//! nullifiers and tachygrams into the polynomials the step opens against),
//! ready to seed or fuse through `PROOF_SYSTEM`. Functions are named after the
//! step they serve. Steps with an empty `()` witness need no utility.

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu::{Header, Step};

use crate::{
    digest::poseidon,
    keys::{GGM_CHUNK_SIZE, GGM_TREE_ARITY, NoteMasterKey, NotePrefixedKey},
    note::Nullifier,
    primitives::{
        ActionDigest, ActionSetPoly, Anchor, EpochIndex, NfSeqPoly, Tachygram, TachygramSetPoly,
    },
    relations::quotient::{RoundBoundaryQuotients, evaluation_sum, expansion_quotients},
    stamp::proof::{
        delegation::{NfMasterStep, NfPrefixStep, NullifierDerivationStep, NullifierFuse},
        pool::{AnchorSeed, UnspentBind, UnspentEpochFuse, UnspentFuse, UnspentSeed},
        spend::SpendBind,
        spendable::SpendableInit,
        stamp::MergeStamp,
    },
};

type StepLeft<S> = <<S as Step>::Left as Header>::Data;

type StepRight<S> = <<S as Step>::Right as Header>::Data;

type StepWitness<'src, S> = <S as Step>::Witness<'src>;

/// Prepare the witness for [`NfMasterStep`].
///
/// Assembles `mk` from the two header-carried parts, runs child `chunk`'s
/// native trace expansion, and builds the round/boundary/decimation
/// quotients its relations open.
#[must_use]
pub fn nf_master_step(
    (left, right): (StepLeft<NfMasterStep>, StepRight<NfMasterStep>),
    chunk: u8,
) -> StepWitness<'static, NfMasterStep> {
    let (left_part, ..) = left;
    let (right_part, ..) = right;
    let mk = NoteMasterKey::from_parts(&[left_part, right_part]);
    let (states, _child, child_poly) = mk.expand_child_trace(chunk);
    let trace = states.spectrum();
    let (round, boundary, decimation) = expansion_quotients(
        trace.0.coefficients(),
        &mk.0,
        &mk.expansion_params(),
        child_poly.0.coefficients(),
        Fp::from(u64::from(chunk) << GGM_CHUNK_SIZE),
    );
    (
        trace,
        RoundBoundaryQuotients { round, boundary },
        child_poly,
        decimation,
        chunk,
    )
}

/// Prepare the witness for [`NfPrefixStep`].
///
/// The parent schedule polynomial (matching the left header's commitment)
/// plus child `chunk`'s native trace expansion and quotients. `node` is the
/// input node's native key.
#[must_use]
pub fn nf_prefix_step(
    (_left, _right): (StepLeft<NfPrefixStep>, StepRight<NfPrefixStep>),
    node: &NotePrefixedKey,
    chunk: u8,
) -> StepWitness<'static, NfPrefixStep> {
    let (states, _child, child_poly) = node.expand_child_trace(chunk);
    let trace = states.spectrum();
    let (round, boundary, decimation) = expansion_quotients(
        trace.0.coefficients(),
        &node.schedule,
        &node.expansion_params(),
        child_poly.0.coefficients(),
        Fp::from(u64::from(chunk) << GGM_CHUNK_SIZE),
    );
    (
        node.key_poly(),
        trace,
        RoundBoundaryQuotients { round, boundary },
        child_poly,
        decimation,
        chunk,
    )
}

/// Prepare the witness for [`NullifierDerivationStep`].
///
/// The depth-2 node's leaf schedule polynomial (matching the left header's
/// commitment), its native leaf expansion trace and quotients, the eval-form
/// leaf polynomial, the coeff-form sentinel sequence of its `GGM_TREE_ARITY`
/// nullifiers, and the homomorphic bind's running-sum accumulator and quotient.
/// `node` is the depth-2 node's native key.
#[must_use]
pub fn nullifier_derivation(
    (_left, _right): (
        StepLeft<NullifierDerivationStep>,
        StepRight<NullifierDerivationStep>,
    ),
    node: &NotePrefixedKey,
) -> StepWitness<'static, NullifierDerivationStep> {
    let (states, outputs, leaf_poly) = node.leaf_nullifier_trace();
    let trace = states.spectrum();
    let (round, boundary, decimation) = expansion_quotients(
        trace.0.coefficients(),
        &node.schedule,
        &node.leaf_params(),
        leaf_poly.0.coefficients(),
        Fp::ZERO,
    );
    let seq = outputs
        .iter()
        .copied()
        .map(Nullifier::from)
        .collect::<NfSeqPoly>();

    // Build the running-sum accumulator for the same `β` the step derives from
    // the two commitments, so the homomorphic eval->coeff bind agrees in-step.
    let beta = poseidon::leaf_sequence_challenge(leaf_poly.0.commit(), Eq::from(seq.commit()));
    let (accumulator, evaluation_quotient) =
        evaluation_sum::<GGM_TREE_ARITY>(leaf_poly.0.coefficients(), beta);

    (
        node.key_poly(),
        trace,
        RoundBoundaryQuotients { round, boundary },
        decimation,
        leaf_poly,
        seq,
        accumulator,
        evaluation_quotient,
    )
}

/// Prepare the witness for [`NullifierFuse`]: `(left, merged, right)`.
#[must_use]
pub fn nullifier_fuse(
    (_left, _right): (StepLeft<NullifierFuse>, StepRight<NullifierFuse>),
    left: &[Nullifier],
    right: &[Nullifier],
) -> StepWitness<'static, NullifierFuse> {
    let mut merged: Vec<Nullifier> = left.to_vec();
    merged.extend_from_slice(right);
    (
        left.iter().copied().collect::<NfSeqPoly>(),
        merged.into_iter().collect::<NfSeqPoly>(),
        right.iter().copied().collect::<NfSeqPoly>(),
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

/// Prepare the witness for [`UnspentFuse`]:
/// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`.
#[must_use]
pub fn unspent_fuse(
    (_left, _right): (StepLeft<UnspentFuse>, StepRight<UnspentFuse>),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentFuse> {
    let mut combined: Vec<Nullifier> = left_elapsed.to_vec();
    combined.extend_from_slice(right_elapsed);
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
    let mut combined: Vec<Nullifier> = left_elapsed.to_vec();
    combined.push(nf_end);
    combined.extend_from_slice(right_elapsed);
    (
        left_elapsed.iter().copied().collect::<NfSeqPoly>(),
        combined.into_iter().collect::<NfSeqPoly>(),
        right_elapsed.iter().copied().collect::<NfSeqPoly>(),
    )
}

/// Prepare the witness for [`UnspentBind`]:
/// `(elapsed_seq, nf_seq, deriv_seq, prefix_seq, suffix_seq)`.
///
/// `elapsed` is the unspent's per-crossing history; `deriv_nfs` the covering
/// derivation's full nullifier sequence (one per covered epoch, in order).
/// Builds the tested sub-sequence `nf_seq = elapsed ++ [unspent_nf_end]` and
/// slices the derivation into the prefix / suffix around its coverage window.
#[must_use]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "prover-side builder; coverage offsets are in-bounds by construction"
)]
pub fn unspent_bind(
    (unspent, deriv): (StepLeft<UnspentBind>, StepRight<UnspentBind>),
    elapsed: &[Nullifier],
    deriv_nfs: &[Nullifier],
) -> StepWitness<'static, UnspentBind> {
    let (_, (unspent_epoch_start, _), _, (_unspent_epoch_end, unspent_nf_end), _) = unspent;
    let (_, deriv_start, ..) = deriv;
    let mut nf_seq: Vec<Nullifier> = elapsed.to_vec();
    nf_seq.push(unspent_nf_end);
    let off =
        usize::try_from(unspent_epoch_start.0 - deriv_start.0).expect("coverage offset fits usize");
    let len = nf_seq.len();
    (
        elapsed.iter().copied().collect::<NfSeqPoly>(),
        nf_seq.into_iter().collect::<NfSeqPoly>(),
        deriv_nfs.iter().copied().collect::<NfSeqPoly>(),
        deriv_nfs[..off].iter().copied().collect::<NfSeqPoly>(),
        deriv_nfs[off + len..]
            .iter()
            .copied()
            .collect::<NfSeqPoly>(),
    )
}

/// Prepare the witness for [`SpendableInit`]:
/// `((pre_epoch_anchor, pre_cm_anchor), creation_set, present_nf,
/// creation_epoch, deriv_seq, prefix_seq, tail_seq)`.
///
/// Confirms `present_nf` by coverage: the derivation covers `creation_epoch` at
/// offset `off = creation_epoch - deriv_start`, so `q = prefix ++ tail` with
/// `tail` starting at `off`. `deriv_nfs` is the derivation's full nullifier
/// sequence.
#[must_use]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "prover-side builder; coverage offsets are in-bounds by construction"
)]
pub fn spendable_init(
    (_chain, deriv): (StepLeft<SpendableInit>, StepRight<SpendableInit>),
    pre_epoch_anchor: Anchor,
    pre_cm_anchor: Anchor,
    creation_tgs: &[Tachygram],
    present_nf: Nullifier,
    creation_epoch: EpochIndex,
    deriv_nfs: &[Nullifier],
) -> StepWitness<'static, SpendableInit> {
    let (_, deriv_start, ..) = deriv;
    let off =
        usize::try_from(creation_epoch.0 - deriv_start.0).expect("coverage offset fits usize");
    (
        (pre_epoch_anchor, pre_cm_anchor),
        creation_tgs.iter().copied().collect::<TachygramSetPoly>(),
        present_nf,
        creation_epoch,
        deriv_nfs.iter().copied().collect::<NfSeqPoly>(),
        deriv_nfs[..off].iter().copied().collect::<NfSeqPoly>(),
        deriv_nfs[off..].iter().copied().collect::<NfSeqPoly>(),
    )
}

/// Prepare the witness for [`SpendBind`]:
/// `(present_epoch, deriv_seq, prefix_seq, tail_seq, next_tail_seq)`.
///
/// Confirms the present and next nullifiers by coverage: `q = prefix ++ tail`
/// with `tail` starting at `off = present_epoch - deriv_start`, and `tail =
/// [present_nf] ++ next_tail`. `deriv_nfs` is the derivation's full nullifier
/// sequence.
#[must_use]
#[expect(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "prover-side builder; coverage offsets are in-bounds by construction"
)]
pub fn spend_bind(
    (_spendable, deriv): (StepLeft<SpendBind>, StepRight<SpendBind>),
    present_epoch: EpochIndex,
    deriv_nfs: &[Nullifier],
) -> StepWitness<'static, SpendBind> {
    let (_, deriv_start, ..) = deriv;
    let off = usize::try_from(present_epoch.0 - deriv_start.0).expect("coverage offset fits usize");
    (
        present_epoch,
        deriv_nfs.iter().copied().collect::<NfSeqPoly>(),
        deriv_nfs[..off].iter().copied().collect::<NfSeqPoly>(),
        deriv_nfs[off..].iter().copied().collect::<NfSeqPoly>(),
        deriv_nfs[off + 1..].iter().copied().collect::<NfSeqPoly>(),
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
