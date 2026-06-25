//! Utilities for preparing step witnesses.
//!
//! Each function interpolates raw nullifiers and tachygrams into the
//! polynomials a single [`Step`] opens against, returning its
//! [`Witness`](ragu::Step::Witness) ready to seed or fuse through
//! `PROOF_SYSTEM`. Functions are named after the step they serve.
//!
//! They assemble the polynomial witness only: no key derivation, GGM walk, or
//! pool query. Steps whose witness is plain value bundling are assembled at the
//! call site instead.

use alloc::vec::Vec;

use ragu::{Header, Step};

use crate::{
    note::Nullifier,
    primitives::{Anchor, EpochIndex, NfSeqPoly, Tachygram, TachygramSetPoly},
    stamp::proof::{
        delegation::NullifierFuse,
        pool::{UnspentEpochFuse, UnspentFuse, UnspentSeed, VerifyUnspent},
        spendable::SpendableInit,
    },
};

/// Prepare the witness for [`NullifierFuse`]: `(left, leaf, merged)`.
///
/// Folds the fresh nullifier `leaf` onto the accumulated range `left` (in epoch
/// order): `merged = left ++ [leaf]`.
#[must_use]
pub fn nullifier_fuse(
    (_left, _right): (
        <<NullifierFuse as Step>::Left as Header>::Data,
        <<NullifierFuse as Step>::Right as Header>::Data,
    ),
    left: &[Nullifier],
    leaf: Nullifier,
) -> <NullifierFuse as Step>::Witness<'static> {
    let mut merged: Vec<Nullifier> = left.to_vec();
    merged.push(leaf);
    (
        left.iter().copied().collect::<NfSeqPoly>(),
        NfSeqPoly::from_iter([leaf]),
        merged.into_iter().collect::<NfSeqPoly>(),
    )
}

/// Prepare the witness for [`UnspentSeed`]: `(prev_anchor, epoch, tg_set, nf)`.
///
/// `prev_anchor` is the anchor before the seeded stamp, `tgs` its tachygrams,
/// and `nf` the nullifier whose absence the seed attests.
#[must_use]
pub fn unspent_seed(
    (_left, _right): (
        <<UnspentSeed as Step>::Left as Header>::Data,
        <<UnspentSeed as Step>::Right as Header>::Data,
    ),
    prev_anchor: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
    nf: Nullifier,
) -> <UnspentSeed as Step>::Witness<'static> {
    (
        prev_anchor,
        epoch,
        tgs.iter().copied().collect::<TachygramSetPoly>(),
        nf,
    )
}

/// Prepare the witness for [`UnspentFuse`]:
/// `(left_elapsed_poly, right_elapsed_poly, combined_elapsed_poly)`.
///
/// Composes two unspent lineages sharing a mid-epoch junction:
/// `combined = left_elapsed ++ right_elapsed`. No splice, since the shared
/// junction nullifier is read from the headers by the step.
#[must_use]
pub fn unspent_fuse(
    (_left, _right): (
        <<UnspentFuse as Step>::Left as Header>::Data,
        <<UnspentFuse as Step>::Right as Header>::Data,
    ),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> <UnspentFuse as Step>::Witness<'static> {
    let mut combined: Vec<Nullifier> = left_elapsed.to_vec();
    combined.extend_from_slice(right_elapsed);
    (
        left_elapsed.iter().copied().collect::<NfSeqPoly>(),
        right_elapsed.iter().copied().collect::<NfSeqPoly>(),
        combined.into_iter().collect::<NfSeqPoly>(),
    )
}

/// Prepare the witness for [`UnspentEpochFuse`]:
/// `(left_elapsed_poly, right_elapsed_poly, combined_elapsed_poly)`.
///
/// Composes two unspent lineages across the epoch boundary between them:
/// `combined = left_elapsed ++ [end_nf] ++ right_elapsed`, where the boundary
/// nullifier `end_nf` is the left
/// [`Unspent`](crate::stamp::proof::pool::Unspent) header's tip. Extending by
/// one fresh epoch passes an empty `right_elapsed`.
#[must_use]
pub fn unspent_epoch_fuse(
    (left, _right): (
        <<UnspentEpochFuse as Step>::Left as Header>::Data,
        <<UnspentEpochFuse as Step>::Right as Header>::Data,
    ),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> <UnspentEpochFuse as Step>::Witness<'static> {
    let ((..), _, _, _, end_nf, _) = left;
    let mut combined: Vec<Nullifier> = left_elapsed.to_vec();
    combined.push(end_nf);
    combined.extend_from_slice(right_elapsed);
    (
        left_elapsed.iter().copied().collect::<NfSeqPoly>(),
        right_elapsed.iter().copied().collect::<NfSeqPoly>(),
        combined.into_iter().collect::<NfSeqPoly>(),
    )
}

/// Prepare the witness for [`VerifyUnspent`]: `(elapsed, tip, range)`.
///
/// `elapsed` is the tested nullifier sequence over the crossed epochs
/// `[start_epoch, end_epoch)`. The `tip` is the end-epoch nullifier `end_nf`
/// from the left [`Unspent`](crate::stamp::proof::pool::Unspent) header; `range
/// = elapsed ++ [end_nf]`.
#[must_use]
pub fn verify_unspent(
    (left, _right): (
        <<VerifyUnspent as Step>::Left as Header>::Data,
        <<VerifyUnspent as Step>::Right as Header>::Data,
    ),
    elapsed: &[Nullifier],
) -> <VerifyUnspent as Step>::Witness<'static> {
    let ((..), _, _, _, end_nf, _) = left;
    let mut range: Vec<Nullifier> = elapsed.to_vec();
    range.push(end_nf);
    (
        elapsed.iter().copied().collect::<NfSeqPoly>(),
        NfSeqPoly::from_iter([end_nf]),
        range.into_iter().collect::<NfSeqPoly>(),
    )
}

/// Prepare the witness for [`SpendableInit`]:
/// `(pre_epoch_anchor, pre_cm_anchor, creation_set, present_nf)`.
///
/// `creation_tgs` are the creation stamp's tachygrams. The two anchors are
/// caller-reconstructed consensus state and `present_nf` is the spendable's
/// present-epoch nullifier.
#[must_use]
pub fn spendable_init(
    (_left, _right): (
        <<SpendableInit as Step>::Left as Header>::Data,
        <<SpendableInit as Step>::Right as Header>::Data,
    ),
    pre_epoch_anchor: Anchor,
    pre_cm_anchor: Anchor,
    creation_tgs: &[Tachygram],
    present_nf: Nullifier,
) -> <SpendableInit as Step>::Witness<'static> {
    (
        pre_epoch_anchor,
        pre_cm_anchor,
        creation_tgs.iter().copied().collect::<TachygramSetPoly>(),
        present_nf,
    )
}
