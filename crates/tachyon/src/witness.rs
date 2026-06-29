//! Utilities for preparing step witnesses.
//!
//! One function per [`Step`](ragu::Step) with a non-empty witness; named after
//! the step it serves. Key material is passed in, never derived here; the
//! expensive expansion/FFT runs once on the wallet and is reused.

use core::array;

use alloc::vec::Vec;

use pasta_curves::Fp;
use ragu::{Header, Polynomial, Step};

use crate::{
    constants::NF_EMITTERS,
    digest::poseidon,
    keys::{ExpandedKey, NoteMasterKey},
    note::Nullifier,
    primitives::{
        Anchor, EpochIndex, ExpKeySpectrumPoly, ExpandedKeyPoly, NfEmitterPoly, NfSeqPoly,
        Tachygram, TachygramSetPoly,
    },
    relations::quotient::{
        self, LIFT_SPLITS, RoundBoundaryQuotients, accumulator_recurrence, weight_recurrence,
    },
    stamp::proof::{
        delegation::{NfMasterExpand, NullifierDerivationStep},
        pool::{UnspentEpochFuse, UnspentFuse, UnspentSeed, VerifyUnspent},
        spendable::SpendableInit,
    },
};

type StepLeft<S> = <<S as Step>::Left as Header>::Data;

type StepRight<S> = <<S as Step>::Right as Header>::Data;

type StepWitness<'src, S> = <S as Step>::Witness<'src>;

/// Witness for [`NfMasterExpand`] for one half.
///
/// `(trace, round_boundary_quotients, half_key_poly, decimation_quotient,
/// half)`. `half ∈ {0,1}` selects the cipher-input window `base = half ·
/// EK_HALF`; the caller supplies that half's `EK_HALF` keys.
#[must_use]
pub fn nf_master_expand<'key>(
    headers: (StepLeft<NfMasterExpand>, StepRight<NfMasterExpand>),
    mk: &'key NoteMasterKey,
    spectrum: &'key ExpKeySpectrumPoly,
    half_keys: &'key [Fp; ExpandedKey::EK_HALF],
    half: usize,
) -> StepWitness<'key, NfMasterExpand> {
    let (_left, _right) = headers;
    let key_poly = ExpandedKey::half_key_poly(half_keys);
    #[expect(clippy::as_conversions, reason = "constant size")]
    let base = Fp::from((half * ExpandedKey::EK_HALF) as u64);
    let (round, boundary, decimation_quotient) = quotient::expansion_quotients(
        spectrum.0.coefficients(),
        *mk,
        key_poly.0.coefficients(),
        base,
    );
    #[expect(clippy::as_conversions, reason = "half is 0 or 1")]
    (
        spectrum.clone(),
        RoundBoundaryQuotients { round, boundary },
        key_poly,
        decimation_quotient,
        Fp::from(half as u64),
    )
}

/// Witness for [`NullifierDerivationStep`].
///
/// `(key_a, key_b, derivation_polys, quotients, creation_epoch)`. `key_a`/`key_b`
/// are the even/odd half-key polys; `keyset` is the assembled interleaved
/// schedule the round quotients are built against.
#[must_use]
pub fn nullifier_derivation<'key>(
    headers: (StepLeft<NullifierDerivationStep>, StepRight<NullifierDerivationStep>),
    keyset: &'key ExpandedKey,
    key_a: ExpandedKeyPoly,
    key_b: ExpandedKeyPoly,
    mk: &'key NoteMasterKey,
    polys: &'key [NfEmitterPoly; NF_EMITTERS],
    creation_epoch: EpochIndex,
) -> StepWitness<'key, NullifierDerivationStep> {
    let (_keyset_even, _keyset_odd) = headers;
    let salts = mk.query_salts();
    // k_0 = K(1) = A(1) = the even-position-0 key.
    let first_key = keyset.round_key(0);

    #[expect(clippy::indexing_slicing, reason = "todo")]
    let quotients: [RoundBoundaryQuotients<_>; NF_EMITTERS] =
        array::from_fn(|i| RoundBoundaryQuotients {
            round: quotient::nf_emitter_round_quotient(polys[i].0.coefficients(), &keyset.0),
            boundary: quotient::nf_emitter_boundary_quotient(
                polys[i].0.coefficients(),
                salts.0[i],
                first_key,
            ),
        });
    (key_a, key_b, polys.clone(), quotients, creation_epoch)
}

/// Witness for [`SpendableInit`]:
/// `(pre_epoch_anchor, pre_cm_anchor, creation_set, derivation_polys)`.
#[must_use]
pub fn spendable_init(
    headers: (StepLeft<SpendableInit>, StepRight<SpendableInit>),
    polys: &[NfEmitterPoly; NF_EMITTERS],
    pre_epoch_anchor: Anchor,
    pre_cm_anchor: Anchor,
    creation_set: TachygramSetPoly,
) -> StepWitness<'_, SpendableInit> {
    let (_anchor_chain, _derivation) = headers;
    (pre_epoch_anchor, pre_cm_anchor, creation_set, polys.clone())
}

/// Witness for [`VerifyUnspent`]: `(elapsed, tip, range, derivation_polys,
/// weights, accumulator, weight_quotients, accumulator_quotient)`.
#[must_use]
pub fn verify_unspent<'key>(
    headers: (StepLeft<VerifyUnspent>, StepRight<VerifyUnspent>),
    polys: &'key [NfEmitterPoly; NF_EMITTERS],
    mk: &'key NoteMasterKey,
    range_nfs: &'key [Nullifier],
    start: EpochIndex,
    present: EpochIndex,
) -> StepWitness<'key, VerifyUnspent> {
    use group::Curve as _;
    use pasta_curves::{Eq, arithmetic::CurveAffine as _};

    // Certified transcript digest, read off the derivation header.
    let (_unspent, derivation) = headers;
    let (_, digest, ..) = derivation;

    // The ratios and shift are re-derived from mk (they match the certified
    // derivation header's by the derivation step's soundness).
    let (ratios, shift) = mk.query_weights();

    // Tested values q over [start, present]: query nullifiers at offsets.
    let split = range_nfs.len() - 1;
    let (elapsed_nfs, tip_nfs) = range_nfs.split_at(split);
    let elapsed = elapsed_nfs.iter().copied().collect::<NfSeqPoly>();
    let tip = tip_nfs.iter().copied().collect::<NfSeqPoly>();
    let range_poly = range_nfs.iter().copied().collect::<NfSeqPoly>();

    // Lift challenge β over the certified digest, commit(q), and range.
    let range_coords = Eq::from(range_poly.commit())
        .to_affine()
        .coordinates()
        .expect("range commitment is not identity");
    let beta = poseidon::lift_challenge(digest.0, range_coords, start, present.next());

    // Per-poly geometric weights w_j (split) and quotients; the
    // exclusive-prefix accumulator A (split) and its recurrence quotient.
    let (weights, weight_quotients): (Vec<_>, Vec<_>) = ratios
        .0
        .map(|ratio| weight_recurrence(ratio * beta, shift.0))
        .into_iter()
        .unzip();
    let weights_arr: [[Polynomial; LIFT_SPLITS]; NF_EMITTERS] =
        weights.try_into().unwrap_or_else(|extra: Vec<_>| {
            unreachable!("NF_EMITTERS is {NF_EMITTERS}, got {}", extra.len())
        });
    let weight_quotients_arr: [Polynomial; NF_EMITTERS] =
        weight_quotients.try_into().unwrap_or_else(|extra: Vec<_>| {
            unreachable!("NF_EMITTERS is {NF_EMITTERS}, got {}", extra.len())
        });
    let (accumulator, accumulator_quotient) =
        accumulator_recurrence(polys, &ratios.0, shift.0, beta);

    (
        elapsed,
        tip,
        range_poly,
        polys.clone(),
        weights_arr,
        accumulator,
        weight_quotients_arr,
        accumulator_quotient,
    )
}

/// Witness for [`UnspentSeed`]: `(anchor_prev, (epoch, nf), stamp_tg_set)`.
#[must_use]
pub fn unspent_seed(
    headers: (StepLeft<UnspentSeed>, StepRight<UnspentSeed>),
    anchor_prev: Anchor,
    epoch: EpochIndex,
    tgs: &[Tachygram],
    nf: Nullifier,
) -> StepWitness<'static, UnspentSeed> {
    let ((), ()) = headers;
    (
        anchor_prev,
        (epoch, nf),
        tgs.iter().copied().collect::<TachygramSetPoly>(),
    )
}

/// Witness for [`UnspentFuse`]:
/// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`. The junction
/// epoch is shared, so no nullifier is inserted between the histories.
#[must_use]
pub fn unspent_fuse(
    headers: (StepLeft<UnspentFuse>, StepRight<UnspentFuse>),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentFuse> {
    let (_left, _right) = headers;
    let mut combined: Vec<Nullifier> = left_elapsed.to_vec();
    combined.extend_from_slice(right_elapsed);
    (
        left_elapsed.iter().copied().collect::<NfSeqPoly>(),
        combined.into_iter().collect::<NfSeqPoly>(),
        right_elapsed.iter().copied().collect::<NfSeqPoly>(),
    )
}

/// Witness for [`UnspentEpochFuse`]:
/// `(left_elapsed_seq, combined_elapsed_seq, right_elapsed_seq)`. The crossed
/// boundary splices the left tip `nf_end` (read off the left header) between the
/// histories.
#[must_use]
pub fn unspent_epoch_fuse(
    headers: (StepLeft<UnspentEpochFuse>, StepRight<UnspentEpochFuse>),
    left_elapsed: &[Nullifier],
    right_elapsed: &[Nullifier],
) -> StepWitness<'static, UnspentEpochFuse> {
    let (left, _right) = headers;
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
