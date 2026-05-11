//! Tachyon Blake2b digests.
//!
//! Each named function matches one protocol-defined hash. All use
//! BLAKE2b-512 (64-byte output). Personalizations are 13–16 bytes;
//! `blake2b_simd::Params::personal` accepts any length ≤ 16.

use blake2b_simd::Params;
use ff::PrimeField as _;
use lazy_static::lazy_static;
use pasta_curves::{EqAffine, Fp, arithmetic::CurveAffine as _};

const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";
const BUNDLE_COMMITMENT_PERSONALIZATION: &[u8; 16] = b"Tachyon-BndlHash";
const AUTH_DIGEST_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTachyHash";
const SPEND_ALPHA_PERSONALIZATION: &[u8; 13] = b"Tachyon-Spend";
const OUTPUT_ALPHA_PERSONALIZATION: &[u8; 14] = b"Tachyon-Output";

// Domain bytes for Tachyon's PRF-expand.
// See https://github.com/zcash/zcash_spec/blob/main/src/prf_expand.rs
const ASK_DOMAIN_BYTE: u8 = 0x21;
const NK_DOMAIN_BYTE: u8 = 0x22;

/// PRF-expand to derive `ask` from a spending key. Performs no normalization.
///
/// $\text{BLAKE2b-512}(\text{"Zcash\_ExpandSeed"}, sk \|
/// \texttt{ASK_DOMAIN_BYTE})$. Mirrors Zcash §5.4.2.
///
/// TODO: return normalized Fq?
pub(crate) fn prf_expand_ask(sk: &[u8; 32]) -> [u8; 64] {
    *Params::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state()
        .update(sk)
        .update(&[ASK_DOMAIN_BYTE])
        .finalize()
        .as_array()
}

/// PRF-expand to derive `nk` from a spending key. Performs no normalization.
///
/// $\text{BLAKE2b-512}(\text{"Zcash\_ExpandSeed"}, sk \|
/// \texttt{NK_DOMAIN_BYTE})$.
///
/// TODO: return normalized Fq?
pub(crate) fn prf_expand_nk(sk: &[u8; 32]) -> [u8; 64] {
    *Params::new()
        .hash_length(64)
        .personal(PRF_EXPAND_PERSONALIZATION)
        .to_state()
        .update(sk)
        .update(&[NK_DOMAIN_BYTE])
        .finalize()
        .as_array()
}

/// Spend-side $\alpha$ pre-image: $\text{BLAKE2b-512}(\text{"Tachyon-Spend"},
/// \theta \| cm)$.
///
/// Caller reduces to scalar via `Fq::from_uniform_bytes`.
pub(crate) fn alpha_spend(theta: &[u8; 32], cm: &[u8; 32]) -> [u8; 64] {
    *Params::new()
        .hash_length(64)
        .personal(SPEND_ALPHA_PERSONALIZATION)
        .to_state()
        .update(theta)
        .update(cm)
        .finalize()
        .as_array()
}

/// Output-side $\alpha$ pre-image: $\text{BLAKE2b-512}(\text{"Tachyon-Output"},
/// \theta \| cm)$.
pub(crate) fn alpha_output(theta: &[u8; 32], cm: &[u8; 32]) -> [u8; 64] {
    *Params::new()
        .hash_length(64)
        .personal(OUTPUT_ALPHA_PERSONALIZATION)
        .to_state()
        .update(theta)
        .update(cm)
        .finalize()
        .as_array()
}

/// A bundle's contribution to the transaction sighash.
///
/// Hashes the bundle's effecting data. The stamp is excluded because it is
/// stripped during aggregation.
#[must_use]
pub(crate) fn bundle_commitment(action_commit: &EqAffine, value_balance: i64) -> [u8; 64] {
    let coords = action_commit
        .coordinates()
        .expect("commitment should not be the identity point");

    *Params::new()
        .hash_length(64)
        .personal(BUNDLE_COMMITMENT_PERSONALIZATION)
        .to_state()
        .update(&coords.x().to_repr())
        .update(&coords.y().to_repr())
        .update(&value_balance.to_le_bytes())
        .finalize()
        .as_array()
}

/// A stamped bundle's contribution to the transaction auth_digest.
///
/// Hashes action signatures, the binding signature, and the stamp.
pub(crate) fn stamped_auth_digest(
    action_sigs: &[[u8; 64]],
    binding_sig: &[u8; 64],
    anchor: &[u8; 32],
    tachygrams: &[Fp],
    proof: &[u8],
) -> [u8; 64] {
    let mut state = Params::new()
        .hash_length(64)
        .personal(AUTH_DIGEST_PERSONALIZATION)
        .to_state();

    for action_sig in action_sigs {
        state.update(action_sig);
    }

    state.update(binding_sig);

    state.update(anchor);

    for tg in tachygrams {
        state.update(&tg.to_repr());
    }

    state.update(proof);

    *state.finalize().as_array()
}

/// A stripped bundle's contribution to the transaction auth_digest.
///
/// Hashes action signatures, the binding signature, and aggregate wtxid.
pub(crate) fn stripped_auth_digest(
    action_sigs: &[[u8; 64]],
    binding_sig: &[u8; 64],
    wtxid: &[u8; 64],
) -> [u8; 64] {
    let mut state = Params::new()
        .hash_length(64)
        .personal(AUTH_DIGEST_PERSONALIZATION)
        .to_state();

    for action_sig in action_sigs {
        state.update(action_sig);
    }

    state.update(binding_sig);

    state.update(wtxid);

    *state.finalize().as_array()
}

lazy_static! {
    /// A non-Tachyon transaction's contribution to the transaction sighash.
    ///
    /// **This is NOT the same as a stripped bundle.**
    ///
    /// **This is NOT the same as a bundle with no actions and zero balance.**
    pub static ref COMMIT_NO_BUNDLE: [u8; 64] = {
        *Params::new()
            .hash_length(64)
            .personal(BUNDLE_COMMITMENT_PERSONALIZATION)
            .to_state()
            .finalize()
            .as_array()
    };

    /// A non-Tachyon transaction's contribution to the transaction auth_digest.
    ///
    /// **This is NOT the same as a stripped bundle.**
    ///
    /// **This is NOT the same as a bundle with no actions and zero balance.**
    pub static ref AUTH_DIGEST_NO_BUNDLE: [u8; 64] = {
        *Params::new()
            .hash_length(64)
            .personal(AUTH_DIGEST_PERSONALIZATION)
            .to_state()
            .finalize()
            .as_array()
    };
}
