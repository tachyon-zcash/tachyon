//! Tachyon Blake2b digests.
//!
//! Each named function matches one protocol-defined hash. All use
//! BLAKE2b-512 (64-byte output). Personalizations are 13–16 bytes;
//! `blake2b_simd::Params::personal` accepts any length ≤ 16.

use blake2b_simd::Params;

const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";
pub(crate) const BUNDLE_COMMITMENT_PERSONALIZATION: &[u8; 16] = b"Tachyon-BndlHash";
pub(crate) const AUTH_DIGEST_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTachyHash";
const SPEND_ALPHA_PERSONALIZATION: &[u8; 13] = b"Tachyon-Spend";
const OUTPUT_ALPHA_PERSONALIZATION: &[u8; 14] = b"Tachyon-Output";

// Domain separators 0x00–0x05 are Sapling, 0x06–0x08 are Orchard.
// Tachyon allocates 0x09+ to avoid collisions.
const ASK_DOMAIN_BYTE: u8 = 0x09;
const NK_DOMAIN_BYTE: u8 = 0x0a;

/// PRF-expand to derive `ask` from a spending key.
///
/// $\text{BLAKE2b-512}(\text{"Zcash\_ExpandSeed"}, sk \| \texttt{0x09})$.
/// Mirrors Zcash §5.4.2.
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

/// PRF-expand to derive `nk` from a spending key.
///
/// $\text{BLAKE2b-512}(\text{"Zcash\_ExpandSeed"}, sk \| \texttt{0x0a})$.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Same key, different domain separators -> different outputs.
    /// This is the core property that makes child key derivation safe.
    #[test]
    fn prf_expand_domain_separators_independent() {
        let sk = [0x42u8; 32];
        assert_ne!(prf_expand_ask(&sk), prf_expand_nk(&sk));
    }
}
