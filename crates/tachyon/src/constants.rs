//! Protocol-wide domain separators and personalizations.
//!
//! All BLAKE2b personalizations are exactly 16 bytes (the BLAKE2b
//! personal field width). Hash-to-curve and Poseidon domains use
//! variable-length strings under the `z.cash:` namespace.

/// BLAKE2b-512 personalization for `PRF^expand`: key expansion from
/// a spending key to child keys (`ask`, `nk`).
///
/// Matches Zcash's `PRF^expand` pattern (§5.4.2 of the protocol spec).
pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

/// BLAKE2b-512 personalization for the bundle commitment.
///
/// $$\mathsf{bundle\_commitment} =
/// \text{BLAKE2b-512}(\text{"Tachyon-BndlHash"},\;   \mathsf{action\_acc} \|
/// \mathsf{value\_balance})$$
///
/// Commits to the bundle's effecting data. The digest contributes to the
/// transaction-level sighash, which is what signatures actually sign.
pub const BUNDLE_COMMITMENT_PERSONALIZATION: &[u8; 16] = b"Tachyon-BndlHash";

/// BLAKE2b-512 personalization for spend-side alpha derivation.
///
/// $$\alpha_{\text{spend}} = \text{ToScalar}(\text{BLAKE2b-512}(
/// \text{"Tachyon-Spend"},\; \theta \| \mathsf{cm}))$$
///
/// Domain-separated from output alpha to prevent cross-context reuse.
pub const SPEND_ALPHA_PERSONALIZATION: &[u8; 13] = b"Tachyon-Spend";

/// BLAKE2b-512 personalization for output-side alpha derivation.
///
/// $$\alpha_{\text{output}} = \text{ToScalar}(\text{BLAKE2b-512}(
/// \text{"Tachyon-Output"},\; \theta \| \mathsf{cm}))$$
///
/// Domain-separated from spend alpha to prevent cross-context reuse.
pub const OUTPUT_ALPHA_PERSONALIZATION: &[u8; 14] = b"Tachyon-Output";

/// Domain for value commitment generators `V` and `R`.
///
/// Shared with Orchard to reuse `reddsa::orchard::Binding` — same
/// generators, same basepoint, same binding signature verification.
pub const VALUE_COMMITMENT_DOMAIN: &str = "z.cash:Orchard-cv";

/// Poseidon domain tag for note master derivation: $mk = \text{KDF}(\psi, nk)$.
pub const NOTE_MASTER_DOMAIN: &[u8; 16] = b"Tachyon-MkDerive";

/// Poseidon domain tag for nullifier derivation (GGM tree steps).
pub const NOTE_NULLIFIER_DOMAIN: &[u8; 16] = b"Tachyon-NfDerive";

/// Poseidon domain tag for note commitments.
pub const NOTE_COMMITMENT_DOMAIN: &[u8; 16] = b"Tachyon-NoteCmmt";

/// Poseidon domain tag for note identity binding: `H(domain, mk, cm)`.
pub const NOTE_ID_DOMAIN: &[u8; 16] = b"Tachyon-NoteMkCm";

/// Poseidon domain tag for action digests.
pub const ACTION_DIGEST_PERSONALIZATION: &[u8; 16] = b"Tachyon-ActnDgst";

/// Poseidon domain tag for payment key derivation: $pk =
/// \text{Poseidon}(\text{domain}, ak_x, nk)$.
pub const PAYMENT_KEY_DOMAIN: &[u8; 16] = b"Tachyon-PkDerive";

/// Maximum note value in zatoshis (§5.3 of the protocol spec)
pub const NOTE_VALUE_MAX: u64 = 2_100_000_000_000_000;

/// Domain-separated key expansion from a spending key.
///
/// `PRF^expand_sk(t) = BLAKE2b-512("Zcash_ExpandSeed", sk || t)`
///
/// Mirrors `zcash_spec::PrfExpand`: a struct with a single-byte domain
/// separator and associated constants for each child key derivation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PrfExpand {
    domain_separator: u8,
}

impl PrfExpand {
    // Domain separators 0x00–0x05 are Sapling, 0x06–0x08 are Orchard.
    // Tachyon allocates 0x09+ to avoid collisions.

    /// `[0x09]` -> `ask` (spend authorizing key, scalar field)
    pub(crate) const ASK: Self = Self {
        domain_separator: 0x09,
    };
    /// `[0x0a]` -> `nk` (nullifier key, base field)
    pub(crate) const NK: Self = Self {
        domain_separator: 0x0a,
    };

    /// Evaluate the PRF: `BLAKE2b-512("Zcash_ExpandSeed", sk || domain_sep)`.
    ///
    /// Returns 64 bytes suitable for unbiased reduction into either field
    /// via `FromUniformBytes`.
    pub(crate) fn with(self, sk: &[u8; 32]) -> [u8; 64] {
        *blake2b_simd::Params::new()
            .hash_length(64)
            .personal(PRF_EXPAND_PERSONALIZATION)
            .to_state()
            .update(sk)
            .update(&[self.domain_separator])
            .finalize()
            .as_array()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same key, different domain separators -> different outputs.
    /// This is the core property that makes child key derivation safe.
    #[test]
    fn prf_expand_domain_separators_independent() {
        let sk = [0x42u8; 32];
        let ask = PrfExpand::ASK.with(&sk);
        let nk = PrfExpand::NK.with(&sk);
        assert_ne!(ask, nk);
    }
}
