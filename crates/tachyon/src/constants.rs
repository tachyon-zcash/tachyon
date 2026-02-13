//! Protocol-wide domain separators and personalizations.
//!
//! All BLAKE2b personalizations are exactly 16 bytes (the BLAKE2b
//! personal field width). Hash-to-curve and Poseidon domains use
//! variable-length strings under the `z.cash:` namespace.

// =============================================================================
// BLAKE2b personalizations (16 bytes)
// =============================================================================

/// BLAKE2b-512 personalization for `PRF^expand`: key expansion from
/// a spending key to child keys (`ask`, `nk`, `pk`).
///
/// Matches Zcash's `PRF^expand` pattern (§5.4.2 of the protocol spec).
pub const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";

/// BLAKE2b-512 personalization for the binding sighash.
///
/// Tachyon-specific: the binding sighash covers `(cv, rk, sig)` tuples
/// and value balance, but NOT the stamp (which is stripped during
/// aggregation).
pub const BINDING_SIGHASH_PERSONALIZATION: &[u8; 16] = b"Tachyon-BindHash";

// =============================================================================
// Hash-to-curve / commitment domains
// =============================================================================

/// Domain for value commitment generators `V` and `R`.
///
/// Shared with Orchard to reuse `reddsa::orchard::Binding` — same
/// generators, same basepoint, same binding signature verification.
pub const VALUE_COMMITMENT_DOMAIN: &str = "z.cash:Orchard-cv";

/// Domain for nullifier derivation (Poseidon).
pub const NULLIFIER_DOMAIN: &str = "z.cash:Tachyon-nf";

/// Domain for note commitments.
pub const NOTE_COMMITMENT_DOMAIN: &str = "z.cash:Tachyon-NoteCommit";

/// Domain for the polynomial accumulator hash-to-curve.
pub const ACCUMULATOR_DOMAIN: &str = "z.cash:Tachyon-acc";
