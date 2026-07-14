//! Tachyon Blake2b digests.
//!
//! Each named function matches one protocol-defined hash. Key and entropy
//! derivation preimages use BLAKE2b-512 (64-byte output, reduced to scalars
//! by the caller); transaction digest contributions use BLAKE2b-256
//! (32-byte output), matching the ZIP 244 digest-tree convention.
//! Personalizations are 13–16 bytes; `blake2b_simd::Params::personal`
//! accepts any length ≤ 16.

use blake2b_simd::Params;
use lazy_static::lazy_static;

/// BLAKE2b-256 digest for transaction digest contributions (ZIP 244 leaves).
///
/// `updater` feeds the preimage into the personalized state.
fn hasher_256(personalization: &[u8], updater: impl FnOnce(&mut blake2b_simd::State)) -> [u8; 32] {
    let mut state = Params::new()
        .hash_length(32)
        .personal(personalization)
        .to_state();
    updater(&mut state);

    #[expect(clippy::expect_used, reason = "hash length is 32")]
    state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("hash length is 32")
}

/// BLAKE2b-512 digest for key and entropy derivation preimages.
///
/// `updater` feeds the preimage into the personalized state.
fn hasher_512(personalization: &[u8], updater: impl FnOnce(&mut blake2b_simd::State)) -> [u8; 64] {
    let mut state = Params::new()
        .hash_length(64)
        .personal(personalization)
        .to_state();
    updater(&mut state);

    #[expect(clippy::expect_used, reason = "hash length is 64")]
    state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("hash length is 64")
}

const SPEND_ALPHA_PERSONALIZATION: &[u8; 13] = b"Tachyon-Spend";
const OUTPUT_ALPHA_PERSONALIZATION: &[u8; 14] = b"Tachyon-Output";

/// Spend-side $\alpha$ pre-image: $\text{BLAKE2b-512}(\text{"Tachyon-Spend"},
/// \theta \| cm)$.
///
/// Caller reduces to scalar via `Fq::from_uniform_bytes`.
pub(crate) fn alpha_spend(theta: &[u8; 32], cm: &[u8; 32]) -> [u8; 64] {
    hasher_512(SPEND_ALPHA_PERSONALIZATION, |state| {
        state.update(theta);
        state.update(cm);
    })
}

/// Output-side $\alpha$ pre-image: $\text{BLAKE2b-512}(\text{"Tachyon-Output"},
/// \theta \| cm)$.
pub(crate) fn alpha_output(theta: &[u8; 32], cm: &[u8; 32]) -> [u8; 64] {
    hasher_512(OUTPUT_ALPHA_PERSONALIZATION, |state| {
        state.update(theta);
        state.update(cm);
    })
}

// See https://github.com/zcash/zcash_spec/blob/main/src/prf_expand.rs
const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";
const PRF_EXPAND_DOMAIN_ASK: u8 = 0x21;
const PRF_EXPAND_DOMAIN_NK: u8 = 0x22;

/// PRF-expand to derive `ask` from a spending key. Performs no normalization.
///
/// $\text{BLAKE2b-512}(\text{"Zcash\_ExpandSeed"}, sk \|
/// \texttt{ASK_DOMAIN_BYTE})$. Mirrors Zcash §5.4.2.
///
/// TODO: return normalized Fq?
pub(crate) fn prf_expand_ask(sk: &[u8; 32]) -> [u8; 64] {
    hasher_512(PRF_EXPAND_PERSONALIZATION, |state| {
        state.update(sk);
        state.update(&[PRF_EXPAND_DOMAIN_ASK]);
    })
}

/// PRF-expand to derive `nk` from a spending key. Performs no normalization.
///
/// $\text{BLAKE2b-512}(\text{"Zcash\_ExpandSeed"}, sk \|
/// \texttt{NK_DOMAIN_BYTE})$.
///
/// TODO: return normalized Fq?
pub(crate) fn prf_expand_nk(sk: &[u8; 32]) -> [u8; 64] {
    hasher_512(PRF_EXPAND_PERSONALIZATION, |state| {
        state.update(sk);
        state.update(&[PRF_EXPAND_DOMAIN_NK]);
    })
}

const ACTION_DESCRIPTOR_PERSONALIZATION: &[u8; 15] = b"Tachyon-Actions";

/// Digest of action descriptors.
///
/// Over the bundle's owned actions this is `hActionsTachyon`, committed on the
/// txid side by [`bundle_commitment`]; over a stamp's covered actions it is the
/// stamp's `hStampActionsTachyon`.
///
/// $$ \text{BLAKE2b-256}(
/// \text{"Tachyon-Actions"},\;
/// \mathsf{cv}_i \| \mathsf{rk}_i) $$
///
/// Each entry is a 64-byte concatenation of `cv || rk` field encodings. Entries
/// are hashed in the order given, so the digest commits to that order; callers
/// pass a canonically (byte-lexicographically) sorted slice.
pub(crate) fn action_descriptor_digest(descriptors: &[[u8; 64]]) -> [u8; 32] {
    hasher_256(ACTION_DESCRIPTOR_PERSONALIZATION, |state| {
        for descriptor in descriptors {
            state.update(descriptor);
        }
    })
}

// See https://github.com/zcash/orchard/blob/main/src/bundle/commitments.rs
const BUNDLE_COMMITMENT_PERSONALIZATION: &[u8; 16] = b"ZTxIdTachyonHash";
const AUTH_DIGEST_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTachyHash";

/// A bundle's contribution to the transaction sighash.
///
/// Hashes the bundle's effecting data: the [`action_descriptor_digest`] of its
/// own actions and the value balance. The stamp is excluded because it is
/// stripped during aggregation.
#[must_use]
pub(crate) fn bundle_commitment(action_commit: &[u8; 32], value_balance: i64) -> [u8; 32] {
    hasher_256(BUNDLE_COMMITMENT_PERSONALIZATION, |state| {
        state.update(action_commit);
        state.update(&value_balance.to_le_bytes());
    })
}

const STAMP_DATA_PERSONALIZATION: &[u8; 13] = b"Tachyon-Stamp";
const STAMP_PROOF_PERSONALIZATION: &[u8; 13] = b"Tachyon-Proof";

/// Digest of a stamp's proof.
///
/// $$ \mathsf{stamp\_proof\_digest} = \text{BLAKE2b-256}(
/// \text{"Tachyon-Proof"},\; \mathsf{proofTachyon}) $$
pub(crate) fn stamp_proof_digest(proof: &[u8]) -> [u8; 32] {
    hasher_256(STAMP_PROOF_PERSONALIZATION, |state| {
        state.update(proof);
    })
}

/// Digest of a proof stamp's proof, anchor, and tachygrams.
///
/// $$ \mathsf{stamp\_data\_digest} = \text{BLAKE2b-256}(
/// \text{"Tachyon-Stamp"},\;
/// \mathsf{stamp\_proof\_digest} \| \mathsf{anchor} \|
/// \mathsf{vTachygrams}) $$
///
/// Tachygrams are hashed in the order given, so the digest commits to that
/// order; callers pass a canonically (byte-lexicographically) sorted slice.
pub(crate) fn stamp_data_digest(
    stamp_proof_digest: [u8; 32],
    anchor: [u8; 32],
    tachygrams: &[[u8; 32]],
) -> [u8; 32] {
    hasher_256(STAMP_DATA_PERSONALIZATION, |state| {
        state.update(&stamp_proof_digest);
        state.update(&anchor);

        // only variable-length component
        for tg in tachygrams {
            state.update(tg);
        }
    })
}

/// A bundle's contribution to the transaction auth_digest.
///
/// $$ \text{BLAKE2b-256}(\text{"ZTxAuthTachyHash"},\;
/// \mathsf{tachyonBundleState} \| \mathsf{vActionSigs} \| \mathsf{bindingSig}
/// \| \mathsf{stamp}) $$
///
/// The action set enters this digest only through `stamp`, whose proof-stamp
/// form concatenates the covered actions' descriptor digest with
/// [`stamp_data_digest`]. The bundle's own action descriptors are committed on
/// the txid side by [`bundle_commitment`], not here.
///
/// `state_header` is `tachyonBundleState` 0x01 or 0x02, indicating the content
/// of the stamp contribution which is either:
/// - 0x01: proof stamp, digests `hStampActionsTachyon || stamp_data_digest`
/// - 0x02: pointer stamp, aggregate's wtxid `txid || auth_digest`
pub(crate) fn bundle_auth_digest(
    state_header: u8,
    action_sigs: &[[u8; 64]],
    binding_sig: &[u8; 64],
    stamp_contrib: &[u8; 64],
) -> [u8; 32] {
    hasher_256(AUTH_DIGEST_PERSONALIZATION, |state| {
        state.update(&[state_header]);
        // only variable-length component
        for sig in action_sigs {
            state.update(sig);
        }
        state.update(binding_sig);
        state.update(stamp_contrib);
    })
}

lazy_static! {
    /// A non-Tachyon transaction's contribution to the transaction sighash.
    ///
    /// **This is NOT the same as a stripped bundle.**
    ///
    /// **This is NOT the same as a bundle with no actions and zero balance.**
    pub static ref COMMIT_NO_BUNDLE: [u8; 32] = {
        hasher_256(BUNDLE_COMMITMENT_PERSONALIZATION, |_| {})
    };

    /// A non-Tachyon transaction's contribution to the transaction auth_digest.
    ///
    /// **This is NOT the same as a bundle with no actions and zero balance.**
    pub static ref AUTH_DIGEST_NO_BUNDLE: [u8; 32] = {
        hasher_256(AUTH_DIGEST_PERSONALIZATION, |_| {})
    };
}
