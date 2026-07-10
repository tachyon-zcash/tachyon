//! Tachyon Blake2b digests.
//!
//! Each named function matches one protocol-defined hash. Key and entropy
//! derivation preimages use BLAKE2b-512 (64-byte output, reduced to scalars
//! by the caller); transaction digest contributions use BLAKE2b-256
//! (32-byte output), matching the ZIP 244 digest-tree convention.
//! Personalizations are 13–16 bytes; `blake2b_simd::Params::personal`
//! accepts any length ≤ 16.

use alloc::vec::Vec;

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

// See https://github.com/zcash/orchard/blob/main/src/bundle/commitments.rs
const BUNDLE_COMMITMENT_PERSONALIZATION: &[u8; 16] = b"ZTxIdTachyonHash";
const AUTH_DIGEST_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTachyHash";

/// A bundle's contribution to the transaction sighash.
///
/// Hashes the bundle's effecting data: the encoding of the action-set
/// commitment and the value balance. The stamp is excluded because it is
/// stripped during aggregation.
#[must_use]
pub(crate) fn bundle_commitment(action_commit: &[u8; 32], value_balance: i64) -> [u8; 32] {
    hasher_256(BUNDLE_COMMITMENT_PERSONALIZATION, |state| {
        state.update(action_commit);
        state.update(&value_balance.to_le_bytes());
    })
}

const STAMP_ACTIONS_PERSONALIZATION: &[u8; 16] = b"Tachyon-StampAct";
const STAMP_DATA_PERSONALIZATION: &[u8; 13] = b"Tachyon-Stamp";
const STAMP_PROOF_PERSONALIZATION: &[u8; 13] = b"Tachyon-Proof";

/// Digest of a stamp's covered action descriptors (`hActionsTachyon`).
///
/// $$ \mathsf{hActionsTachyon} = \text{BLAKE2b-256}(
/// \text{"Tachyon-StampAct"},\;
/// \mathsf{sorted}(\mathsf{cv}_i \| \mathsf{rk}_i)) $$
///
/// Each entry is a 64-byte `cv || rk` field encoding. Entries are sorted
/// byte-lexicographically before hashing: the digest commits to the
/// covered-action multiset.
pub(crate) fn stamp_actions_digest(descriptors: &[[u8; 64]]) -> [u8; 32] {
    let mut sorted: Vec<&[u8; 64]> = descriptors.iter().collect();
    sorted.sort_unstable();
    hasher_256(STAMP_ACTIONS_PERSONALIZATION, |state| {
        for descriptor in sorted {
            state.update(descriptor);
        }
    })
}

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
/// \mathsf{sorted}(\mathsf{vTachygrams})) $$
///
/// Tachygrams are sorted byte-lexicographically before hashing: the digest
/// commits to the tachygram multiset.
pub(crate) fn stamp_data_digest(
    stamp_proof_digest: [u8; 32],
    anchor: [u8; 32],
    tachygrams: &[[u8; 32]],
) -> [u8; 32] {
    let mut sorted: Vec<&[u8; 32]> = tachygrams.iter().collect();
    sorted.sort_unstable();
    hasher_256(STAMP_DATA_PERSONALIZATION, |state| {
        state.update(&stamp_proof_digest);
        state.update(&anchor);
        for tg in sorted {
            state.update(tg);
        }
    })
}

/// A bundle's contribution to the transaction auth_digest.
///
/// $$ \text{BLAKE2b-256}(\text{"ZTxAuthTachyHash"},\;
/// \mathsf{vActionSigs} \| \mathsf{bindingSig} \| \mathsf{stamp}) $$
///
/// `stamp` is the 64-byte wtxid-shaped stamp digest:
///
/// - proof stamp: `hActionsTachyon || stamp_data_digest`, see
///   [`stamp_actions_digest`] and [`stamp_data_digest`];
/// - pointer stamp: the covering aggregate's `wtxid = txid || auth_digest`.
///
/// Each variable-length component reaches this preimage through its own
/// personalized sub-digest, except the action signatures: their count is
/// recovered by length arithmetic (64-byte elements before a fixed
/// 128-byte suffix) and pinned on the txid side by `action_acc`'s monic
/// degree — the role `nActionsOrchard` plays in ZIP 244.
pub(crate) fn auth_digest(
    action_sigs: &[[u8; 64]],
    binding_sig: &[u8; 64],
    stamp: &[u8; 64],
) -> [u8; 32] {
    hasher_256(AUTH_DIGEST_PERSONALIZATION, |state| {
        for sig in action_sigs {
            state.update(sig);
        }
        state.update(binding_sig);
        state.update(stamp);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Moving 32 bytes across the tachygram/proof boundary changes
    /// `stamp_data_digest`.
    #[test]
    fn tachygram_proof_boundary() {
        let anchor = [0x11u8; 32];
        let tg = [0x22u8; 32];
        let proof = [0x33u8; 100];

        let split = stamp_data_digest(stamp_proof_digest(&proof), anchor, &[tg]);

        let mut moved = Vec::from(tg);
        moved.extend_from_slice(&proof);
        let joined = stamp_data_digest(stamp_proof_digest(&moved), anchor, &[]);

        assert_ne!(split, joined);
    }

    /// Sorted digests are permutation-invariant and element-sensitive.
    #[test]
    fn sorted_multiset_digests() {
        let (desc_a, desc_b) = ([0xAAu8; 64], [0xBBu8; 64]);
        assert_eq!(
            stamp_actions_digest(&[desc_a, desc_b]),
            stamp_actions_digest(&[desc_b, desc_a])
        );
        assert_ne!(
            stamp_actions_digest(&[desc_a, desc_b]),
            stamp_actions_digest(&[desc_a, desc_a])
        );

        let (tg_a, tg_b) = ([0xCCu8; 32], [0xDDu8; 32]);
        let (proof, anchor) = (stamp_proof_digest(&[]), [0u8; 32]);
        assert_eq!(
            stamp_data_digest(proof, anchor, &[tg_a, tg_b]),
            stamp_data_digest(proof, anchor, &[tg_b, tg_a])
        );
        assert_ne!(
            stamp_data_digest(proof, anchor, &[tg_a, tg_b]),
            stamp_data_digest(proof, anchor, &[tg_a, tg_a])
        );
    }

    /// Personalization separates the empty digests of every node.
    #[test]
    fn empty_digests_distinct() {
        let empties = [
            *COMMIT_NO_BUNDLE,
            *AUTH_DIGEST_NO_BUNDLE,
            stamp_actions_digest(&[]),
            stamp_proof_digest(&[]),
        ];
        for (i, x) in empties.iter().enumerate() {
            for y in &empties[i + 1..] {
                assert_ne!(x, y);
            }
        }
    }

    /// The no-bundle value differs from a zero-action bundle's contribution.
    #[test]
    fn no_bundle_differs_from_zero_action_bundle() {
        let contribution = auth_digest(&[], &[0u8; 64], &[0x42u8; 64]);
        assert_ne!(*AUTH_DIGEST_NO_BUNDLE, contribution);
    }
}
