//! Tachyon Blake2b digests.
//!
//! Each named function provides one protocol-defined hash.

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

/// BLAKE2b-512 digest for key derivation preimages.
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

// See https://github.com/zcash/zcash_spec/blob/main/src/prf_expand.rs
const PRF_EXPAND_PERSONALIZATION: &[u8; 16] = b"Zcash_ExpandSeed";
const PRF_EXPAND_DOMAIN_ASK: u8 = 0x21;
const PRF_EXPAND_DOMAIN_NK: u8 = 0x22;

/// PRF-expand to derive `ask` from a spending key. Performs no normalization.
///
/// $$
///   \text{BLAKE2b-512}_\texttt{Zcash\\_ExpandSeed}(
///     sk \Vert \texttt{0x21}
///   )
/// $$
///
/// Mirrors Zcash §5.4.2.
///
/// TODO: return normalized Fq?
#[must_use]
pub fn prf_expand_ask(sk: &[u8; 32]) -> [u8; 64] {
    hasher_512(PRF_EXPAND_PERSONALIZATION, |state| {
        state.update(sk);
        state.update(&[PRF_EXPAND_DOMAIN_ASK]);
    })
}

/// PRF-expand to derive `nk` from a spending key. Performs no normalization.
///
/// $$
///   \text{BLAKE2b-512}_\texttt{Zcash\\_ExpandSeed}(
///     sk \Vert \texttt{0x22}
///   )
/// $$
///
/// TODO: return normalized Fq?
#[must_use]
pub fn prf_expand_nk(sk: &[u8; 32]) -> [u8; 64] {
    hasher_512(PRF_EXPAND_PERSONALIZATION, |state| {
        state.update(sk);
        state.update(&[PRF_EXPAND_DOMAIN_NK]);
    })
}

const ACTION_DESCRIPTOR_PERSONALIZATION: &[u8; 15] = b"Tachyon-Actions";

/// Digest of action descriptors.
///
/// Action descriptors are hashed in the order given, so the digest commits to
/// that order.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{Tachyon-Actions}(
///     \mathsf{cv}_i \Vert \mathsf{rk}_i
///   )
/// $$
///
/// Over a bundle's actions this is `hActionsTachyon`.
#[must_use]
pub fn action_descriptor_digest(descriptors: &[[u8; 64]]) -> [u8; 32] {
    hasher_256(ACTION_DESCRIPTOR_PERSONALIZATION, |state| {
        for descriptor in descriptors {
            state.update(descriptor);
        }
    })
}

const MEMO_PERSONALIZATION: &[u8; 12] = b"Tachyon-Memo";

/// Digest of a bundle's memo payload.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{Tachyon-Memo}(
///     \mathsf{vMemoTachyon}
///   )
/// $$
///
/// This is `hMemoTachyon`. Hashing the payload to a fixed width here is what
/// lets [`bundle_commitment`] absorb it without a length prefix.
#[must_use]
pub fn memo_digest(memo: &[u8]) -> [u8; 32] {
    hasher_256(MEMO_PERSONALIZATION, |state| {
        state.update(memo);
    })
}

// See https://github.com/zcash/orchard/blob/main/src/bundle/commitments.rs
const BUNDLE_COMMITMENT_PERSONALIZATION: &[u8; 16] = b"ZTxIdTachyonHash";
const AUTH_DIGEST_PERSONALIZATION: &[u8; 16] = b"ZTxAuthTachyHash";

/// A bundle's contribution to the transaction sighash.
///
/// Only digests effecting data.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{ZTxIdTachyonHash}(
///     \mathsf{hActionsTachyon} \Vert \mathsf{valueBalanceTachyon} \Vert
///     \mathsf{cvFeeMaxTachyon} \Vert \mathsf{hMemoTachyon}
///   )
/// $$
///
/// The stamp and the fee are excluded because they are mutable auth data. The
/// memo is included because it is effecting: relayers rewrite `auth_digest`
/// during aggregation, so only the sighash can hold a payload a miner must not
/// strip.
#[must_use]
pub fn bundle_commitment(
    action_commit: &[u8; 32],
    value_balance: i64,
    cv_feemax: &[u8; 32],
    memo_digest: &[u8; 32],
) -> [u8; 32] {
    hasher_256(BUNDLE_COMMITMENT_PERSONALIZATION, |state| {
        state.update(action_commit);
        state.update(&value_balance.to_le_bytes());
        state.update(cv_feemax);
        state.update(memo_digest);
    })
}

const STAMP_PERSONALIZATION: &[u8; 13] = b"Tachyon-Stamp";
const STAMP_PROOF_PERSONALIZATION: &[u8; 13] = b"Tachyon-Proof";

/// `hStampProofTachyon`, the stamp proof, the anchor and the tachygram set
/// commitment. A verifier rebuilds the stamp proof's header from the last two.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{Tachyon-Proof}(
///     \mathsf{anchorTachyon} \Vert
///     \mathsf{cTachygrams} \Vert
///     \mathsf{proofTachyon}
///   )
/// $$
#[must_use]
pub fn stamp_proof_digest(anchor: [u8; 32], tachygram_set: [u8; 32], proof: &[u8]) -> [u8; 32] {
    hasher_256(STAMP_PROOF_PERSONALIZATION, |state| {
        state.update(&anchor);
        state.update(&tachygram_set);
        // only variable-length component
        state.update(proof);
    })
}

/// `hStampTachyon` for a proof stamp.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{Tachyon-Stamp}(
///     \mathsf{vAdjunctsTachyon} \Vert
///     \mathsf{hStampProofTachyon}
///   )
/// $$
///
/// Adjunct txids are hashed in the order given, without a count. The list is
/// empty for an autonome. A stripped stamp instead uses [`STAMP_DIGEST_EMPTY`].
#[must_use]
pub fn stamp_digest(adjuncts: &[[u8; 32]], stamp_proof_digest: &[u8; 32]) -> [u8; 32] {
    hasher_256(STAMP_PERSONALIZATION, |state| {
        // only variable-length component
        for txid in adjuncts {
            state.update(txid);
        }
        state.update(stamp_proof_digest);
    })
}

/// A bundle's contribution to the transaction auth_digest.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{ZTxAuthTachyHash}(
///     \mathsf{tachyonBundleState} \Vert
///     (\mathsf{sig}_i \Vert \mathsf{tg}_{i,0} \Vert \mathsf{tg}_{i,1})_i \Vert
///     \mathsf{LE64}(\mathsf{vFeeTachyon}) \Vert \mathsf{cmChangeTachyon} \Vert
///     \mathsf{bindingSigTachyon} \Vert \mathsf{hStampTachyon}
///   )
/// $$
///
/// Each 128-byte record projects one action's signature and tachygram pair,
/// preserving the pair's wire order. Records are hashed in the order given,
/// without a count; they are the only variable-length input.
#[must_use]
pub fn bundle_auth_digest(
    state_header: u8,
    action_auth: &[[u8; 128]],
    fee: u64,
    cm_change: &[u8; 32],
    binding_sig: &[u8; 64],
    stamp_digest: &[u8; 32],
) -> [u8; 32] {
    hasher_256(AUTH_DIGEST_PERSONALIZATION, |state| {
        state.update(&[state_header]);
        // only variable-length component
        for record in action_auth {
            state.update(record);
        }
        state.update(&fee.to_le_bytes());
        state.update(cm_change);
        state.update(binding_sig);
        state.update(stamp_digest);
    })
}

lazy_static! {
    /// A non-Tachyon transaction's contribution to the transaction sighash.
    ///
    /// $$
    ///   \text{BLAKE2b-256}_\texttt{ZTxIdTachyonHash}()
    /// $$
    ///
    /// **This is NOT the same as a bundle with no actions and zero balance.**
    pub static ref COMMIT_NO_BUNDLE: [u8; 32] = {
        hasher_256(BUNDLE_COMMITMENT_PERSONALIZATION, |_| {})
    };

    /// A non-Tachyon transaction's contribution to the transaction auth_digest.
    ///
    /// $$
    ///   \text{BLAKE2b-256}_\texttt{ZTxAuthTachyHash}()
    /// $$
    ///
    /// **This is NOT the same as a bundle with no actions and zero balance.**
    pub static ref AUTH_DIGEST_NO_BUNDLE: [u8; 32] = {
        hasher_256(AUTH_DIGEST_PERSONALIZATION, |_| {})
    };

    /// `hStampTachyon` for a stripped stamp: the hash of the empty input.
    ///
    /// $$
    ///   \text{BLAKE2b-256}_\texttt{Tachyon-Stamp}()
    /// $$
    ///
    /// This differs from [`stamp_digest`] with an empty adjunct list, which
    /// still absorbs a proof digest.
    pub static ref STAMP_DIGEST_EMPTY: [u8; 32] = {
        hasher_256(STAMP_PERSONALIZATION, |_| {})
    };
}

#[cfg(test)]
mod tests {
    use super::{STAMP_DIGEST_EMPTY, bundle_auth_digest, stamp_digest, stamp_proof_digest};

    // Expected bytes were computed independently using Python's hashlib.blake2b.
    #[test]
    fn stamp_digest_vectors() {
        let proof = stamp_proof_digest([0x11; 32], [0x22; 32], &[0x33, 0x44, 0x55]);
        assert_eq!(
            proof,
            [
                0x4d, 0x08, 0x6d, 0x7d, 0x0c, 0x5b, 0x50, 0x82, 0x65, 0x99, 0xa2, 0x3b, 0x07, 0x8e,
                0xa9, 0xd9, 0xbc, 0x62, 0xcc, 0x99, 0x96, 0xcc, 0xe2, 0x03, 0x48, 0xa3, 0x75, 0x27,
                0x52, 0xda, 0x07, 0x93,
            ]
        );
        assert_eq!(
            stamp_digest(&[[0x66; 32], [0x77; 32]], &proof),
            [
                0x53, 0x22, 0x91, 0x26, 0x22, 0xf5, 0x0f, 0x2b, 0x4e, 0x46, 0x00, 0xb6, 0xbc, 0xf1,
                0x1f, 0xfe, 0x9f, 0x8d, 0x25, 0xef, 0x07, 0xc0, 0xbb, 0x17, 0x76, 0x5c, 0xc0, 0xcf,
                0x12, 0xa9, 0xcd, 0x81,
            ]
        );
        assert_eq!(
            stamp_digest(&[], &proof),
            [
                0x13, 0xcb, 0x9b, 0x1f, 0x5d, 0xee, 0x18, 0x99, 0x89, 0x6c, 0xbd, 0x47, 0xfd, 0xe4,
                0x26, 0xde, 0x28, 0xc2, 0xf3, 0x54, 0x8e, 0x76, 0xe2, 0xba, 0x93, 0xc1, 0x23, 0xd7,
                0x36, 0x27, 0x61, 0xc6,
            ]
        );
        assert_eq!(
            *STAMP_DIGEST_EMPTY,
            [
                0x60, 0x48, 0x6f, 0x8f, 0x4c, 0xe1, 0xe4, 0xe3, 0x24, 0x1e, 0x27, 0x69, 0x63, 0x1e,
                0xbe, 0xd5, 0xe0, 0x10, 0xfa, 0xe2, 0x8b, 0xbf, 0xce, 0xa2, 0x02, 0xf8, 0xc6, 0x6b,
                0xd9, 0x65, 0x82, 0x47,
            ]
        );
    }

    #[test]
    fn bundle_auth_digest_vectors() {
        let proof = stamp_proof_digest([0x11; 32], [0x22; 32], &[0x33, 0x44, 0x55]);
        let stamp = stamp_digest(&[[0x66; 32], [0x77; 32]], &proof);
        let mut records = [[0x88; 128], [0xdd; 128]];
        records[0][64..96].fill(0x99);
        records[0][96..].fill(0xaa);
        records[1][64..96].fill(0xee);
        records[1][96..].fill(0xff);
        let digest = bundle_auth_digest(
            0x01,
            &records,
            0x0102_0304_0506_0708,
            &[0xbb; 32],
            &[0xcc; 64],
            &stamp,
        );
        assert_eq!(
            digest,
            [
                0x07, 0x3f, 0xda, 0x7e, 0x5b, 0x23, 0xad, 0x7f, 0x1d, 0x9b, 0xcd, 0xdb, 0xa3, 0x16,
                0x17, 0xb1, 0x8d, 0xad, 0x14, 0xcf, 0x5c, 0x9f, 0xaf, 0xa6, 0x3c, 0x1c, 0x89, 0x88,
                0x1e, 0x48, 0x34, 0x41,
            ]
        );

        assert_eq!(
            bundle_auth_digest(0x02, &[], 0, &[0xbb; 32], &[0xcc; 64], &STAMP_DIGEST_EMPTY),
            [
                0x92, 0x3b, 0x50, 0x85, 0x15, 0x37, 0xb2, 0x27, 0xcb, 0x23, 0xe7, 0x02, 0x1a, 0xdc,
                0x19, 0xd9, 0x8c, 0x9c, 0x2e, 0xe4, 0x7a, 0x1f, 0x90, 0x96, 0x4b, 0x84, 0xb8, 0xdf,
                0xd6, 0x57, 0x62, 0xa4,
            ]
        );
    }
}
