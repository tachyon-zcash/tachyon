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

/// Spend-side $\alpha$ pre-image.
///
/// $$
///   \text{BLAKE2b-512}_\texttt{Tachyon-Spend}(
///     \theta \Vert cm
///   )
/// $$
///
/// Caller reduces to scalar via `Fq::from_uniform_bytes`.
#[must_use]
pub fn alpha_spend(theta: &[u8; 32], cm: &[u8; 32]) -> [u8; 64] {
    hasher_512(SPEND_ALPHA_PERSONALIZATION, |state| {
        state.update(theta);
        state.update(cm);
    })
}

/// Output-side $\alpha$ pre-image.
///
/// $$
///   \text{BLAKE2b-512}_\texttt{Tachyon-Output}(
///     \theta \Vert cm
///   )
/// $$
#[must_use]
pub fn alpha_output(theta: &[u8; 32], cm: &[u8; 32]) -> [u8; 64] {
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
///
/// Over a stamp's covered actions this is `hStampActionsTachyon`.
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

const TACHYGRAM_CHAIN_PERSONALIZATION: &[u8; 15] = b"Tachyon-TgChain";

/// One step of a tachygram list's chain digest.
///
/// $$
///   d_{i+1} = \text{BLAKE2b-256}_\texttt{Tachyon-TgChain}(
///     d_i \Vert \mathsf{tg}_i
///   )
/// $$
///
/// $d_0$ is 32 zero bytes, so the empty list digests to $d_0$. A list's
/// digest folds this step over its tachygrams in order. Over a bundle's
/// tachygrams this is `hTachygramsTachyon`.
#[must_use]
pub fn tachygram_chain(digest: &[u8; 32], tachygram: &[u8; 32]) -> [u8; 32] {
    hasher_256(TACHYGRAM_CHAIN_PERSONALIZATION, |state| {
        state.update(digest);
        state.update(tachygram);
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
///     \mathsf{hActionsTachyon} \Vert \mathsf{vBalanceTachyon} \Vert
///     \mathsf{hMemoTachyon} \Vert \mathsf{hTachygramsTachyon}
///   )
/// $$
///
/// The stamp is excluded because it is mutable auth data. The memo is included
/// because it is effecting: relayers rewrite `auth_digest` during aggregation,
/// so only the sighash can hold a payload a miner must not strip. The
/// tachygram digest is included so that signatures bind the tachygrams each
/// action publishes.
#[must_use]
pub fn bundle_commitment(
    action_commit: &[u8; 32],
    value_balance: i64,
    memo_digest: &[u8; 32],
    tachygram_digest: &[u8; 32],
) -> [u8; 32] {
    hasher_256(BUNDLE_COMMITMENT_PERSONALIZATION, |state| {
        state.update(action_commit);
        state.update(&value_balance.to_le_bytes());
        state.update(memo_digest);
        state.update(tachygram_digest);
    })
}

const STAMP_DATA_PERSONALIZATION: &[u8; 13] = b"Tachyon-Stamp";
const STAMP_PROOF_PERSONALIZATION: &[u8; 13] = b"Tachyon-Proof";

/// Digest of a stamp's proof.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{Tachyon-Proof}(
///     \mathsf{proofTachyon}
///   )
/// $$
#[must_use]
pub fn stamp_proof_digest(proof: &[u8]) -> [u8; 32] {
    hasher_256(STAMP_PROOF_PERSONALIZATION, |state| {
        state.update(proof);
    })
}

/// Digest of a proof stamp's proof, anchor, tachygram-set commitment, and
/// tachygrams.
///
/// Tachygrams are hashed in the order given, so the digest commits to that
/// order.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{Tachyon-Stamp}(
///     \mathsf{hStampProofTachyon} \Vert
///     \mathsf{anchorTachyon} \Vert
///     \mathsf{cTachygrams} \Vert
///     \mathsf{vTachygrams}
///   )
/// $$
#[must_use]
pub fn stamp_data_digest(
    stamp_proof_digest: [u8; 32],
    anchor: [u8; 32],
    tachygram_set: [u8; 32],
    tachygrams: &[[u8; 32]],
) -> [u8; 32] {
    hasher_256(STAMP_DATA_PERSONALIZATION, |state| {
        state.update(&stamp_proof_digest);
        state.update(&anchor);
        state.update(&tachygram_set);

        // only variable-length component
        for tg in tachygrams {
            state.update(tg);
        }
    })
}

/// A bundle's contribution to the transaction auth_digest.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{ZTxAuthTachyHash}(
///     \mathsf{tachyonBundleState} \Vert \mathsf{vActionSigs} \Vert
///     \mathsf{bindingSigTachyon} \Vert \mathsf{tachyonStampState}
///   )
/// $$
///
/// $\mathsf{tachyonBundleState}$ is one byte indicating format of
/// $\mathsf{tachyonStampState}$
///
/// | $\mathsf{tachyonBundleState}$ | Impl | $\mathsf{tachyonStampState}$ |
/// | ----------------------------- | ---- | ---------------------------- |
/// | `0x01` | [`ProofStamp`](crate::stamp::ProofStamp) | $ \mathsf{hStampActionsTachyon} \Vert \mathsf{hStampDataTachyon} $ |
/// | `0x02` | [`PointerStamp`](crate::stamp::PointerStamp) | aggregate's `wtxid` |
#[must_use]
pub fn bundle_auth_digest(
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
}

#[cfg(test)]
mod tests {
    use ff::PrimeField as _;
    use pasta_curves::Fp;

    use super::*;

    /// Canonical little-endian encoding of a small field element.
    fn tg(n: u64) -> [u8; 32] {
        Fp::from(n).to_repr()
    }

    fn fold(tachygrams: &[[u8; 32]]) -> [u8; 32] {
        tachygrams.iter().fold([0u8; 32], |digest, tachygram| {
            tachygram_chain(&digest, tachygram)
        })
    }

    /// Vectors from an independent Python reference (`hashlib.blake2b`).
    #[test]
    fn tachygram_chain_vectors() {
        assert_eq!(
            fold(&[tg(1)]),
            [
                0x59, 0xc8, 0xe3, 0x4f, 0x28, 0x29, 0xec, 0x2e, //
                0xfd, 0xfc, 0xf5, 0xb7, 0x76, 0xa8, 0xd9, 0x35, //
                0xa0, 0xf8, 0x89, 0xe7, 0x20, 0x9b, 0xd0, 0x91, //
                0x1c, 0xf2, 0xc7, 0x99, 0x67, 0x14, 0xae, 0xcd, //
            ]
        );
        assert_eq!(
            fold(&[tg(1), tg(2), tg(3)]),
            [
                0x4d, 0xa8, 0xe6, 0x98, 0x18, 0x93, 0x7a, 0x9f, //
                0xa9, 0x10, 0x62, 0x57, 0x73, 0xc7, 0xe9, 0x42, //
                0xd8, 0x76, 0x97, 0x4a, 0x38, 0x47, 0x0c, 0x0f, //
                0xa2, 0x3f, 0xcb, 0x96, 0x9f, 0x7d, 0xc7, 0x52, //
            ]
        );
        assert_eq!(
            fold(&[tg(3), tg(2), tg(1)]),
            [
                0x3f, 0x99, 0x17, 0xe7, 0x49, 0x93, 0x48, 0x0a, //
                0xb1, 0xf8, 0x08, 0x27, 0xbc, 0xcd, 0xad, 0xe7, //
                0xc1, 0x71, 0xa0, 0xb0, 0x73, 0xb4, 0x04, 0x99, //
                0x75, 0xb1, 0x34, 0x6e, 0x54, 0xcc, 0xdc, 0x60, //
            ]
        );
    }

    /// The empty list digests to $d_0$.
    #[test]
    fn tachygram_chain_empty_is_zero() {
        assert_eq!(fold(&[]), [0u8; 32]);
    }

    /// Reordering a list changes its digest.
    #[test]
    fn tachygram_chain_commits_to_order() {
        assert_ne!(fold(&[tg(1), tg(2)]), fold(&[tg(2), tg(1)]));
    }

    /// A proper prefix digests differently from the whole list.
    #[test]
    fn tachygram_chain_prefix_differs() {
        let list = [tg(1), tg(2), tg(3)];
        let whole = fold(&list);
        for len in 0..list.len() {
            assert_ne!(fold(&list[..len]), whole);
        }
    }
}
