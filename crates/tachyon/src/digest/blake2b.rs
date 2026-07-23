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
///     \theta \| cm
///   )
/// $$
///
/// Caller reduces to scalar via `Fq::from_uniform_bytes`.
pub(crate) fn alpha_spend(theta: &[u8; 32], cm: &[u8; 32]) -> [u8; 64] {
    hasher_512(SPEND_ALPHA_PERSONALIZATION, |state| {
        state.update(theta);
        state.update(cm);
    })
}

/// Output-side $\alpha$ pre-image.
///
/// $$
///   \text{BLAKE2b-512}_\texttt{Tachyon-Output}(
///     \theta \| cm
///   )
/// $$
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
/// $$
///   \text{BLAKE2b-512}_\texttt{Zcash\_ExpandSeed}(
///     sk \| \text{ASK_DOMAIN_BYTE}
///   )
/// $$
///
/// Mirrors Zcash §5.4.2.
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
/// $$
///   \text{BLAKE2b-512}_\texttt{Zcash\_ExpandSeed}(
///     sk \| \text{NK_DOMAIN_BYTE}
///   )
/// $$
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
/// Action descriptors are hashed in the order given, so the digest commits to
/// that order.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{Tachyon-Actions}(
///     \mathsf{cv}_i \| \mathsf{rk}_i
///   )
/// $$
///
/// Over a bundle's actions this is `hActionsTachyon`.
///
/// Over a stamp's covered actions this is `hStampActionsTachyon`.
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
/// Only digests effecting data.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{ZTxIdTachyonHash}(
///     \mathsf{hActionsTachyon} \| \mathsf{vBalanceTachyon}
///   )
/// $$
///
/// The stamp is excluded because it is mutable auth data.
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
/// $$
///   \text{BLAKE2b-256}_\texttt{Tachyon-Proof}(
///     \mathsf{proofTachyon}
///   )
/// $$
pub(crate) fn stamp_proof_digest(proof: &[u8]) -> [u8; 32] {
    hasher_256(STAMP_PROOF_PERSONALIZATION, |state| {
        state.update(proof);
    })
}

/// Digest of a proof stamp's proof, anchor, and tachygrams.
///
/// Tachygrams are hashed in the order given, so the digest commits to that
/// order.
///
/// $$
///   \text{BLAKE2b-256}_\texttt{Tachyon-Stamp}(
///     \mathsf{hStampProofTachyon} \|
///     \mathsf{stampAnchorTachyon} \|
///     \mathsf{vTachygrams}
///   )
/// $$
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
/// $$
///   \text{BLAKE2b-256}_\texttt{ZTxAuthTachyHash}(
///     \mathsf{tachyonBundleState} \| \mathsf{vActionSigs} \|
///     \mathsf{bindingSigTachyon} \| \mathsf{tachyonStampState}
///   )
/// $$
///
/// $\mathsf{tachyonBundleState}$ is one byte indicating format of $\mathsf{tachyonStampState}$
///
/// | $\mathsf{tachyonBundleState}$ | Impl | $\mathsf{tachyonStampState}$ |
/// | ----------------------------- | ---- | ---------------------------- |
/// | `0x01` | [`ProofStamp`](`crate::stamp::ProofStamp`) | $ \mathsf{hStampActionsTachyon} \| \mathsf{hStampDataTachyon} $ |
/// | `0x02` | [`PointerStamp`](`crate::stamp::PointerStamp`) | aggregate's `wtxid` |
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

#[cfg(test)]
mod domain_separation {
    //! Registry of every BLAKE2b hash context and a check that they are
    //! mutually domain-separated.
    //!
    //! Separation comes from the fixed 16-byte `personal` field, optionally
    //! refined by a trailing in-preimage domain byte. BLAKE2b zero-pads
    //! shorter tags to 16 bytes, so distinctness is checked on the padded
    //! block — the form the hash actually sees — not the source literal
    //! (`b"foo"` and `b"foo\0"` are the same personalization). Two contexts
    //! are separated whenever their `(personal_block, domain_byte)` pair
    //! differs. `prf_expand_ask`/`prf_expand_nk` deliberately share the
    //! global `Zcash_ExpandSeed` personalization and are separated by that
    //! trailing byte (the standard Zcash PRF^expand pattern), so no reuse is
    //! unseparated here.

    use super::{
        ACTION_DESCRIPTOR_PERSONALIZATION, AUTH_DIGEST_PERSONALIZATION,
        BUNDLE_COMMITMENT_PERSONALIZATION, OUTPUT_ALPHA_PERSONALIZATION, PRF_EXPAND_DOMAIN_ASK,
        PRF_EXPAND_DOMAIN_NK, PRF_EXPAND_PERSONALIZATION, SPEND_ALPHA_PERSONALIZATION,
        STAMP_DATA_PERSONALIZATION, STAMP_PROOF_PERSONALIZATION,
    };

    /// A BLAKE2b hash context: its `personal` field and any trailing in-preimage
    /// domain byte. `(personal_block(personal), domain_byte)` is the separation
    /// key.
    struct Context {
        name: &'static str,
        personal: &'static [u8],
        domain_byte: Option<u8>,
    }

    /// The 16-byte `personal` block BLAKE2b actually keys on: shorter tags are
    /// zero-padded, so distinctness must be compared on this form.
    fn personal_block(personal: &[u8]) -> [u8; 16] {
        assert!(personal.len() <= 16, "personalization exceeds 16 bytes");
        let mut block = [0u8; 16];
        for (dst, src) in block.iter_mut().zip(personal) {
            *dst = *src;
        }
        block
    }

    const REGISTRY: &[Context] = &[
        Context {
            name: "alpha_spend",
            personal: SPEND_ALPHA_PERSONALIZATION,
            domain_byte: None,
        },
        Context {
            name: "alpha_output",
            personal: OUTPUT_ALPHA_PERSONALIZATION,
            domain_byte: None,
        },
        Context {
            name: "prf_expand_ask",
            personal: PRF_EXPAND_PERSONALIZATION,
            domain_byte: Some(PRF_EXPAND_DOMAIN_ASK),
        },
        Context {
            name: "prf_expand_nk",
            personal: PRF_EXPAND_PERSONALIZATION,
            domain_byte: Some(PRF_EXPAND_DOMAIN_NK),
        },
        Context {
            name: "action_descriptor_digest",
            personal: ACTION_DESCRIPTOR_PERSONALIZATION,
            domain_byte: None,
        },
        Context {
            name: "bundle_commitment",
            personal: BUNDLE_COMMITMENT_PERSONALIZATION,
            domain_byte: None,
        },
        Context {
            name: "bundle_auth_digest",
            personal: AUTH_DIGEST_PERSONALIZATION,
            domain_byte: None,
        },
        Context {
            name: "stamp_proof_digest",
            personal: STAMP_PROOF_PERSONALIZATION,
            domain_byte: None,
        },
        Context {
            name: "stamp_data_digest",
            personal: STAMP_DATA_PERSONALIZATION,
            domain_byte: None,
        },
    ];

    #[test]
    fn every_blake2b_context_is_domain_separated() {
        for (index, a) in REGISTRY.iter().enumerate() {
            for b in REGISTRY.iter().skip(index + 1) {
                let collides = personal_block(a.personal) == personal_block(b.personal)
                    && a.domain_byte == b.domain_byte;
                assert!(
                    !collides,
                    "BLAKE2b contexts `{}` and `{}` share a personalization and domain \
                     byte — they are not domain-separated",
                    a.name, b.name,
                );
            }
        }
    }
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
