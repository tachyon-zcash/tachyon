//! ## Key Hierarchy
//!
//! Tachyon simplifies the key hierarchy compared to Orchard by removing
//! key diversification, viewing keys, and payment addresses from the core
//! protocol. These capabilities are handled by higher-level wallet software
//! through out-of-band payment protocols.
//!
//! ```mermaid
//! flowchart TB
//!     sk[SpendingKey]
//!     ask[SpendAuthorizingKey ask]
//!     ak[SpendValidatingKey ak]
//!     nk[NullifierKey nk]
//!     pk[PaymentKey pk]
//!     rk_sig["(rk, sig)"]
//!     rk[ActionVerificationKey rk]
//!     pak[ProofAuthorizingKey]
//!     sk --> ask & nk & pk
//!     ask --> ak
//!     theta["ActionEntropy theta"] -- spend_randomizer --> spend_alpha["SpendRandomizer"]
//!     theta -- output_randomizer --> output_alpha["OutputRandomizer"]
//!     spend_alpha -- "authorize(ask, cv)" --> rk_sig
//!     output_alpha -- "authorize(cv)" --> rk_sig
//!     ak -- "+alpha" --> rk
//!     ak & nk --> pak
//! ```
//!
//! ### Private keys ([`private`])
//!
//! - `sk`: Root spending key (full authority)
//! - `ask`: Authorizes spends (long-lived, cannot sign directly)
//! - `bsk = Σrcvᵢ`: Binding signing key (per-bundle)
//!
//! ### Public keys ([`public`])
//!
//! - `ak`: Public counterpart of `ask` (long-lived, cannot verify action sigs)
//! - `rk = ak + [alpha]G`: Per-action verification key (can verify, public)
//! - `bvk`: Binding verification key (derived from value commitments)
//!
//! ### Note keys ([`note`])
//!
//! - `nk`: Observes when funds are spent (nullifier derivation)
//! - `pk`: Used in note construction and out-of-band payment protocols
//!
//! ### Proof keys ([`proof`])
//!
//! - `pak`: `ak` + `nk` (proof authorizing key): Authorizes proof construction
//!   without spend authority
//!
//! ## Nullifier Derivation
//!
//! Nullifiers are derived via a GGM tree PRF instantiated from Poseidon:
//!
//! $$\mathsf{mk} = \text{KDF}(\psi, \mathsf{nk})$$
//! $$\mathsf{nf} = F_{\mathsf{mk}}(\text{flavor})$$
//!
//! where $\psi$ is the note's nullifier trapdoor, $\mathsf{nk}$ is the
//! nullifier key, and flavor is the epoch-id.
//!
//! The master root key $\mathsf{mk}$ supports oblivious sync delegation:
//! prefix keys $\Psi_t$ permit evaluating the PRF only for epochs
//! $e \leq t$, enabling range-restricted delegation without revealing
//! spend capability.

pub mod private;
pub mod public;

mod note;
mod proof;

// Re-exports: public API surface.
pub use note::{NoteDelegateKey, NoteMasterKey, NullifierKey, PaymentKey};
pub use proof::ProofAuthorizingKey;

#[cfg(test)]
mod tests {
    use ff::{Field as _, PrimeField as _};
    use pasta_curves::{Fp, Fq};
    use rand::{RngCore as _, SeedableRng as _, rngs::StdRng};

    use crate::{
        constants::PrfExpand,
        keys::private,
        note::{self, CommitmentTrapdoor, Note, NullifierTrapdoor},
    };

    /// RedPallas requires ak to have tilde_y = 0 (sign bit cleared).
    /// The key derivation must enforce this for any spending key.
    /// Verifies both code paths: keys that needed negation and keys that
    /// didn't.
    #[test]
    fn ask_sign_normalization() {
        use ff::FromUniformBytes as _;
        use reddsa::orchard::SpendAuth;

        let mut rng = StdRng::seed_from_u64(0);
        let mut flipped = 0u32;
        for _ in 0u8..20 {
            let mut sk_bytes = [0u8; 32];
            rng.fill_bytes(&mut sk_bytes);

            // Check the raw (pre-normalization) sign bit.
            let ask_scalar = Fq::from_uniform_bytes(&PrfExpand::ASK.with(&sk_bytes));
            let unnormalized_ak: [u8; 32] = reddsa::VerificationKey::from(
                &reddsa::SigningKey::<SpendAuth>::try_from(ask_scalar.to_repr()).unwrap(),
            )
            .into();
            if unnormalized_ak[31] >> 7u8 == 1u8 {
                flipped += 1;
            }

            // Verify normalization produces tilde_y = 0.
            let sk = private::SpendingKey::from(sk_bytes);
            let ak = sk.derive_auth_private().derive_auth_public();
            let ak_bytes: [u8; 32] = ak.0.into();
            assert_eq!(ak_bytes[31] >> 7u8, 0u8, "ak sign bit must be 0");
        }
        // 16 of 20 keys need the sign flip with this seed,
        // confirming both code paths are exercised.
        assert_eq!(flipped, 16u32);
    }

    /// ask, nk, pk derived from the same sk must all be different
    /// (different domain separators produce independent keys).
    #[test]
    fn child_keys_independent() {
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask_bytes: [u8; 32] = sk.derive_auth_private().derive_auth_public().0.into();
        let nk: Fp = sk.derive_nullifier_private().0;
        let pk: Fp = sk.derive_payment_key().0;

        assert_ne!(ask_bytes, nk.to_repr());
        assert_ne!(nk.to_repr(), pk.to_repr());
    }

    /// rsk.derive_action_public() must equal ak.derive_action_public(alpha) for
    /// the same alpha. This is the core consistency property between signer
    /// and prover sides of the randomized key derivation.
    #[test]
    fn rsk_public_equals_ak_derive_action_public() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let ak = ask.derive_auth_public();
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let theta = private::ActionEntropy::random(&mut rng);
        let alpha = theta.spend_randomizer(&note.commitment());
        let rsk = ask.derive_action_private(&alpha);
        let witness_alpha: private::ActionRandomizer = alpha.into();

        let rk_from_signer: [u8; 32] = rsk.derive_action_public().into();
        let rk_from_prover: [u8; 32] = ak.derive_action_public(&witness_alpha).into();

        assert_eq!(rk_from_signer, rk_from_prover);
    }
}
