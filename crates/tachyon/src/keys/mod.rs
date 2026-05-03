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
//!     rk[ActionVerificationKey rk]
//!     sig["sig (action::Signature)"]
//!     pak[ProofAuthorizingKey]
//!     sighash["sighash &amp;[u8; 32]"]
//!     sk --> ask & nk
//!     ask --> ak
//!     theta["ActionEntropy theta"] -- "randomizer::&lt;Spend&gt;" --> spend_alpha["ActionRandomizer&lt;Spend&gt;"]
//!     theta -- "randomizer::&lt;Output&gt;" --> output_alpha["ActionRandomizer&lt;Output&gt;"]
//!     ask -- "derive_action_private(alpha)" --> spend_rsk["ActionSigningKey&lt;Spend&gt;"]
//!     output_alpha -- "new" --> output_rsk["ActionSigningKey&lt;Output&gt;"]
//!     ak -- "+alpha" --> rk
//!     spend_rsk -- "derive_action_public()" --> rk
//!     output_rsk -- "derive_action_public()" --> rk
//!     spend_rsk -- "sign(sighash)" --> sig
//!     output_rsk -- "sign(sighash)" --> sig
//!     ak & nk --> pak
//!     ak & nk -->|"Poseidon"| pk
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
//! - `pk = Poseidon(domain, ak_x, nk)`: Derived from `pak`, binds spending
//!   authority and nullifier key to the note commitment
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

mod ggm;
mod note;
mod proof;

// Re-exports: public API surface.
pub use ggm::{GGM_TREE_DEPTH, NoteMasterKey, NotePrefixedKey};
pub use note::{NullifierKey, PaymentKey};
pub use proof::{ProofAuthorizingKey, SpendValidatingKey};

#[cfg(test)]
mod tests {
    use ff::{Field as _, PrimeField as _};
    use pasta_curves::{Fp, Fq};
    use proptest::prelude::*;
    use rand::{RngCore as _, SeedableRng as _, rngs::StdRng};

    use crate::{
        constants::PrfExpand,
        entropy::ActionEntropy,
        keys::{NullifierKey, PaymentKey, private},
        note::{self, Note},
        primitives::effect,
        reddsa,
        testing::arb_note,
    };

    /// RedPallas requires ak to have tilde_y = 0 (sign bit cleared).
    /// The key derivation must enforce this for any spending key.
    /// Verifies both code paths: keys that needed negation and keys that
    /// didn't.
    #[test]
    fn ask_sign_normalization() {
        use ff::FromUniformBytes as _;

        let mut rng = StdRng::seed_from_u64(0);
        let mut flipped = 0u32;
        for _ in 0u8..20 {
            let mut sk_bytes = [0u8; 32];
            rng.fill_bytes(&mut sk_bytes);

            // Check the raw (pre-normalization) sign bit.
            let ask_scalar = Fq::from_uniform_bytes(&PrfExpand::ASK.with(&sk_bytes));
            let unnormalized_ak: [u8; 32] = reddsa::VerificationKey::from(
                &reddsa::SigningKey::<reddsa::ActionAuth>::try_from(ask_scalar.to_repr()).unwrap(),
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

    /// ask, nk, pk derived from the same sk must all be different.
    /// pk derives from (ak, nk) via Poseidon, not directly from sk.
    #[test]
    fn child_keys_independent() {
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ak = sk.derive_auth_private().derive_auth_public();
        let nk = sk.derive_nullifier_private();
        let pk = sk.derive_payment_key();

        let ak_bytes: [u8; 32] = ak.0.into();
        assert_ne!(ak_bytes, nk.0.to_repr());
        assert_ne!(nk.0.to_repr(), pk.0.to_repr());

        let pak = sk.derive_proof_private();
        assert_eq!(pak.derive_payment_key().0, pk.0);
    }

    /// pk must bind to nk: varying nk (with ak fixed) must produce a
    /// different pk. This is what makes the note commitment transitively
    /// pin the full proof authorizing key.
    #[test]
    fn payment_key_binds_nk() {
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ak = sk.derive_auth_private().derive_auth_public();
        let nk = sk.derive_nullifier_private();
        let pk = PaymentKey::derive(&ak, &nk);

        let nk_other = NullifierKey(nk.0 + Fp::ONE);
        let pk_other = PaymentKey::derive(&ak, &nk_other);
        assert_ne!(pk.0, pk_other.0);
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
            psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
        };
        let theta = ActionEntropy::random(&mut rng);
        let alpha = theta.randomizer::<effect::Spend>(&note.commitment());
        let rsk = ask.derive_action_private(&alpha);

        let rk_from_signer: [u8; 32] = rsk.derive_action_public().0.into();
        let rk_from_prover: [u8; 32] = ak.derive_action_public(&alpha).0.into();

        assert_eq!(rk_from_signer, rk_from_prover);
    }

    proptest! {
        /// Different spending keys derive different authorization keys.
        #[test]
        fn different_sk_different_ak(
            sk_a in any::<[u8; 32]>(),
            sk_b in any::<[u8; 32]>(),
        ) {
            prop_assume!(sk_a != sk_b);
            let ak_a: [u8; 32] = private::SpendingKey::from(sk_a)
                .derive_auth_private().derive_auth_public().0.into();
            let ak_b: [u8; 32] = private::SpendingKey::from(sk_b)
                .derive_auth_private().derive_auth_public().0.into();
            // PRF collision would be a security finding.
            prop_assert_ne!(ak_a, ak_b);
        }

        /// rk derived by signer (ask + alpha) equals rk derived by prover (ak + [alpha]G).
        #[test]
        fn rk_signer_equals_prover(
            sk_bytes in any::<[u8; 32]>(),
            theta_bytes in any::<[u8; 32]>(),
            note in arb_note(),
        ) {
            let sk = private::SpendingKey::from(sk_bytes);
            let ask = sk.derive_auth_private();
            let pak = sk.derive_proof_private();
            let theta = ActionEntropy::from_bytes(theta_bytes);
            let cm = note.commitment();
            let alpha = theta.randomizer::<effect::Spend>(&cm);

            let rk_signer: [u8; 32] = ask
                .derive_action_private(&alpha)
                .derive_action_public()
                .0
                .into();
            let rk_prover: [u8; 32] = pak.ak.derive_action_public(&alpha).0.into();
            prop_assert_eq!(rk_signer, rk_prover);
        }

        /// pak.derive_payment_key() matches sk.derive_payment_key().
        #[test]
        fn pak_payment_key_consistent(sk_bytes in any::<[u8; 32]>()) {
            let sk = private::SpendingKey::from(sk_bytes);
            let pak = sk.derive_proof_private();
            prop_assert_eq!(pak.derive_payment_key().0, sk.derive_payment_key().0);
        }
    }
}
