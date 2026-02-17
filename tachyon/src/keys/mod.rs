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
//!     alpha[SpendAuthRandomizer alpha]
//!     rsk[RandomizedSigningKey rsk]
//!     rk[RandomizedVerificationKey rk]
//!     pak[ProvingKey]
//!     sk --> ask & nk & pk
//!     ask --> ak
//!     ask -- "+alpha" --> rsk
//!     ak -- "+alpha" --> rk
//!     rsk --> rk
//!     ak & nk --> pak
//! ```
//!
//! ### Private keys ([`private`])
//!
//! - `sk`: Root spending key (full authority)
//! - `ask`: Authorizes spends (long-lived, cannot sign directly)
//! - `rsk = ask + alpha`: Per-action signing key (can sign)
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
//! - `pak`: `ak` + `nk` (proving key): Constructs proofs without spend
//!   authority; might be delegated to a syncing service
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

pub mod note;
pub mod private;
pub mod proof;
pub mod public;

// Signature types live here because they bridge private (sign) and public
// (verify).
pub(crate) mod signature;

// Re-exports: public API surface.
pub use note::{NullifierKey, PaymentKey};
pub use private::{BindingSigningKey, RandomizedSigningKey, SpendAuthorizingKey, SpendingKey};
pub use proof::ProvingKey;
pub use public::{BindingVerificationKey, RandomizedVerificationKey, SpendValidatingKey};
pub use signature::{BindingSignature, SpendAuthSignature};

#[cfg(test)]
mod tests {
    use ff::{Field as _, PrimeField as _};
    use pasta_curves::{Fp, Fq};
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        Action,
        action::spend_auth_message,
        note::{self, CommitmentTrapdoor, Note, NullifierTrapdoor},
        primitives::{SpendAuthEntropy, SpendAuthRandomizer},
        value,
    };

    /// RedPallas requires ak to have tilde_y = 0 (sign bit cleared).
    /// The key derivation must enforce this for any spending key.
    #[test]
    fn ask_sign_normalization() {
        for seed in 0u8..20 {
            let sk = SpendingKey::from([seed; 32]);
            let ak = sk.spend_authorizing_key().validating_key();
            let ak_bytes: [u8; 32] = ak.0.into();
            assert_eq!(
                ak_bytes[31] >> 7u8,
                0u8,
                "ak sign bit must be 0 for sk=[{seed}; 32]"
            );
        }
    }

    /// ask, nk, pk derived from the same sk must all be different
    /// (different domain separators produce independent keys).
    #[test]
    fn child_keys_independent() {
        let sk = SpendingKey::from([0x42u8; 32]);
        let ask_bytes: [u8; 32] = sk.spend_authorizing_key().validating_key().0.into();
        let nk: Fp = sk.nullifier_key().into();
        let pk: Fp = sk.payment_key().into();

        assert_ne!(ask_bytes, nk.to_repr());
        assert_ne!(nk.to_repr(), pk.to_repr());
    }

    /// rsk.public() must equal ak.derive_action_public(alpha) for the same
    /// alpha. This is the core consistency property between signer and prover
    /// sides of the randomized key derivation.
    #[test]
    fn rsk_public_equals_ak_derive_action_public() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = SpendingKey::from([0x42u8; 32]);
        let ask = sk.spend_authorizing_key();
        let ak = ask.validating_key();
        let note = Note {
            pk: sk.payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let cmx = note.commitment();
        let theta = SpendAuthEntropy::random(&mut rng);
        let alpha = SpendAuthRandomizer::derive(&theta, &cmx);

        let rk_from_signer: [u8; 32] = ask.derive_action_private(&alpha).public().into();
        let rk_from_prover: [u8; 32] = ak.derive_action_public(&alpha).into();

        assert_eq!(rk_from_signer, rk_from_prover);
    }

    /// Spend auth signature round-trip: rsk signs, rk verifies.
    #[test]
    fn spend_auth_sign_verify_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = SpendingKey::from([0x42u8; 32]);
        let ask = sk.spend_authorizing_key();
        let note = Note {
            pk: sk.payment_key(),
            value: note::Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let cmx = note.commitment();
        let theta = SpendAuthEntropy::random(&mut rng);
        let alpha = SpendAuthRandomizer::derive(&theta, &cmx);

        let rsk = ask.derive_action_private(&alpha);
        let rk = rsk.public();

        let msg = b"test message for spend auth";
        let sig = rsk.sign(&mut rng, msg);
        rk.verify(msg, &sig).unwrap();
    }

    /// BSK/BVK consistency: [bsk]R must equal the bvk derived from
    /// value commitments (§4.14 binding property).
    #[test]
    fn bsk_bvk_consistency() {
        let mut rng = StdRng::seed_from_u64(0);
        let sk = SpendingKey::from([0x42u8; 32]);
        let ask = sk.spend_authorizing_key();
        let theta = SpendAuthEntropy::random(&mut rng);

        // Two actions: spend 300, output 200 → balance = 100
        let (rcv_a, cv_a) = value::Commitment::commit(300, &mut rng);
        let (rcv_b, cv_b) = value::Commitment::commit(-200, &mut rng);

        let bsk: BindingSigningKey = [rcv_a, rcv_b].into_iter().sum();
        let bvk_from_bsk = bsk.verification_key();

        // Build stub actions with the given cv values
        let actions: Vec<Action> = [cv_a, cv_b]
            .into_iter()
            .map(|cv| {
                let note = Note {
                    pk: sk.payment_key(),
                    value: note::Value::from(1000u64),
                    psi: NullifierTrapdoor::from(Fp::ZERO),
                    rcm: CommitmentTrapdoor::from(Fq::ZERO),
                };
                let cmx = note.commitment();
                let alpha = SpendAuthRandomizer::derive(&theta, &cmx);
                let rsk = ask.derive_action_private(&alpha);
                let rk = rsk.public();
                let msg = spend_auth_message(&cv, &rk);
                let sig = rsk.sign(&mut rng, &msg);
                Action { cv, rk, sig }
            })
            .collect();

        let bvk_from_cvs = BindingVerificationKey::derive(&actions, 100);
        assert_eq!(bvk_from_bsk, bvk_from_cvs);
    }
}
