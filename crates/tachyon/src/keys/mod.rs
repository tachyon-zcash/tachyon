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
//! Nullifiers are derived from a per-note master key $\mathsf{mk} = [k, w]$:
//!
//! $$[k, w] = \mathsf{Poseidon}_\texttt{Tachyon-NfMaster}(\psi, \mathsf{nk})$$
//! $$\mathsf{nf}_e = E_k(e) + w$$
//!
//! where $\psi$ is the note's nullifier trapdoor, $\mathsf{nk}$ is the
//! nullifier key, and the cipher input $e$ is the epoch index itself. Every
//! epoch window's nullifiers are the cipher outputs.

pub mod private;
pub mod public;

mod note;
mod proof;

// Re-exports: public API surface.
pub use note::{NoteMasterKey, NullifierKey, PaymentKey};
pub use proof::{ProofAuthorizingKey, SpendValidatingKey};

#[cfg(test)]
mod tests {
    use ff::{Field as _, PrimeField as _};
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use crate::{
        entropy::ActionEntropy,
        keys::{NullifierKey, PaymentKey, private},
        note::{self, Note},
        nullifier,
        primitives::effect,
        value,
    };

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
        let rng = &mut StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::random(rng);
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
        let rng = &mut StdRng::seed_from_u64(0);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let ak = ask.derive_auth_public();
        let note = Note {
            pk: sk.derive_payment_key(),
            value: value::Positive::try_from(1000u64).unwrap(),
            psi: nullifier::Trapdoor::random(rng),
            rcm: note::CommitmentTrapdoor::random(rng),
        };
        let theta = ActionEntropy::random(rng);
        let alpha = theta.randomizer::<effect::Spend>(note.commitment());
        let rsk = ask.derive_action_private(&alpha);

        let rk_from_signer: [u8; 32] = rsk.derive_action_public().0.into();
        let rk_from_prover: [u8; 32] = ak.derive_action_public(&alpha).0.into();

        assert_eq!(rk_from_signer, rk_from_prover);
    }

    #[test]
    fn debug_spending_key_redacts_bytes() {
        let sk = private::SpendingKey::from([0xAB; 32]);
        let dbg = alloc::format!("{sk:?}");
        assert!(dbg.contains("SpendingKey"), "must name the type");
        assert!(!dbg.contains("AB"), "must not leak key bytes");
        assert!(!dbg.contains("171"), "must not leak decimal bytes");
    }

    #[test]
    fn debug_nullifier_key_redacts_value() {
        let nk = NullifierKey(Fp::from(0xDEADu64));
        let dbg = alloc::format!("{nk:?}");
        assert!(dbg.contains("NullifierKey"), "must name the type");
        assert!(!dbg.contains("DEAD"), "must not leak field element");
        assert!(!dbg.contains("57005"), "must not leak decimal value");
    }
}
