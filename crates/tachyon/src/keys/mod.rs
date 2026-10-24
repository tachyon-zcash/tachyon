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
//! - `pk = Poseidon_domain(ak_x, ak_y, nk)`: Derived from `pak`, binds spending
//!   authority and nullifier key to the note commitment
//!
//! ### Proof keys ([`proof`])
//!
//! - `pak`: `ak` + `nk` (proof authorizing key): Authorizes proof construction
//!   without spend authority
//!
//! ## Nullifier Derivation
//!
//! Nullifiers come `PoseidonFp::RATE` at a time from one Poseidon sponge
//! keyed on the note's master key and the epoch's group start
//! $w = e - (e \bmod \mathsf{RATE})$:
//!
//! $$
//!   \mathsf{mk} = \mathsf{Poseidon}_\texttt{Tachyon-NfMaster}(
//!     \psi,\ \mathsf{nk}
//!   )
//! $$
//!
//! $$
//!   \mathsf{nf}_e = \mathsf{squeeze} _{e - w}\big(
//!     \mathsf{absorb}_\texttt{Tachyon-NfDerive}(\mathsf{mk},\ w)
//!   \big)
//! $$
//!
//! where $\psi$ is the note's nullifier trapdoor, $\mathsf{nk}$ is the
//! nullifier key, and $e$ is the epoch index. Each group re-absorbs $w$, so
//! $\mathsf{nf}_e$ depends on $(\mathsf{mk}, e)$ alone and overlapping
//! derivation windows agree on the epochs they share; start epochs are
//! group-aligned.
//!
//! `mk` evaluates the whole epoch space; delegation carries proven value
//! windows.

pub mod private;
pub mod public;

mod master;
mod note;
mod proof;

// Re-exports: public API surface.
pub use master::NoteMasterKey;
pub use note::{NullifierKey, PaymentKey};
pub use proof::{ProofAuthorizingKey, SpendValidatingKey};

#[cfg(test)]
mod tests {
    use ff::{Field as _, PrimeField as _};
    use pasta_curves::Fp;
    use proptest::prelude::*;
    use rand::{SeedableRng as _, rngs::StdRng};

    use crate::{
        constants::{EPOCH_MAX, MAX_MONEY},
        entropy::ActionEntropy,
        keys::{NoteMasterKey, NullifierKey, PaymentKey, private},
        note::{self, Note},
        nullifier,
        primitives::{EpochIndex, effect},
        testing::check,
        value,
    };

    /// ask, nk and pk derived from one sk are distinct, and pak derives the
    /// same pk the spending key does.
    #[test]
    fn child_keys_are_independent() {
        check(256, any::<[u8; 32]>(), |bytes| {
            let sk = private::SpendingKey::from(bytes);
            let ak = sk.derive_auth_private().derive_auth_public();
            let nk = sk.derive_nullifier_private();
            let pk = sk.derive_payment_key();

            let ak_bytes: [u8; 32] = ak.0.into();
            prop_assert_ne!(ak_bytes, nk.0.to_repr());
            prop_assert_ne!(nk.0.to_repr(), Fp::from(pk).to_repr());
            prop_assert_eq!(
                Fp::from(sk.derive_proof_private().derive_payment_key()),
                Fp::from(pk)
            );
            Ok(())
        });
    }

    /// pk binds nk: another nk under the same ak gives another pk, which is
    /// what makes the note commitment pin the whole pak.
    #[test]
    fn payment_key_binds_nk() {
        check(256, any::<u64>(), |seed| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let sk = private::SpendingKey::random(rng);
            let ak = sk.derive_auth_private().derive_auth_public();
            let nk = sk.derive_nullifier_private();
            let other = NullifierKey(Fp::random(&mut *rng));
            prop_assert_ne!(
                Fp::from(PaymentKey::derive(&ak, &nk)),
                Fp::from(PaymentKey::derive(&ak, &other))
            );
            Ok(())
        });
    }

    /// The signer's rk and the prover's rk agree for any alpha.
    #[test]
    fn signer_and_prover_derive_one_rk() {
        check(256, (any::<u64>(), 0..=MAX_MONEY), |(seed, value)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let sk = private::SpendingKey::random(rng);
            let ask = sk.derive_auth_private();
            let note = Note {
                pk: sk.derive_payment_key(),
                value: value::Positive::try_from(value).unwrap(),
                psi: nullifier::Trapdoor::random(rng),
                rcm: note::CommitmentTrapdoor::random(rng),
            };
            let alpha = ActionEntropy::random(rng).randomizer::<effect::Spend>(note.commitment());

            let from_signer: [u8; 32] = ask
                .derive_action_private(&alpha)
                .derive_action_public()
                .0
                .into();
            let from_prover: [u8; 32] = ask
                .derive_auth_public()
                .derive_action_public(&alpha)
                .0
                .into();
            prop_assert_eq!(from_signer, from_prover);
            Ok(())
        });
    }

    /// Debug output names the type and is the same for every key, so it
    /// carries none of the key.
    #[test]
    fn debug_redacts_key_material() {
        let strategy = (any::<[u8; 32]>(), any::<[u8; 32]>(), any::<u64>());
        check(256, strategy, |(left, right, seed)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let spending = [left, right]
                .map(private::SpendingKey::from)
                .map(|sk| alloc::format!("{sk:?}"));
            let nullifier = [Fp::random(&mut *rng), Fp::random(&mut *rng)]
                .map(NullifierKey)
                .map(|nk| alloc::format!("{nk:?}"));
            for (debug, name) in [(spending, "SpendingKey"), (nullifier, "NullifierKey")] {
                prop_assert!(debug[0].contains(name));
                prop_assert_eq!(&debug[0], &debug[1]);
            }
            Ok(())
        });
    }

    /// A window that would run past the epoch range names epochs that map to
    /// no block height, so there is nothing to derive.
    #[test]
    #[should_panic(expected = "epoch index above EPOCH_MAX")]
    fn window_rejects_a_start_too_close_to_the_final_epoch() {
        let mk = NoteMasterKey(Fp::random(&mut StdRng::seed_from_u64(0)));
        // Group-aligned for any EPOCH_MAX of the form `2^k - 1`, and short of
        // a whole window by three epochs.
        let window = mk.derive_window(EpochIndex::new(EPOCH_MAX - 3));
        panic!("a window past the final epoch must not derive, got {window:?}");
    }
}
