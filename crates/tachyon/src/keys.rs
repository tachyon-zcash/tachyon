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
mod note {
    //! Note-related keys: NullifierKey, PaymentKey.

    use derive_more::{AsRef, Debug, From, Into};
    #[cfg(test)]
    use rand_core::CryptoRng;
    use udon::curve::Affine as _;
    #[cfg(test)]
    use udon::field::Field as _;

    use super::{master::NoteMasterKey, proof::SpendValidatingKey};
    use crate::{
        digest::poseidon,
        nullifier,
        pasta::{EpAffine, Fp},
    };

    /// A Tachyon nullifier deriving key.
    ///
    /// Tachyon simplifies Orchard's nullifier construction
    /// ("Tachyaction at a Distance", Bowe 2025):
    ///
    /// $$
    ///   \mathsf{nf} = F_{\mathsf{nk}}(\Psi \Vert e)
    /// $$
    ///
    /// where $F$ is a keyed PRF (Poseidon), $\Psi$ is the note's nullifier
    /// trapdoor, and $e$ is the epoch index. This replaces Orchard's more
    /// complex construction that defended against faerie gold attacks, which
    /// are moot under out-of-band payments.
    ///
    /// ## Capabilities
    ///
    /// - **Nullifier derivation**: detecting when a note has been spent
    /// - **Oblivious sync delegation**: a delegate receives proven value
    ///   windows. The master key $\mathsf{mk} =
    ///   \mathsf{Poseidon}_\texttt{Tachyon-NfMaster}( \Psi, \mathsf{nk})$
    ///   evaluates every epoch.
    ///
    /// `nk` alone does NOT confer spend authority; combined with `ak` it
    /// forms the proof authorizing key `pak`, enabling proof construction
    /// and nullifier derivation without signing capability.
    #[derive(Clone, Copy, Debug, Into)]
    pub struct NullifierKey(#[debug(skip)] pub(super) Fp);

    impl NullifierKey {
        #[cfg(test)]
        pub(crate) fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
            Self(Fp::random(|bytes| rng.fill_bytes(bytes)))
        }

        /// Derive a note's master key from its nullifier trapdoor `psi`.
        #[must_use]
        pub fn derive_note_private(&self, psi: nullifier::Trapdoor) -> NoteMasterKey {
            NoteMasterKey(poseidon::nf_master(psi.into(), self.0))
        }
    }

    /// A Tachyon payment key: a recipient identifier, minted fresh per sender.
    ///
    /// Replaces Orchard's diversified transmission key $\mathsf{pk_d}$ and
    /// the entire diversified address system. Tachyon removes the diversifier
    /// $d$ because payment addresses are removed from the on-chain protocol
    /// ("Tachyaction at a Distance", Bowe 2025):
    ///
    /// > "The transmission key $\mathsf{pk_d}$ is substituted with a payment
    /// > key $\mathsf{pk}$."
    ///
    /// ## Derivation
    ///
    /// Derived from the proof authorizing key components:
    ///
    /// $$
    ///   \mathsf{pk} = \text{Poseidon}_\texttt{Tachyon-PkDerive}(
    ///     \mathsf{ak}_x,\ \mathsf{ak}_y,\ \mathsf{nk}
    ///   )
    /// $$
    ///
    /// where $(\mathsf{ak}_x, \mathsf{ak}_y)$ are the affine coordinates of the
    /// spend validating key.
    /// This binds `pk` to both `ak` and `nk`, so the note commitment `cm`
    /// (which contains `pk`) transitively pins the full proof authorizing key.
    /// Wrong `nk` produces wrong `pk`, wrong `cm`, and accumulator inclusion
    /// fails.
    ///
    /// `pk` is deterministic in `(ak, nk)`, so unlinkability comes from minting
    /// a fresh address per sender: a receiver walks its wallet-standard
    /// derivation path to a freshly indexed `(ak, nk)` pair. That index sits
    /// above `sk`, so [`SpendingKey`](super::private::SpendingKey) takes it
    /// already applied and no derivation path is fixed here. Transfer proofs
    /// never constrain it; they check `pk` against a witnessed `pak`.
    ///
    /// ## Usage
    ///
    /// The recipient's `pk` appears in the note and is committed to in the
    /// note commitment. It is NOT an on-chain address; payment coordination
    /// happens out-of-band via higher-level protocols (ZIP 321 payment
    /// requests, ZIP 324 URI encapsulated payments).
    #[derive(AsRef, Clone, Copy, Debug, From, Into)]
    pub struct PaymentKey(#[debug(skip)] Fp);

    impl PaymentKey {
        #[cfg(test)]
        pub(crate) fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
            Self(Fp::random(|bytes| rng.fill_bytes(bytes)))
        }

        /// Derive the payment key from `ak` and `nk`:
        ///
        /// $$
        ///   \mathsf{pk} = \text{Poseidon}_\texttt{Tachyon-PkDerive}(
        ///     \mathsf{ak}_x,\ \mathsf{ak}_y,\ \mathsf{nk}
        ///   )
        /// $$
        ///
        /// # Panics
        ///
        /// Panics if `ak` is the identity, which has no affine coordinates.
        #[must_use]
        pub fn derive(ak: &SpendValidatingKey, nk: &NullifierKey) -> Self {
            let ak_bytes: [u8; 32] = ak.0.into();
            #[expect(clippy::expect_used, reason = "a validating key is a curve point")]
            let point =
                EpAffine::from_bytes(ak_bytes).expect("ak bytes should be a valid curve point");
            Self(poseidon::payment_key(point, nk.0))
        }
    }
}
mod proof;

// Re-exports: public API surface.
pub use master::NoteMasterKey;
pub use note::{NullifierKey, PaymentKey};
pub use proof::{ProofAuthorizingKey, SpendValidatingKey};

#[cfg(test)]
mod tests;
