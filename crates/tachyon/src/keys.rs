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
mod tests;
