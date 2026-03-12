//! Proof-related keys: ProofAuthorizingKey.

use reddsa::orchard::SpendAuth;

use super::{note::NullifierKey, public};
use crate::entropy::SpendRandomizer;

/// The proof authorizing key (`ak` + `nk`).
///
/// Authorizes proof construction without spend authority. The holder can
/// construct proofs for all notes (since `nk` is wallet-wide) but cannot
/// sign actions.
///
/// Derived from [`SpendAuthorizingKey`](super::private::SpendAuthorizingKey)
/// $\to$ [`SpendValidatingKey`] and [`NullifierKey`].
///
/// ## Status
///
/// Currently a data holder — no proof-construction methods yet. These will be
/// added once the Ragu PCD circuit is integrated and proof delegation is
/// specified.
// TODO: add proof-construction methods (e.g., create_action_proof, create_merge_proof)
// once the Ragu circuit API is available.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ProofAuthorizingKey {
    /// The spend validating key `ak = [ask] G`.
    pub(super) ak: SpendValidatingKey,
    /// The nullifier deriving key.
    pub(super) nk: NullifierKey,
}

impl ProofAuthorizingKey {
    /// The spend validating key $\mathsf{ak} = [\mathsf{ask}]\,\mathcal{G}$.
    #[must_use]
    pub const fn ak(&self) -> &SpendValidatingKey {
        &self.ak
    }

    /// The nullifier deriving key $\mathsf{nk}$.
    #[must_use]
    pub const fn nk(&self) -> &NullifierKey {
        &self.nk
    }
}

/// The spend validating key $\mathsf{ak} = [\mathsf{ask}]\,\mathcal{G}$ —
/// the long-lived counterpart of
/// [`SpendAuthorizingKey`](super::private::SpendAuthorizingKey).
///
/// Corresponds to the "spend validating key" in Orchard (§4.2.3).
/// Constrains per-action `rk` in the proof, tying accumulator activity
/// to the holder of `ask`.
///
/// `ak` **cannot verify action signatures directly** — the prover uses
/// [`derive_action_public`](Self::derive_action_public) to compute the
/// per-action `rk` for the proof witness. Component of
/// [`ProofAuthorizingKey`] for proof authorization
/// without spend authority.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct SpendValidatingKey(pub(super) reddsa::VerificationKey<SpendAuth>);

impl SpendValidatingKey {
    /// Derive the per-action public (verification) key: $\mathsf{rk} =
    /// \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    ///
    /// Only accepts [`SpendRandomizer`] — output actions derive `rk` via
    /// [`ActionSigningKey<Output>::derive_action_public`](super::private::ActionSigningKey::derive_action_public)
    /// instead.
    ///
    /// Used by the prover (who has
    /// [`ProofAuthorizingKey`] containing `ak`)
    /// to compute the `rk` that the Ragu circuit constrains. During
    /// action construction the signer derives `rk` via
    /// [`ActionSigningKey<Spend>::derive_action_public`](super::private::ActionSigningKey::derive_action_public)
    /// instead.
    #[must_use]
    pub fn derive_action_public(&self, alpha: &SpendRandomizer) -> public::ActionVerificationKey {
        public::ActionVerificationKey(self.0.randomize(&alpha.0))
    }
}
