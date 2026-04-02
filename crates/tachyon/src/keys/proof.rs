//! Proof-related keys: ProofAuthorizingKey.

use super::{
    note::{NullifierKey, PaymentKey},
    public,
};
use crate::{entropy::ActionRandomizer, primitives::effect, reddsa};

/// The proof authorizing key (`ak` + `nk`).
///
/// Authorizes proof construction without spend authority. The holder can
/// construct proofs for all notes (since `nk` is wallet-wide) but cannot
/// sign actions.
///
/// Derived from
/// [`reddsa::ActionAuthorizingKey`](super::reddsa::ActionAuthorizingKey) $\to$
/// [`SpendValidatingKey`] and [`NullifierKey`].
///
/// ## Status
///
/// Currently a data holder — no proof-construction methods yet. These will be
/// added once the Ragu PCD circuit is integrated and proof delegation is
/// specified.
// TODO: add proof-construction methods (e.g., create_action_proof, create_merge_proof)
// once the Ragu circuit API is available.
#[derive(Clone, Copy, Debug)]
pub struct ProofAuthorizingKey {
    /// The spend validating key `ak = [ask] G`.
    pub ak: SpendValidatingKey,
    /// The nullifier deriving key.
    pub nk: NullifierKey,
}

impl ProofAuthorizingKey {
    /// Derive the payment key $\mathsf{pk}$ from `ak` and `nk`.
    ///
    /// Allows the pak holder to compute `pk` without access to `sk`.
    #[must_use]
    pub fn derive_payment_key(&self) -> PaymentKey {
        PaymentKey::derive(&self.ak, &self.nk)
    }
}

/// The spend validating key $\mathsf{ak} = [\mathsf{ask}]\,\mathcal{G}$ —
/// the long-lived counterpart of
/// [`reddsa::ActionAuthorizingKey`](super::reddsa::ActionAuthorizingKey).
///
/// Corresponds to the "spend validating key" in Orchard (§4.2.3).
/// Constrains per-action `rk` in the proof, tying accumulator activity
/// to the holder of `ask`.
///
/// `ak` **cannot verify action signatures directly** — the prover uses
/// [`derive_action_public`](Self::derive_action_public) to compute the
/// per-action `rk` for the proof witness. Component of
/// [`ProofAuthorizingKey`](super::ProofAuthorizingKey) for proof authorization
/// without spend authority.
#[derive(Clone, Copy, Debug)]
pub struct SpendValidatingKey(pub(crate) reddsa::VerificationKey<reddsa::ActionAuth>);

impl SpendValidatingKey {
    /// Derive the per-action public (verification) key: $\mathsf{rk} =
    /// \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    ///
    /// Only accepts [`ActionRandomizer<Spend>`] — output actions derive `rk`
    /// via
    /// [`ActionSigningKey<Output>::derive_action_public`](super::private::ActionSigningKey::derive_action_public)
    /// instead.
    ///
    /// Used by the prover (who has
    /// [`ProofAuthorizingKey`](super::ProofAuthorizingKey) containing `ak`)
    /// to compute the `rk` that the Ragu circuit constrains. During
    /// action construction the signer derives `rk` via
    /// [`ActionSigningKey<Spend>::derive_action_public`](super::private::ActionSigningKey::derive_action_public)
    /// instead.
    #[must_use]
    pub fn derive_action_public(
        &self,
        alpha: &ActionRandomizer<effect::Spend>,
    ) -> public::ActionVerificationKey {
        public::ActionVerificationKey(self.0.randomize(&alpha.0))
    }
}
