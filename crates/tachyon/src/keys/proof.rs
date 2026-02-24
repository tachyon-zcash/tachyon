//! Proof-related keys: ProofAuthorizingKey.

use reddsa::orchard::SpendAuth;

use super::{note::NullifierKey, private, public};

/// The proof authorizing key (`ak` + `nk`).
///
/// Authorizes proof construction without spend authority. The holder can
/// construct proofs for all notes (since `nk` is wallet-wide) but cannot
/// sign actions.
///
/// Derived from [`SpendAuthorizingKey`](super::SpendAuthorizingKey) $\to$
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
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
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

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 64]> for ProofAuthorizingKey {
    fn into(self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        let ak_bytes: [u8; 32] = self.ak.into();
        let nk_bytes: [u8; 32] = self.nk.into();
        bytes[..32].copy_from_slice(&ak_bytes);
        bytes[32..].copy_from_slice(&nk_bytes);
        bytes
    }
}

/// The spend validating key $\mathsf{ak} = [\mathsf{ask}]\,\mathcal{G}$ —
/// the long-lived counterpart of
/// [`SpendAuthorizingKey`](super::SpendAuthorizingKey).
///
/// Corresponds to the "spend validating key" in Orchard (§4.2.3).
/// Constrains per-action `rk` in the proof, tying accumulator activity
/// to the holder of `ask`.
///
/// `ak` **cannot verify action signatures directly** — the prover uses
/// [`derive_action_public`](Self::derive_action_public) to compute the
/// per-action `rk` for the proof witness. Component of
/// [`ProofAuthorizingKey`](super::ProofAuthorizingKey) for proof authorization without spend
/// authority.
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct SpendValidatingKey(pub(super) reddsa::VerificationKey<SpendAuth>);

impl SpendValidatingKey {
    /// Derive the per-action public (verification) key: $\mathsf{rk} =
    /// \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    ///
    /// Used by the prover (who has [`ProofAuthorizingKey`](super::ProofAuthorizingKey) containing
    /// `ak`) to compute the `rk` that the Ragu circuit constrains. During
    /// action construction the signer derives `rk` via
    /// [`ActionSigningKey::derive_action_public`](super::ActionSigningKey::derive_action_public)
    /// instead.
    #[must_use]
    pub fn derive_action_public(
        &self,
        alpha: &private::ActionRandomizer,
    ) -> public::ActionVerificationKey {
        public::ActionVerificationKey(self.0.randomize(&alpha.0))
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for SpendValidatingKey {
    fn into(self) -> [u8; 32] {
        self.0.into()
    }
}
