//! Private keys — user-device confidential, not delegated.
//!
//! Keys in this module remain on the user's device.  They are never
//! shared with external parties (provers, sync services).  Compromise
//! means privacy loss, not fund loss.

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use reddsa::orchard::SpendAuth;

use super::{delegated, public};
use crate::{
    entropy,
    note::{Nullifier, NullifierTrapdoor},
    primitives::Epoch,
};

// ---------------------------------------------------------------------------
// Spend validating key (ak)
// ---------------------------------------------------------------------------

/// The spend validating key $\mathsf{ak} = [\mathsf{ask}]\,\mathcal{G}$ —
/// the long-lived counterpart of
/// [`SpendAuthorizingKey`](super::custody::SpendAuthorizingKey).
///
/// Corresponds to the "spend validating key" in Orchard (§4.2.3).
/// Constrains per-action `rk` in the proof, tying accumulator activity
/// to the holder of `ask`.
///
/// `ak` **cannot verify action signatures directly** — the prover uses
/// [`derive_action_public`](Self::derive_action_public) to compute the
/// per-action `rk` for the proof witness. Component of
/// [`ProofAuthorizingKey`](delegated::ProofAuthorizingKey) for proof
/// authorization without spend authority.
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct SpendValidatingKey(pub(super) reddsa::VerificationKey<SpendAuth>);

impl SpendValidatingKey {
    /// Derive the per-action public (verification) key: $\mathsf{rk} =
    /// \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    ///
    /// Used by the prover (who has
    /// [`ProofAuthorizingKey`](delegated::ProofAuthorizingKey) containing `ak`)
    /// to compute the `rk` that the Ragu circuit constrains. During
    /// action construction the signer derives `rk` via
    /// [`ActionSigningKey::derive_action_public`](super::custody::ActionSigningKey::derive_action_public)
    /// instead.
    #[must_use]
    pub fn derive_action_public(
        &self,
        alpha: &entropy::ActionRandomizer,
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

// ---------------------------------------------------------------------------
// Nullifier key hierarchy (nk → mk)
// ---------------------------------------------------------------------------

/// A Tachyon nullifier deriving key.
///
/// Tachyon simplifies Orchard's nullifier construction
/// ("Tachyaction at a Distance", Bowe 2025):
///
/// $$\mathsf{nf} = F_{\mathsf{nk}}(\Psi \| \text{flavor})$$
///
/// where $F$ is a keyed PRF (Poseidon), $\Psi$ is the note's nullifier
/// trapdoor, and flavor is the epoch-id. This replaces Orchard's more
/// complex construction that defended against faerie gold attacks — which
/// are moot under out-of-band payments.
///
/// ## Capabilities
///
/// - **Nullifier derivation**: detecting when a note has been spent
/// - **Oblivious sync delegation** (Nullifier Derivation Scheme doc): the
///   master root key $\mathsf{mk} = \text{KDF}(\Psi, \mathsf{nk})$ seeds a GGM
///   tree PRF; prefix keys $\Psi_t$ permit evaluating the PRF only for epochs
///   $e \leq t$, enabling range-restricted delegation without revealing spend
///   capability
///
/// `nk` alone does NOT confer spend authority — combined with `ak` it
/// forms the proof authorizing key `pak`, enabling proof construction
/// and nullifier derivation without signing capability.
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct NullifierKey(pub(super) Fp);

impl NullifierKey {
    /// Derive the per-note master root key: $\mathsf{mk} = \text{KDF}(\psi,
    /// \mathsf{nk})$.
    ///
    /// `mk` is the root of the GGM tree for one note. It is used to:
    /// - Derive nullifiers directly: $\mathsf{nf} =
    ///   F_{\mathsf{mk}}(\text{flavor})$
    /// - Derive epoch-restricted prefix keys $\Psi_t$ for OSS delegation
    #[must_use]
    pub fn derive_note_private(&self, _psi: &NullifierTrapdoor) -> NoteMasterKey {
        todo!("Poseidon KDF");
        NoteMasterKey(Fp::ZERO)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for NullifierKey {
    fn into(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

/// Per-note master root key $\mathsf{mk} = \text{KDF}(\psi, \mathsf{nk})$.
///
/// Root of the GGM tree PRF for a single note. Derived by the user device
/// from [`NullifierKey`] and the note's $\psi$ trapdoor.
///
/// ## Delegation chain
///
/// ```text
/// nk + psi → mk (per-note root, user device)
///              ├── nf = F_mk(flavor)     nullifier for a specific epoch
///              └── psi_t = GGM(mk, t)    prefix key for epochs e ≤ t (OSS)
/// ```
///
/// `mk` is not stored or transmitted — the user device derives it
/// ephemerally when needed. The OSS receives only the prefix keys.
#[derive(Clone, Copy, Debug)]
pub struct NoteMasterKey(Fp);

impl NoteMasterKey {
    /// Derive a nullifier for a specific epoch: $\mathsf{nf} =
    /// F_{\mathsf{mk}}(\text{flavor})$.
    ///
    /// GGM tree walk over the bits of `flavor`. The user device calls
    /// this directly; the OSS uses
    /// [`NoteDelegateKey::derive_nullifier`](delegated::NoteDelegateKey::derive_nullifier)
    /// instead (restricted to authorized epochs).
    #[must_use]
    pub fn derive_nullifier(&self, _flavor: Epoch) -> Nullifier {
        todo!("GGM tree PRF evaluation");
        Nullifier::from(Fp::ZERO)
    }

    /// Derive an epoch-restricted prefix key $\Psi_t$ for OSS delegation.
    ///
    /// The prefix key allows evaluating $\mathsf{nf}_e = F_{\mathsf{mk}}(e)$
    /// for epochs $e \leq t$ only. The OSS cannot compute nullifiers for
    /// future epochs $e > t$.
    ///
    /// When the chain advances past $t$, the user device sends a delta
    /// prefix key covering the new range $(t..t']$.
    #[must_use]
    pub fn derive_note_delegate(
        &self,
        _epoch: Epoch,
    ) -> delegated::NoteDelegateKey {
        todo!("GGM tree prefix key derivation");
        delegated::NoteDelegateKey(Fp::ZERO)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for NoteMasterKey {
    fn into(self) -> [u8; 32] {
        self.0.to_repr()
    }
}
