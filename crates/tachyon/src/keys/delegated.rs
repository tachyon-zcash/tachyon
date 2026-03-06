//! Delegated keys — shared with trusted external parties.
//!
//! Keys in this module are confidential material that has been packaged
//! for handoff to a trusted delegate (prover, oblivious sync service).
//! Compromise means restricted privacy loss.

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;

use super::private::{NullifierKey, SpendValidatingKey};
use crate::{note::Nullifier, primitives::Epoch};

// ---------------------------------------------------------------------------
// Proof authorizing key (pak = ak + nk)
// ---------------------------------------------------------------------------

/// The proof authorizing key (`ak` + `nk`).
///
/// Authorizes proof construction without spend authority. The holder can
/// construct proofs for all notes (since `nk` is wallet-wide) but cannot
/// sign actions.
///
/// Derived from [`SpendAuthorizingKey`](super::custody::SpendAuthorizingKey) $\to$
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

// ---------------------------------------------------------------------------
// Note delegate key (psi_t)
// ---------------------------------------------------------------------------

/// Epoch-restricted GGM prefix key $\Psi_t$.
///
/// Derived from [`NoteMasterKey`](super::private::NoteMasterKey) for a specific
/// epoch bound $t$.  Held by the Oblivious Syncing Service (OSS) to evaluate
/// nullifiers $\mathsf{nf}_e = F_{\mathsf{mk}}(e)$ for epochs $e \leq t$
/// without learning `mk` or `nk`.
///
/// ## Security boundary
///
/// - **Can**: derive nullifiers for epochs $e \leq t$ of one note
/// - **Cannot**: derive nullifiers for future epochs $e > t$
/// - **Cannot**: recover `mk` or `nk` from the prefix key
/// - **Cannot**: derive prefix keys for other notes
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct NoteDelegateKey(pub(super) Fp);

impl NoteDelegateKey {
    /// Derive a nullifier for an epoch within the authorized range:
    /// $\mathsf{nf}_e = F_{\mathsf{mk}}(e)$ for $e \leq t$.
    ///
    /// The OSS calls this to scan blocks for matching nullifiers.
    /// Evaluating an epoch outside the authorized range is not possible
    /// — the GGM prefix key only contains the subtree needed for
    /// $e \leq t$.
    #[must_use]
    pub fn derive_nullifier(&self, _flavor: Epoch) -> Nullifier {
        todo!("GGM tree PRF evaluation from prefix key");
        Nullifier::from(Fp::ZERO)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for NoteDelegateKey {
    fn into(self) -> [u8; 32] {
        self.0.to_repr()
    }
}
