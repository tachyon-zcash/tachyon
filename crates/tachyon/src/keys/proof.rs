//! Proof-related keys: ProvingKey.

#![allow(clippy::from_over_into, reason = "restricted conversions")]

use super::{note::NullifierKey, public::SpendValidatingKey};

/// The proving key (`ak` + `nk`).
///
/// Allows constructing proofs without spend authority. This might be delegated
/// to a service that constructs non-membership proofs for nullifiers without
/// learning the wallet's spending key.
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
pub struct ProvingKey {
    /// The spend validating key `ak = [ask] G`.
    ak: SpendValidatingKey,
    /// The nullifier deriving key.
    nk: NullifierKey,
}

impl ProvingKey {
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

impl From<(SpendValidatingKey, NullifierKey)> for ProvingKey {
    fn from((ak, nk): (SpendValidatingKey, NullifierKey)) -> Self {
        Self { ak, nk }
    }
}

impl Into<[u8; 64]> for ProvingKey {
    fn into(self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        let ak_bytes: [u8; 32] = self.ak.into();
        let nk_bytes: [u8; 32] = self.nk.into();
        bytes[..32].copy_from_slice(&ak_bytes);
        bytes[32..].copy_from_slice(&nk_bytes);
        bytes
    }
}
