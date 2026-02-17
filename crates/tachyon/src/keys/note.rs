//! Note-related keys: PaymentKey, NullifierKey.

#![allow(clippy::from_over_into, reason = "restricted conversions")]

use ff::{FromUniformBytes as _, PrimeField as _};
use pasta_curves::Fp;

use crate::constants::PrfExpand;

/// A Tachyon nullifier deriving key.
///
/// Used in the GGM tree PRF: $mk = \text{KDF}(\psi, nk)$, then
/// $nf = F_{mk}(\text{flavor})$. This key enables:
///
/// - **Nullifier derivation**: detecting when a note has been spent
/// - **Oblivious sync delegation**: prefix keys $\Psi_t$ derived from $mk$
///   permit evaluating the PRF only for epochs $e \leq t$
///
/// `nk` alone does NOT confer spend authority — it only allows observing
/// spend status and constructing proofs (when combined with `ak`).
///
/// ## Status
///
/// Currently only exposes `Into<Fp>`. Nullifier derivation is implemented
/// externally in [`note::Nullifier`](crate::note::Nullifier). The GGM tree
/// PRF and prefix key delegation are not yet implemented.
// TODO: implement GGM tree PRF methods for oblivious sync delegation
// (derive_master_key, derive_prefix_key, etc.)
#[derive(Clone, Copy, Debug)]
pub struct NullifierKey(Fp);

impl NullifierKey {
    /// Derive `nk` from raw spending key bytes.
    pub(super) fn from_sk(sk: &[u8; 32]) -> Self {
        Self(Fp::from_uniform_bytes(&PrfExpand::NK.with(sk)))
    }
}

impl Into<Fp> for NullifierKey {
    fn into(self) -> Fp {
        self.0
    }
}

impl Into<[u8; 32]> for NullifierKey {
    fn into(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

/// A Tachyon payment key.
///
/// Used in note construction and out-of-band payment protocols. Replaces
/// Orchard's diversified transmission key (`pk_d`) — Tachyon removes key
/// diversification from the core protocol.
///
/// The recipient's `pk` appears in the note and is committed to in the
/// note commitment. It is NOT an on-chain address; payment coordination
/// happens out-of-band (e.g. URI encapsulated payments, payment requests).
#[derive(Clone, Copy, Debug)]
pub struct PaymentKey(Fp);

impl PaymentKey {
    /// Derive `pk` from raw spending key bytes.
    pub(super) fn from_sk(sk: &[u8; 32]) -> Self {
        Self(Fp::from_uniform_bytes(&PrfExpand::PK.with(sk)))
    }
}

impl Into<Fp> for PaymentKey {
    fn into(self) -> Fp {
        self.0
    }
}

impl Into<[u8; 32]> for PaymentKey {
    fn into(self) -> [u8; 32] {
        self.0.to_repr()
    }
}
