//! Note-related keys: PaymentKey, NullifierKey.

use ff::PrimeField as _;
use pasta_curves::Fp;

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
/// - **Oblivious sync delegation** (Nullifier Derivation Scheme doc):
///   the master root key $\mathsf{mk} = \text{KDF}(\Psi, \mathsf{nk})$
///   seeds a GGM tree PRF; prefix keys $\Psi_t$ permit evaluating the
///   PRF only for epochs $e \leq t$, enabling range-restricted delegation
///   without revealing spend capability
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
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct NullifierKey(pub(super) Fp);

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for NullifierKey {
    fn into(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

/// A Tachyon payment key — static per-spending-key recipient identifier.
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
/// Deterministic per-`sk`: $\mathsf{pk} =
/// \text{ToBase}(\text{PRF}^{\text{expand}}_{\mathsf{sk}}([0\text{x}0b]))$.
/// Every note from the same spending key shares the same `pk`. There is
/// no per-note diversification — unlinkability is the wallet layer's
/// responsibility, not the core protocol's.
///
/// ## Usage
///
/// The recipient's `pk` appears in the note and is committed to in the
/// note commitment. It is NOT an on-chain address; payment coordination
/// happens out-of-band via higher-level protocols (ZIP 321 payment
/// requests, ZIP 324 URI encapsulated payments).
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct PaymentKey(pub(super) Fp);

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for PaymentKey {
    fn into(self) -> [u8; 32] {
        self.0.to_repr()
    }
}
