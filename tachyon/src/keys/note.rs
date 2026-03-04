//! Note-related keys: NullifierKey, MasterRootKey, PrefixKey, PaymentKey.

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;

use crate::{
    note::{Nullifier, NullifierTrapdoor},
    primitives::Epoch,
};

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
    /// this directly; the OSS uses [`NoteDelegateKey::derive_nullifier`]
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
    pub fn derive_note_delegate(&self, _epoch: Epoch) -> NoteDelegateKey {
        todo!("GGM tree prefix key derivation");
        NoteDelegateKey(Fp::ZERO)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for NoteMasterKey {
    fn into(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

/// Epoch-restricted GGM prefix key $\Psi_t$.
///
/// Derived from [`NoteMasterKey`] for a specific epoch bound $t$.
/// Held by the Oblivious Syncing Service (OSS) to evaluate nullifiers
/// $\mathsf{nf}_e = F_{\mathsf{mk}}(e)$ for epochs $e \leq t$ without
/// learning `mk` or `nk`.
///
/// ## Security boundary
///
/// - **Can**: derive nullifiers for epochs $e \leq t$ of one note
/// - **Cannot**: derive nullifiers for future epochs $e > t$
/// - **Cannot**: recover `mk` or `nk` from the prefix key
/// - **Cannot**: derive prefix keys for other notes
#[derive(Clone, Copy, Debug)]
pub struct NoteDelegateKey(Fp);

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
