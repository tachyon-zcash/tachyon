//! Note-related keys: NullifierKey, MasterRootKey, PrefixKey, PaymentKey.

use ff::PrimeField as _;
use pasta_curves::Fp;

use crate::{
    ggm,
    note::{Nullifier, NullifierTrapdoor},
    poseidon,
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
    pub fn derive_note_private(&self, psi: &NullifierTrapdoor) -> NoteMasterKey {
        let psi_fp: Fp = (*psi).into();
        NoteMasterKey(poseidon::hash([psi_fp, self.0]))
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
    pub fn derive_nullifier(&self, flavor: Epoch) -> Nullifier {
        Nullifier::from(ggm::evaluate(self.0, u32::from(flavor)))
    }

    /// Derive an epoch-restricted prefix key $\Psi_t$ for OSS delegation.
    ///
    /// The prefix key covers epochs `0..2^bit_length(t)` — the smallest
    /// power-of-two range containing `t`. The OSS cannot compute
    /// nullifiers for epochs beyond that range.
    ///
    /// When the chain advances past $t$, the user device sends a delta
    /// prefix key covering the new range $(t..t']$.
    #[must_use]
    #[expect(clippy::expect_used, reason = "infallible usize/u8 conversions")]
    pub fn derive_note_delegate(&self, epoch: Epoch) -> NoteDelegateKey {
        let bound = u32::from(epoch);
        // Number of MSB left-child descents = leading zeros of bound.
        // For bound=0, the prefix covers only leaf 0 (full depth).
        let depth = if bound == 0 {
            ggm::TREE_DEPTH
        } else {
            usize::try_from(bound.leading_zeros()).expect("leading_zeros fits in usize")
        };
        NoteDelegateKey {
            node: ggm::prefix_node(self.0, depth),
            depth: u8::try_from(depth).expect("depth <= 32"),
        }
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
pub struct NoteDelegateKey {
    /// GGM tree node at the prefix boundary.
    node: Fp,
    /// Number of MSB levels already descended (0..=32).
    depth: u8,
}

impl NoteDelegateKey {
    /// Derive a nullifier for an epoch within the authorized range:
    /// $\mathsf{nf}_e = F_{\mathsf{mk}}(e)$ for $e \leq t$.
    ///
    /// The OSS calls this to scan blocks for matching nullifiers.
    /// Evaluating an epoch outside the authorized range is not possible
    /// — the GGM prefix key only contains the subtree needed for
    /// $e \leq t$.
    #[must_use]
    pub fn derive_nullifier(&self, flavor: Epoch) -> Nullifier {
        Nullifier::from(ggm::evaluate_from(
            self.node,
            u32::from(flavor),
            usize::from(self.depth),
        ))
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 33]> for NoteDelegateKey {
    fn into(self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[..32].copy_from_slice(&self.node.to_repr());
        out[32] = self.depth;
        out
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
pub struct PaymentKey(pub(crate) Fp);

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for PaymentKey {
    fn into(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::note::NullifierTrapdoor;

    #[test]
    fn derive_note_private_deterministic() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let bytes_1: [u8; 32] = nk.derive_note_private(&psi).into();
        let bytes_2: [u8; 32] = nk.derive_note_private(&psi).into();
        assert_eq!(bytes_1, bytes_2);
    }

    #[test]
    fn different_psi_different_mk() {
        let nk = NullifierKey(Fp::from(42u64));
        let mk1: [u8; 32] = nk
            .derive_note_private(&NullifierTrapdoor::from(Fp::from(1u64)))
            .into();
        let mk2: [u8; 32] = nk
            .derive_note_private(&NullifierTrapdoor::from(Fp::from(2u64)))
            .into();
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn different_epochs_different_nullifiers() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);
        assert_ne!(
            mk.derive_nullifier(Epoch::from(0u32)),
            mk.derive_nullifier(Epoch::from(1u32)),
        );
    }

    /// Delegate key produces same nullifier as master key for epochs
    /// within the authorized range.
    #[test]
    fn delegate_matches_master() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);

        let bound = Epoch::from(15u32); // covers 0..16
        let dk = mk.derive_note_delegate(bound);

        for epoch in 0..=15u32 {
            assert_eq!(
                mk.derive_nullifier(Epoch::from(epoch)),
                dk.derive_nullifier(Epoch::from(epoch)),
                "mismatch at epoch {epoch}"
            );
        }
    }
}
