//! Note-related keys: NullifierKey, PaymentKey.

use ff::PrimeField as _;
// TODO(#39): replace halo2_poseidon with Ragu Poseidon params
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use super::{ggm::NoteMasterKey, proof::SpendValidatingKey};
use crate::{
    constants::{NOTE_MASTER_DOMAIN, PAYMENT_KEY_DOMAIN},
    note,
    primitives::NoteId,
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
    pub fn derive_note_private(&self, psi: &note::NullifierTrapdoor) -> NoteMasterKey {
        #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
        let personalization = Fp::from_u128(u128::from_le_bytes(*NOTE_MASTER_DOMAIN));
        NoteMasterKey(
            Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
                personalization,
                psi.0,
                self.0,
            ]),
        )
    }

    /// Provides the note identity binding: `H(domain, mk, cm)`.
    ///
    /// Computes the master key and note commitment internally.
    ///
    /// This method is located here and not on `NoteMasterKey` to encourage the
    /// correct relationship between master key and note commitment.
    #[must_use]
    pub fn note_id(&self, note: &note::Note) -> NoteId {
        NoteId::derive(self, note)
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
/// Derived from the proof authorizing key components:
///
/// $$\mathsf{pk} = \text{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x,
/// \mathsf{nk})$$
///
/// where $\mathsf{ak}_x$ is the x-coordinate of the spend validating key.
/// This binds `pk` to both `ak` and `nk`, so the note commitment `cm`
/// (which contains `pk`) transitively pins the full proof authorizing key.
/// Wrong `nk` produces wrong `pk`, wrong `cm`, and accumulator inclusion
/// fails.
///
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

impl PaymentKey {
    /// Derive the payment key from `ak` and `nk`:
    /// $\mathsf{pk} = \text{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x,
    /// \mathsf{nk})$.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "sign-normalized ak (tilde_y=0) is always a valid Fp repr"
    )]
    pub fn derive(ak: &SpendValidatingKey, nk: &NullifierKey) -> Self {
        #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
        let domain = Fp::from_u128(u128::from_le_bytes(*PAYMENT_KEY_DOMAIN));

        let ak_bytes: [u8; 32] = ak.0.into();
        let ak_x =
            Option::from(Fp::from_repr(ak_bytes)).expect("sign-normalized ak should be a valid Fp");

        Self(Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([domain, ak_x, nk.0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::Epoch;

    #[test]
    fn derive_note_private_deterministic() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = note::NullifierTrapdoor::from(Fp::from(99u64));
        let mk1 = nk.derive_note_private(&psi);
        let mk2 = nk.derive_note_private(&psi);
        assert_eq!(mk1, mk2);
    }

    #[test]
    fn different_psi_different_mk() {
        let nk = NullifierKey(Fp::from(42u64));
        let mk1 = nk.derive_note_private(&note::NullifierTrapdoor::from(Fp::from(1u64)));
        let mk2 = nk.derive_note_private(&note::NullifierTrapdoor::from(Fp::from(2u64)));
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn different_epochs_different_nullifiers() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = note::NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);
        assert_ne!(
            mk.derive_nullifier(Epoch::from(0u32)),
            mk.derive_nullifier(Epoch::from(1u32)),
        );
    }

    /// Delegate key produces same nullifiers as master for epochs in range.
    #[test]
    fn delegate_matches_master() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = note::NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);

        for dk in &mk.derive_note_delegates(0..=99) {
            for epoch in dk.range() {
                assert_eq!(
                    mk.derive_nullifier(Epoch::from(epoch)),
                    dk.derive_nullifier(Epoch::from(epoch)),
                    "mismatch at epoch {epoch} with delegate {dk:?}"
                );
            }
        }
    }

    /// A delegate key panics for epochs outside its authorized range.
    #[test]
    #[should_panic(expected = "epoch out of range")]
    fn delegate_rejects_outside_range() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = note::NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);

        // Delegate covering [0..=63]
        let dk = &mk.derive_note_delegates(0..=63)[0];
        // epoch 64 is outside the authorized range
        let _compute = dk.derive_nullifier(Epoch::from(64u32));
    }
}
