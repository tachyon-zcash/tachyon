//! Note-related keys: NullifierKey, PaymentKey.

use derive_more::{AsRef, Debug, From, Into};
use group::GroupEncoding as _;
use pasta_curves::{EpAffine, Fp, arithmetic::CurveAffine as _};

use super::{ggm::NoteMasterKey, proof::SpendValidatingKey};
use crate::{digest::poseidon, nullifier};

/// A Tachyon nullifier deriving key.
///
/// Tachyon simplifies Orchard's nullifier construction
/// ("Tachyaction at a Distance", Bowe 2025):
///
/// $$\mathsf{nf} = F_{\mathsf{nk}}(\Psi \| e)$$
///
/// where $F$ is a keyed PRF (Poseidon), $\Psi$ is the note's nullifier
/// trapdoor, and $e$ is the epoch index. This replaces Orchard's more
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
pub struct NullifierKey(#[debug(skip)] pub(super) Fp);

impl NullifierKey {
    /// Derive a note's GGM master root from its nullifier trapdoor `psi`.
    #[must_use]
    pub fn derive_note_private(&self, psi: nullifier::Trapdoor) -> NoteMasterKey {
        NoteMasterKey(poseidon::nf_master(psi.into(), self.0))
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
/// \mathsf{ak}_y, \mathsf{nk})$$
///
/// where $(\mathsf{ak}_x, \mathsf{ak}_y)$ are the affine coordinates of the
/// spend validating key.
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
#[derive(Clone, Copy, Debug, AsRef, From, Into)]
pub struct PaymentKey(#[debug(skip)] Fp);

impl PaymentKey {
    /// Derive the payment key from `ak` and `nk`:
    /// $\mathsf{pk} = \text{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x,
    /// \mathsf{ak}_y, \mathsf{nk})$.
    ///
    /// # Panics
    ///
    /// Panics if `ak` is the identity, which has no affine coordinates.
    #[must_use]
    pub fn derive(ak: &SpendValidatingKey, nk: &NullifierKey) -> Self {
        let ak_bytes: [u8; 32] = ak.0.into();
        #[expect(clippy::expect_used, reason = "a validating key is a curve point")]
        let point = EpAffine::from_bytes(&ak_bytes)
            .into_option()
            .expect("ak bytes should be a valid curve point");
        #[expect(clippy::expect_used, reason = "a validating key is not the identity")]
        let coords = point
            .coordinates()
            .into_option()
            .expect("ak must not be the identity");
        Self(poseidon::payment_key(coords, nk.0))
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{primitives::EpochIndex, reddsa};

    /// reddsa accepts the identity as a verification key, but it has no affine
    /// coordinates to absorb.
    #[test]
    #[should_panic(expected = "identity")]
    fn derive_rejects_identity_ak() {
        let rng = &mut StdRng::seed_from_u64(0);
        let ak = SpendValidatingKey(
            reddsa::VerificationKey::try_from([0u8; 32]).expect("identity is a valid key"),
        );
        let nk = NullifierKey(Fp::random(rng));

        let _derived = PaymentKey::derive(&ak, &nk);
    }

    #[test]
    fn derive_note_private_deterministic() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = nullifier::Trapdoor::random(rng);
        let mk1 = nk.derive_note_private(psi);
        let mk2 = nk.derive_note_private(psi);
        assert_eq!(mk1, mk2);
    }

    #[test]
    fn different_psi_different_mk() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi1 = nullifier::Trapdoor::random(rng);
        let psi2 = nullifier::Trapdoor::random(rng);
        let mk1 = nk.derive_note_private(psi1);
        let mk2 = nk.derive_note_private(psi2);
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn different_epochs_different_nullifiers() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = nullifier::Trapdoor::random(rng);
        let mk = nk.derive_note_private(psi);
        assert_ne!(
            mk.derive_nullifier(EpochIndex(0u32)),
            mk.derive_nullifier(EpochIndex(1u32)),
        );
    }

    /// Delegate key produces same nullifiers as master for epochs in range.
    #[test]
    fn delegate_matches_master() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = nullifier::Trapdoor::random(rng);
        let mk = nk.derive_note_private(psi);

        for dk in &mk.derive_note_delegates(0..=99) {
            for epoch in dk.range() {
                assert_eq!(
                    mk.derive_nullifier(EpochIndex(epoch)),
                    dk.derive_nullifier(EpochIndex(epoch)),
                    "mismatch at epoch {epoch} with delegate {dk:?}"
                );
            }
        }
    }

    /// A delegate key panics for epochs outside its authorized range.
    #[test]
    #[should_panic(expected = "epoch out of range")]
    fn delegate_rejects_outside_range() {
        let rng = &mut StdRng::seed_from_u64(0);
        let nk = NullifierKey(Fp::random(&mut *rng));
        let psi = nullifier::Trapdoor::random(rng);
        let mk = nk.derive_note_private(psi);

        // Delegate covering [0..=63]
        let dk = &mk.derive_note_delegates(0..=63)[0];
        // epoch 64 is outside the authorized range
        let _compute = dk.derive_nullifier(EpochIndex(64u32));
    }
}
