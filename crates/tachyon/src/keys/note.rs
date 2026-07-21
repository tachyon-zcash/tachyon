//! Note-related keys: NullifierKey, PaymentKey.

use derive_more::{Debug, Eq as TotalEq, PartialEq};
use ff::PrimeField as _;
use pasta_curves::Fp;

use super::proof::SpendValidatingKey;
use crate::{
    EpochIndex,
    digest::poseidon,
    nullifier::{self, Nullifier, NullifierTrace},
};

/// A Tachyon nullifier deriving key, which seeds the per-note master key.
///
/// ## Capabilities
///
/// - **Nullifier derivation**: detecting when a note has been spent
///
/// `nk` alone does NOT confer spend authority — combined with `ak` it
/// forms the proof authorizing key `pak`, enabling proof construction
/// and nullifier derivation without signing capability.
#[derive(Clone, Copy, Debug)]
pub struct NullifierKey(#[debug(skip)] pub(super) Fp);

impl NullifierKey {
    /// Derive a note's master key from its nullifier trapdoor.
    #[must_use]
    pub fn derive_note_private(&self, psi: nullifier::Trapdoor) -> NoteMasterKey {
        let (mk_r, mk_w) = poseidon::nf_master_key(psi.into(), self.0);
        NoteMasterKey(mk_r, mk_w)
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
pub struct PaymentKey(#[debug(skip)] pub(crate) Fp);

impl PaymentKey {
    /// Derive the payment key from `ak` and `nk`:
    /// $\mathsf{pk} = \text{Poseidon}(\text{PK\_DOMAIN}, \mathsf{ak}_x,
    /// \mathsf{nk})$.
    #[must_use]
    pub fn derive(ak: &SpendValidatingKey, nk: &NullifierKey) -> Self {
        let ak_bytes: [u8; 32] = ak.0.into();
        let ak_fp = Fp::from_repr(ak_bytes).expect("ak bytes should be a valid Fp");
        Self(poseidon::payment_key(ak_fp, nk.0))
    }
}

/// Per-note master key $\mathsf{mk} = \[k, w\]$ representing a round key and
/// whitening key.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct NoteMasterKey(#[debug(skip)] pub(crate) Fp, #[debug(skip)] pub(crate) Fp);

impl NoteMasterKey {
    /// Derive a nullifier for the given epoch.
    #[must_use]
    pub fn derive_nullifier(&self, epoch: EpochIndex) -> Nullifier {
        Nullifier::derive(self, epoch)
    }

    /// Derive the nullifier trace for the given epoch.
    #[must_use]
    pub fn derive_nullifier_trace(&self, epoch: EpochIndex) -> (NullifierTrace, Nullifier) {
        Nullifier::derive_trace(self, epoch)
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::primitives::EpochIndex;

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
}
