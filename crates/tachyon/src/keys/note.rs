//! Note-related keys: NullifierKey, PaymentKey.

use core::fmt;

use ff::PrimeField as _;
use pasta_curves::Fp;

use super::proof::SpendValidatingKey;
use crate::digest::poseidon;

/// A Tachyon nullifier deriving key.
///
/// In Tachyon, each note's per-epoch nullifiers are coefficients of a
/// pronullifier polynomial $M$ committed into `cm` as $\psi = \sum_i M_i G_i$,
/// so `nk` no longer seeds a per-note PRF directly. `nk` still binds the note:
/// it feeds the payment key $\mathsf{pk} = \text{Poseidon}(\text{domain},
/// \mathsf{ak}_x, \mathsf{nk})$, which sits inside `cm`.
///
/// `nk` alone does NOT confer spend authority — combined with `ak` it
/// forms the proof authorizing key `pak`, enabling proof construction
/// without signing capability.
#[derive(Clone, Copy)]
pub struct NullifierKey(pub(super) Fp);

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
#[derive(Clone, Copy)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct PaymentKey(pub(crate) Fp);

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

impl fmt::Debug for NullifierKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NullifierKey").finish_non_exhaustive()
    }
}

impl fmt::Debug for PaymentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymentKey").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::keys::private::SpendingKey;

    /// `derive` is a pure function of `(ak, nk)`.
    #[test]
    fn payment_key_deterministic() {
        let rng = &mut StdRng::seed_from_u64(0);
        let sk = SpendingKey::random(rng);
        let ak = sk.derive_auth_private().derive_auth_public();
        let nk = sk.derive_nullifier_private();
        assert_eq!(
            PaymentKey::derive(&ak, &nk).0,
            PaymentKey::derive(&ak, &nk).0
        );
    }

    /// Varying `nk` (with `ak` fixed) changes `pk` — `nk` is pinned into the
    /// note commitment through `pk`.
    #[test]
    fn payment_key_binds_nk() {
        let rng = &mut StdRng::seed_from_u64(0);
        let sk = SpendingKey::random(rng);
        let ak = sk.derive_auth_private().derive_auth_public();
        let nk = sk.derive_nullifier_private();
        let nk_other = NullifierKey(nk.0 + Fp::ONE);
        assert_ne!(
            PaymentKey::derive(&ak, &nk).0,
            PaymentKey::derive(&ak, &nk_other).0
        );
    }
}
