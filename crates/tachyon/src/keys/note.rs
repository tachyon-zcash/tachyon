//! Note-related keys: NullifierKey, PaymentKey.

use derive_more::{AsRef, Debug, From, Into};
use group::GroupEncoding as _;
use pasta_curves::{EpAffine, Fp, arithmetic::CurveAffine as _};

use super::{master::NoteMasterKey, proof::SpendValidatingKey};
use crate::{digest::poseidon, nullifier};

/// A Tachyon nullifier deriving key.
///
/// Tachyon simplifies Orchard's nullifier construction
/// ("Tachyaction at a Distance", Bowe 2025):
///
/// $$
///   \mathsf{nf} = F_{\mathsf{nk}}(\Psi \Vert e)
/// $$
///
/// where $F$ is a keyed PRF (Poseidon), $\Psi$ is the note's nullifier
/// trapdoor, and $e$ is the epoch index. This replaces Orchard's more
/// complex construction that defended against faerie gold attacks, which
/// are moot under out-of-band payments.
///
/// ## Capabilities
///
/// - **Nullifier derivation**: detecting when a note has been spent
/// - **Oblivious sync delegation**: a delegate receives proven value windows.
///   The master key $\mathsf{mk} = \mathsf{Poseidon}_\texttt{Tachyon-NfMaster}(
///   \Psi, \mathsf{nk})$ evaluates every epoch.
///
/// `nk` alone does NOT confer spend authority; combined with `ak` it
/// forms the proof authorizing key `pak`, enabling proof construction
/// and nullifier derivation without signing capability.
#[derive(Clone, Copy, Debug)]
pub struct NullifierKey(#[debug(skip)] pub(super) Fp);

impl NullifierKey {
    /// Derive a note's master key from its nullifier trapdoor `psi`.
    #[must_use]
    pub fn derive_note_private(&self, psi: nullifier::Trapdoor) -> NoteMasterKey {
        NoteMasterKey(poseidon::nf_master(psi.into(), self.0))
    }
}

/// A Tachyon payment key: a recipient identifier, minted fresh per sender.
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
/// $$
///   \mathsf{pk} = \text{Poseidon}_\texttt{Tachyon-PkDerive}(
///     \mathsf{ak}_x,\ \mathsf{ak}_y,\ \mathsf{nk}
///   )
/// $$
///
/// where $(\mathsf{ak}_x, \mathsf{ak}_y)$ are the affine coordinates of the
/// spend validating key.
/// This binds `pk` to both `ak` and `nk`, so the note commitment `cm`
/// (which contains `pk`) transitively pins the full proof authorizing key.
/// Wrong `nk` produces wrong `pk`, wrong `cm`, and accumulator inclusion
/// fails.
///
/// `pk` is deterministic in `(ak, nk)`, so unlinkability comes from minting
/// a fresh address per sender: a receiver walks its wallet-standard
/// derivation path to a freshly indexed `(ak, nk)` pair. That index sits
/// above `sk`, so [`SpendingKey`](super::private::SpendingKey) takes it
/// already applied and no derivation path is fixed here. Transfer proofs
/// never constrain it; they check `pk` against a witnessed `pak`.
///
/// ## Usage
///
/// The recipient's `pk` appears in the note and is committed to in the
/// note commitment. It is NOT an on-chain address; payment coordination
/// happens out-of-band via higher-level protocols (ZIP 321 payment
/// requests, ZIP 324 URI encapsulated payments).
#[derive(AsRef, Clone, Copy, Debug, From, Into)]
pub struct PaymentKey(#[debug(skip)] Fp);

impl PaymentKey {
    /// Derive the payment key from `ak` and `nk`:
    ///
    /// $$
    ///   \mathsf{pk} = \text{Poseidon}_\texttt{Tachyon-PkDerive}(
    ///     \mathsf{ak}_x,\ \mathsf{ak}_y,\ \mathsf{nk}
    ///   )
    /// $$
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
    use proptest::prelude::*;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{constants::EPOCH_MAX, primitives::EpochIndex, reddsa, testing::check};

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

    /// mk is a function of (nk, psi): another psi gives another mk.
    #[test]
    fn master_key_is_a_function_of_nk_and_psi() {
        check(256, any::<u64>(), |seed| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let nk = NullifierKey(Fp::random(&mut *rng));
            let psi = nullifier::Trapdoor::random(rng);
            let other = nullifier::Trapdoor::random(rng);
            prop_assert_ne!(nk.derive_note_private(psi), nk.derive_note_private(other));
            Ok(())
        });
    }

    /// Distinct epochs take distinct nullifiers, within a sponge group and
    /// across groups.
    #[test]
    fn distinct_epochs_take_distinct_nullifiers() {
        let strategy = (any::<u64>(), 0..=EPOCH_MAX, 0..=EPOCH_MAX);
        check(256, strategy, |(seed, first, second)| {
            prop_assume!(first != second);
            let rng = &mut StdRng::seed_from_u64(seed);
            let psi = nullifier::Trapdoor::random(rng);
            let mk = NullifierKey(Fp::random(&mut *rng)).derive_note_private(psi);
            prop_assert_ne!(
                mk.derive_nullifier(EpochIndex::new(first)),
                mk.derive_nullifier(EpochIndex::new(second))
            );
            Ok(())
        });
    }

    #[test]
    fn debug_redacts_the_nullifier_trapdoor() {
        check(256, any::<u64>(), |seed| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let [left, right] = [
                nullifier::Trapdoor::random(rng),
                nullifier::Trapdoor::random(rng),
            ]
            .map(|psi| alloc::format!("{psi:?}"));
            prop_assert!(left.contains("Trapdoor"));
            prop_assert_eq!(left, right);
            Ok(())
        });
    }
}
