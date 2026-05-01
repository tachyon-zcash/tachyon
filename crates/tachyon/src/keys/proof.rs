//! Proof-related keys: ProofAuthorizingKey.

use super::{
    note::{NullifierKey, PaymentKey},
    public,
};
use crate::{entropy::ActionRandomizer, primitives::effect, reddsa};

/// The proof authorizing key (`ak` + `nk`).
///
/// Authorizes proof construction without spend authority. The holder can
/// construct proofs for all notes (since `nk` is wallet-wide) but cannot
/// sign actions.
///
/// Derived from
/// [`reddsa::ActionAuthorizingKey`](super::reddsa::ActionAuthorizingKey) $\to$
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
pub struct ProofAuthorizingKey {
    /// The spend validating key `ak = [ask] G`.
    pub ak: SpendValidatingKey,
    /// The nullifier deriving key.
    pub nk: NullifierKey,
}

impl ProofAuthorizingKey {
    /// Derive the payment key $\mathsf{pk}$ from `ak` and `nk`.
    ///
    /// Allows the pak holder to compute `pk` without access to `sk`.
    #[must_use]
    pub fn derive_payment_key(&self) -> PaymentKey {
        PaymentKey::derive(&self.ak, &self.nk)
    }
}

/// The spend validating key $\mathsf{ak} = [\mathsf{ask}]\,\mathcal{G}$ —
/// the long-lived counterpart of
/// [`reddsa::ActionAuthorizingKey`](super::reddsa::ActionAuthorizingKey).
///
/// Corresponds to the "spend validating key" in Orchard (§4.2.3).
/// Constrains per-action `rk` in the proof, tying accumulator activity
/// to the holder of `ask`.
///
/// `ak` **cannot verify action signatures directly** — the prover uses
/// [`derive_action_public`](Self::derive_action_public) to compute the
/// per-action `rk` for the proof witness. Component of
/// [`ProofAuthorizingKey`](super::ProofAuthorizingKey) for proof authorization
/// without spend authority.
#[derive(Clone, Copy, Debug)]
pub struct SpendValidatingKey(pub(crate) reddsa::VerificationKey<reddsa::ActionAuth>);

impl SpendValidatingKey {
    /// Derive the per-action public (verification) key: $\mathsf{rk} =
    /// \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    ///
    /// Only accepts [`ActionRandomizer<Spend>`] — output actions derive `rk`
    /// via
    /// [`ActionSigningKey<Output>::derive_action_public`](super::private::ActionSigningKey::derive_action_public)
    /// instead.
    ///
    /// Used by the prover (who has
    /// [`ProofAuthorizingKey`](super::ProofAuthorizingKey) containing `ak`)
    /// to compute the `rk` that the Ragu circuit constrains. During
    /// action construction the signer derives `rk` via
    /// [`ActionSigningKey<Spend>::derive_action_public`](super::private::ActionSigningKey::derive_action_public)
    /// instead.
    #[must_use]
    pub fn derive_action_public(
        &self,
        alpha: &ActionRandomizer<effect::Spend>,
    ) -> public::ActionVerificationKey {
        public::ActionVerificationKey(self.0.randomize(&alpha.0))
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use crate::{
        entropy::ActionEntropy,
        keys::private,
        note::{self, Note},
        primitives::effect,
    };

    /// pak.derive_payment_key() must equal sk.derive_payment_key().
    #[test]
    fn pak_payment_key_matches_sk() {
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let pak = sk.derive_proof_private();
        assert_eq!(pak.derive_payment_key().0, sk.derive_payment_key().0);
    }

    /// SpendValidatingKey.derive_action_public(alpha) must agree with
    /// ActionSigningKey<Spend>.derive_action_public() for the same alpha.
    #[test]
    fn svk_rk_matches_signer_rk() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let pak = sk.derive_proof_private();

        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
        };
        let theta = ActionEntropy::random(&mut rng);
        let alpha = theta.randomizer::<effect::Spend>(&note.commitment());

        let rk_prover: [u8; 32] = pak.ak.derive_action_public(&alpha).0.into();
        let rk_signer: [u8; 32] = ask
            .derive_action_private(&alpha)
            .derive_action_public()
            .0
            .into();
        assert_eq!(rk_prover, rk_signer);
    }
}
