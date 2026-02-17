use ff::{FromUniformBytes as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand::{CryptoRng, RngCore};

use crate::{constants::ALPHA_PERSONALIZATION, note};

/// Per-action entropy chosen by the signer (e.g. hardware wallet).
///
/// 32 bytes of randomness combined with a note commitment to
/// deterministically derive [`SpendAuthRandomizer`] ($\alpha$).
/// The signer picks $\theta$ once; any device with $\theta$ and the
/// note can independently reconstruct $\alpha$.
#[derive(Clone, Copy, Debug)]
pub struct SpendAuthEntropy([u8; 32]);

impl SpendAuthEntropy {
    /// Sample fresh per-action entropy.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// Per-action spend authorization randomizer $\alpha$.
///
/// Deterministically derived from [`SpendAuthEntropy`] and a note commitment:
///
/// $$\alpha = \text{ToScalar}(\text{BLAKE2b-512}(\text{"Tachyon-AlphaDrv"},\;
///   \theta \| \mathsf{cmx}))$$
///
/// This binding lets a hardware wallet sign ($\mathsf{rsk} = \mathsf{ask} +
/// \alpha$) independently of the proof, which can be constructed later on a
/// separate device that knows $\theta$ and $\mathsf{cmx}$.
///
/// Used to derive:
/// - $\mathsf{rsk} = \mathsf{ask} + \alpha$ via
///   [`SpendAuthorizingKey::derive_action_private`](crate::keys::SpendAuthorizingKey::derive_action_private)
/// - $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$ via
///   [`SpendValidatingKey::derive_action_public`](crate::keys::SpendValidatingKey::derive_action_public)
///
/// Each action gets a fresh $\alpha$, ensuring $\mathsf{rk}$ is unlinkable to
/// $\mathsf{ak}$.
#[derive(Clone, Copy, Debug)]
pub struct SpendAuthRandomizer(Fq);

impl SpendAuthRandomizer {
    /// Access the inner scalar (crate-internal).
    pub(crate) const fn inner(&self) -> &Fq {
        &self.0
    }

    /// Derive $\alpha$ deterministically from per-action randomness and
    /// a note commitment.
    ///
    /// $$\alpha =
    /// \text{ToScalar}(\text{BLAKE2b-512}(\text{"Tachyon-AlphaDrv"},\;
    ///   \theta \| \mathsf{cmx}))$$
    #[must_use]
    pub fn derive(theta: &SpendAuthEntropy, cmx: &note::Commitment) -> Self {
        let hash = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(ALPHA_PERSONALIZATION)
            .to_state()
            .update(&theta.0)
            .update(&Fp::from(*cmx).to_repr())
            .finalize();
        Self(Fq::from_uniform_bytes(hash.as_array()))
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<Fq> for SpendAuthRandomizer {
    /// Extract the raw scalar for circuit witness extraction.
    fn into(self) -> Fq {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        action::Action,
        keys::SpendingKey,
        note::{CommitmentTrapdoor, Note, NullifierTrapdoor, Value},
        primitives::Epoch,
    };

    /// Actions constructed with different theta (all else equal) must
    /// produce different rk values — theta is the source of per-action
    /// unlinkability.
    #[test]
    fn different_theta_produces_different_rk() {
        let mut rng = StdRng::seed_from_u64(0);

        let sk = SpendingKey::from([0x42u8; 32]);
        let ask = sk.spend_authorizing_key();
        let nk = sk.nullifier_key();
        let note = Note {
            pk: sk.payment_key(),
            value: Value::from(1000u64),
            psi: NullifierTrapdoor::from(Fp::ZERO),
            rcm: CommitmentTrapdoor::from(Fq::ZERO),
        };
        let flavor = Epoch::from(Fp::ONE);
        let nf = note.nullifier(&nk, flavor);

        let theta_a = SpendAuthEntropy([0x01u8; 32]);
        let theta_b = SpendAuthEntropy([0x02u8; 32]);

        let (action_a, witness_a) = Action::spend(&ask, note, nf, flavor, &theta_a, &mut rng);
        let (action_b, witness_b) = Action::spend(&ask, note, nf, flavor, &theta_b, &mut rng);

        // Control: deterministic witness fields are identical
        assert_eq!(witness_a.tachygram, witness_b.tachygram);
        assert_eq!(witness_a.flavor, witness_b.flavor);

        // Property: theta -> alpha -> rk, so different theta -> different rk
        let rk_a: [u8; 32] = action_a.rk.into();
        let rk_b: [u8; 32] = action_b.rk.into();
        assert_ne!(rk_a, rk_b);
    }
}
