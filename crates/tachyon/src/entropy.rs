//! Per-action randomizers and entropy.
//!
//! [`ActionEntropy`] ($\theta$) is per-action randomness chosen by the signer.
//! Combined with a note commitment it deterministically derives a
//! [`Randomizer`].

use core::marker::PhantomData;

use ff::{FromUniformBytes as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand_core::{CryptoRng, RngCore};

use crate::{
    primitives::{Output, Effect, Spend},
    constants::{OUTPUT_ALPHA_PERSONALIZATION, SPEND_ALPHA_PERSONALIZATION},
    note,
};

/// Per-action entropy $\theta$ chosen by the signer (e.g. hardware wallet).
///
/// 32 bytes of randomness combined with a note commitment to
/// deterministically derive $\alpha$ via
/// [`spend_randomizer`](Self::spend_randomizer) or
/// [`output_randomizer`](Self::output_randomizer).
/// The signer picks $\theta$ once; any device with $\theta$ and the
/// note can independently reconstruct $\alpha$.
///
/// This separation enables **hardware wallet signing without proof
/// construction**: the hardware wallet holds $\mathsf{ask}$ and $\theta$,
/// signs with $\mathsf{rsk} = \mathsf{ask} + \alpha$, and a separate
/// (possibly untrusted) device constructs the proof later using $\theta$
/// and $\mathsf{cm}$ to recover $\alpha$
/// ("Tachyaction at a Distance", Bowe 2025).
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[expect(
    clippy::module_name_repetitions,
    reason = "ActionEntropy is the established protocol name"
)]
pub struct ActionEntropy([u8; 32]);

impl ActionEntropy {
    /// Sample fresh per-action entropy.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derive $\alpha$ for a spend action.
    #[must_use]
    pub fn spend_randomizer(&self, cm: &note::Commitment) -> Randomizer<Spend> {
        Randomizer(derive_alpha(SPEND_ALPHA_PERSONALIZATION, self, cm), PhantomData)
    }

    /// Derive $\alpha$ for an output action.
    #[must_use]
    pub fn output_randomizer(&self, cm: &note::Commitment) -> Randomizer<Output> {
        Randomizer(derive_alpha(OUTPUT_ALPHA_PERSONALIZATION, self, cm), PhantomData)
    }
}

/// Per-action randomizer $\alpha$, parameterized by plan effect.
///
/// - [`Randomizer<Spend>`]: $\mathsf{rsk} = \mathsf{ask} + \alpha$,
///   $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$.
/// - [`Randomizer<Output>`]: $\mathsf{rsk} = \alpha$.
#[derive(Clone, Copy, Debug)]
pub struct Randomizer<E: Effect>(pub(crate) Fq, pub(crate) PhantomData<E>);

impl<E: Effect> From<Randomizer<E>> for Fq {
    fn from(randomizer: Randomizer<E>) -> Self {
        randomizer.0
    }
}

/// Derive the raw $\alpha$ scalar from $\theta$ and $\mathsf{cm}$.
///
/// $$\alpha_{\text{spend}} = \text{ToScalar}(\text{BLAKE2b-512}(
///   \text{"Tachyon-Spend"},\; \theta \| \mathsf{cm}))$$
/// $$\alpha_{\text{output}} = \text{ToScalar}(\text{BLAKE2b-512}(
///   \text{"Tachyon-Output"},\; \theta \| \mathsf{cm}))$$
fn derive_alpha(personalization: &[u8], theta: &ActionEntropy, cm: &note::Commitment) -> Fq {
    assert!(
        personalization == SPEND_ALPHA_PERSONALIZATION
            || personalization == OUTPUT_ALPHA_PERSONALIZATION,
        "invalid personalization: {personalization:?}",
    );
    let hash = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(personalization)
        .to_state()
        .update(&theta.0)
        .update(&Fp::from(*cm).to_repr())
        .finalize();
    Fq::from_uniform_bytes(hash.as_array())
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fq;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::note;

    fn test_cm() -> note::Commitment {
        note::Commitment::from(Fp::ZERO)
    }

    /// Distinct BLAKE2b personalizations must yield distinct alpha scalars
    /// for the same (theta, cm).
    #[test]
    fn spend_and_output_randomizers_differ() {
        let mut rng = StdRng::seed_from_u64(100);
        let theta = ActionEntropy::random(&mut rng);
        let cm = test_cm();

        let spend_alpha: Fq = theta.spend_randomizer(&cm).into();
        let output_alpha: Fq = theta.output_randomizer(&cm).into();

        assert_ne!(spend_alpha, output_alpha);
    }

    #[test]
    fn randomizer_deterministic() {
        let mut rng = StdRng::seed_from_u64(101);
        let theta_a = ActionEntropy::random(&mut rng);
        let theta_b = ActionEntropy::random(&mut rng);
        let cm = test_cm();

        // Deterministic: same theta twice
        let first: Fq = theta_a.spend_randomizer(&cm).into();
        let second: Fq = theta_a.spend_randomizer(&cm).into();
        assert_eq!(first, second);

        // Sensitive: different theta
        let other: Fq = theta_b.spend_randomizer(&cm).into();
        assert_ne!(first, other);
    }
}
