//! Per-action randomizers and entropy.
//!
//! [`ActionEntropy`] ($\theta$) is per-action randomness chosen by the signer.
//! Combined with a note commitment it deterministically derives an
//! [`ActionRandomizer`].

use core::marker::PhantomData;

use ff::{FromUniformBytes as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand_core::{CryptoRng, RngCore};

use crate::{note, primitives::Effect};

/// Per-action entropy $\theta$ chosen by the signer (e.g. hardware wallet).
///
/// 32 bytes of randomness combined with a note commitment to
/// deterministically derive $\alpha$ via
/// [`randomizer`](Self::randomizer).
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
#[expect(
    clippy::module_name_repetitions,
    reason = "ActionEntropy is the established protocol name"
)]
pub struct ActionEntropy([u8; 32]);

impl ActionEntropy {
    /// Parse action entropy from 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Sample fresh per-action entropy.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derive the action randomizer $\alpha$ for effect `E`.
    ///
    /// Uses distinct BLAKE2b personalizations for spend vs output to
    /// ensure the two randomizers are independent.
    #[must_use]
    pub fn randomizer<E: Effect>(&self, cm: &note::Commitment) -> ActionRandomizer<E> {
        ActionRandomizer(E::derive_alpha(self, cm), PhantomData)
    }
}

mod sealed {
    use crate::primitives::Effect;

    pub trait RandomizerState: Copy {}
    impl<T: Effect> RandomizerState for T {}
}

/// Per-action randomizer $\alpha$, parameterized by effect state.
///
/// - [`ActionRandomizer<Spend>`]: $\mathsf{rsk} = \mathsf{ask} + \alpha$,
///   $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$.
/// - [`ActionRandomizer<Output>`]: $\mathsf{rsk} = \alpha$.
#[derive(Clone, Copy, Debug)]
pub struct ActionRandomizer<S: sealed::RandomizerState>(pub(crate) Fq, pub(crate) PhantomData<S>);

impl<S: sealed::RandomizerState> From<ActionRandomizer<S>> for Fq {
    fn from(randomizer: ActionRandomizer<S>) -> Self {
        randomizer.0
    }
}

/// Derive the raw $\alpha$ scalar from $\theta$ and $\mathsf{cm}$.
///
/// $$\alpha_{\text{spend}} = \text{ToScalar}(\text{BLAKE2b-512}(
///   \text{"Tachyon-Spend"},\; \theta \| \mathsf{cm}))$$
/// $$\alpha_{\text{output}} = \text{ToScalar}(\text{BLAKE2b-512}(
///   \text{"Tachyon-Output"},\; \theta \| \mathsf{cm}))$$
pub(crate) fn derive_alpha(
    personalization: &[u8],
    theta: &ActionEntropy,
    cm: &note::Commitment,
) -> Fq {
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
    use pasta_curves::{Fp, Fq};
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{note, primitives::effect};

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

        let spend_alpha: Fq = theta.randomizer::<effect::Spend>(&cm).into();
        let output_alpha: Fq = theta.randomizer::<effect::Output>(&cm).into();

        assert_ne!(spend_alpha, output_alpha);
    }

    #[test]
    fn randomizer_deterministic() {
        let mut rng = StdRng::seed_from_u64(101);
        let theta_a = ActionEntropy::random(&mut rng);
        let theta_b = ActionEntropy::random(&mut rng);
        let cm = test_cm();

        // Deterministic: same theta twice
        let first: Fq = theta_a.randomizer::<effect::Spend>(&cm).into();
        let second: Fq = theta_a.randomizer::<effect::Spend>(&cm).into();
        assert_eq!(first, second);

        // Sensitive: different theta
        let other: Fq = theta_b.randomizer::<effect::Spend>(&cm).into();
        assert_ne!(first, other);
    }
}
