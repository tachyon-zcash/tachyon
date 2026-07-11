//! Per-action randomizers and entropy.
//!
//! [`ActionEntropy`] ($\theta$) is per-action randomness chosen by the signer.
//! Combined with a note commitment it deterministically derives an
//! [`ActionRandomizer`].

use core::{any::type_name, marker::PhantomData};

use derive_more::Debug;
use pasta_curves::Fq;
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
#[expect(clippy::module_name_repetitions, reason = "intentional name")]
pub struct ActionEntropy(#[debug(skip)] pub(crate) [u8; 32]);

impl ActionEntropy {
    /// Parse action entropy from 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Sample fresh per-action entropy.
    pub fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derive the action randomizer $\alpha$ for effect `E`.
    ///
    /// Uses distinct BLAKE2b personalizations for spend vs output to
    /// ensure the two randomizers are independent.
    #[must_use]
    pub fn randomizer<E: Effect>(&self, cm: note::Commitment) -> ActionRandomizer<E> {
        ActionRandomizer(E::derive_alpha(*self, cm), PhantomData)
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
#[debug("ActionRandomizer<{}>", type_name::<S>())]
pub struct ActionRandomizer<S: sealed::RandomizerState>(pub(crate) Fq, pub(crate) PhantomData<S>);

impl<S: sealed::RandomizerState> From<ActionRandomizer<S>> for Fq {
    fn from(randomizer: ActionRandomizer<S>) -> Self {
        randomizer.0
    }
}

#[cfg(test)]
mod tests {
    use pasta_curves::Fq;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{note, primitives::effect};

    /// Distinct BLAKE2b personalizations must yield distinct alpha scalars
    /// for the same (theta, cm).
    #[test]
    fn spend_and_output_randomizers_differ() {
        let mut rng = StdRng::seed_from_u64(100);
        let theta = ActionEntropy::random(&mut rng);
        let cm = note::Commitment::random(&mut rng);

        let spend_alpha: Fq = theta.randomizer::<effect::Spend>(cm).into();
        let output_alpha: Fq = theta.randomizer::<effect::Output>(cm).into();

        assert_ne!(spend_alpha, output_alpha);
    }

    #[test]
    fn randomizer_deterministic() {
        let mut rng = StdRng::seed_from_u64(101);
        let theta_a = ActionEntropy::random(&mut rng);
        let theta_b = ActionEntropy::random(&mut rng);
        let cm = note::Commitment::random(&mut rng);

        // Deterministic: same theta twice
        let first: Fq = theta_a.randomizer::<effect::Spend>(cm).into();
        let second: Fq = theta_a.randomizer::<effect::Spend>(cm).into();
        assert_eq!(first, second);

        // Sensitive: different theta
        let other: Fq = theta_b.randomizer::<effect::Spend>(cm).into();
        assert_ne!(first, other);
    }

    #[test]
    fn debug_entropy_redacts_bytes() {
        let theta = ActionEntropy::from_bytes([0xAB; 32]);
        let dbg = alloc::format!("{theta:?}");
        assert!(dbg.contains("ActionEntropy"), "must name the type");
        assert!(!dbg.contains("AB"), "must not leak entropy bytes");
        assert!(!dbg.contains("171"), "must not leak entropy bytes");
    }

    #[test]
    fn debug_randomizer_redacts_scalar() {
        let mut rng = StdRng::seed_from_u64(200);
        let theta = ActionEntropy::random(&mut rng);
        let cm = note::Commitment::random(&mut rng);
        let alpha = theta.randomizer::<effect::Spend>(cm);
        let dbg = alloc::format!("{alpha:?}");
        assert!(dbg.contains("ActionRandomizer"), "must name the type");
        // The scalar value must not appear; the state type name should.
        assert!(dbg.contains("Spend"), "must show type parameter");
    }
}
