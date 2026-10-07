//! Per-action randomizers and entropy.
//!
//! [`ActionEntropy`] ($\theta$) is per-action randomness chosen by the signer.
//! Combined with a note commitment it deterministically derives an
//! [`ActionRandomizer`].

use core::{any::type_name, marker::PhantomData};

use derive_more::{Debug, Into};
use ff::{Field as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand_core::CryptoRng;

use crate::{note, primitives::Effect};

/// Per-action entropy $\theta$ chosen by the signer (e.g. hardware wallet).
///
/// A random field element combined with a note commitment to
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
pub struct ActionEntropy(#[debug(skip)] pub(crate) Fp);

impl ActionEntropy {
    /// Parse action entropy from its canonical 32-byte encoding.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        Option::from(Fp::from_repr(bytes)).map(Self)
    }

    /// Sample fresh per-action entropy.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(rng))
    }

    /// Derive the action randomizer $\alpha$ for effect `E`.
    ///
    /// Spend and output use distinct Poseidon domains, so the two randomizers
    /// are independent.
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
///   $\mathsf{rk} = \mathsf{ak} + [\alpha]\mathcal{G}$.
/// - [`ActionRandomizer<Output>`]: $\mathsf{rsk} = \alpha$.
#[derive(Clone, Copy, Debug, Into)]
#[debug("ActionRandomizer<{}>", type_name::<S>())]
pub struct ActionRandomizer<S: sealed::RandomizerState>(
    pub(crate) Fq,
    #[into(skip)] pub(crate) PhantomData<S>,
);

#[cfg(test)]
mod tests {
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{digest::poseidon, note, primitives::effect};

    /// Distinct Poseidon domains must yield distinct alpha scalars for the
    /// same (theta, cm).
    #[test]
    fn spend_and_output_randomizers_differ() {
        let mut rng = StdRng::seed_from_u64(100);
        let theta = ActionEntropy::random(&mut rng);
        let cm = note::Commitment::from(Fp::random(&mut rng));

        let spend_alpha: Fq = theta.randomizer::<effect::Spend>(cm).into();
        let output_alpha: Fq = theta.randomizer::<effect::Output>(cm).into();

        assert_ne!(spend_alpha, output_alpha);
    }

    #[test]
    fn randomizer_deterministic() {
        let mut rng = StdRng::seed_from_u64(101);
        let theta_a = ActionEntropy::random(&mut rng);
        let theta_b = ActionEntropy::random(&mut rng);
        let cm = note::Commitment::from(Fp::random(&mut rng));

        // Deterministic: same theta twice
        let first: Fq = theta_a.randomizer::<effect::Spend>(cm).into();
        let second: Fq = theta_a.randomizer::<effect::Spend>(cm).into();
        assert_eq!(first, second);

        // Sensitive: different theta
        let other: Fq = theta_b.randomizer::<effect::Spend>(cm).into();
        assert_ne!(first, other);
    }

    /// The scalar alpha has the same encoding as the Poseidon output, so the
    /// circuit's base-field alpha is the signer's scalar.
    #[test]
    fn randomizer_embeds_the_poseidon_output() {
        let mut rng = StdRng::seed_from_u64(102);
        let theta = ActionEntropy::random(&mut rng);
        let cm = note::Commitment::from(Fp::random(&mut rng));

        let spend: Fq = theta.randomizer::<effect::Spend>(cm).into();
        let output: Fq = theta.randomizer::<effect::Output>(cm).into();

        assert_eq!(
            spend.to_repr(),
            poseidon::alpha_spend(theta.0, cm.into()).to_repr()
        );
        assert_eq!(
            output.to_repr(),
            poseidon::alpha_output(theta.0, cm.into()).to_repr()
        );
    }

    #[test]
    fn from_bytes_round_trips_canonical_encodings() {
        let theta = ActionEntropy::random(&mut StdRng::seed_from_u64(103));
        let Some(parsed) = ActionEntropy::from_bytes(theta.0.to_repr()) else {
            panic!("canonical encoding must parse");
        };
        assert_eq!(parsed.0, theta.0);
    }

    #[test]
    fn from_bytes_rejects_non_canonical_encodings() {
        assert!(ActionEntropy::from_bytes([0xFF; 32]).is_none());
    }

    #[test]
    fn debug_entropy_redacts_bytes() {
        let mut bytes = [0xAB; 32];
        bytes[31] = 0x2B;
        let Some(theta) = ActionEntropy::from_bytes(bytes) else {
            panic!("canonical encoding must parse");
        };
        let dbg = alloc::format!("{theta:?}");
        assert!(dbg.contains("ActionEntropy"), "must name the type");
        assert!(!dbg.contains("AB"), "must not leak entropy bytes");
        assert!(!dbg.contains("171"), "must not leak entropy bytes");
    }

    #[test]
    fn debug_randomizer_redacts_scalar() {
        let mut rng = StdRng::seed_from_u64(200);
        let theta = ActionEntropy::random(&mut rng);
        let cm = note::Commitment::from(Fp::random(&mut rng));
        let alpha = theta.randomizer::<effect::Spend>(cm);
        let dbg = alloc::format!("{alpha:?}");
        assert!(dbg.contains("ActionRandomizer"), "must name the type");
        // The scalar value must not appear; the state type name should.
        assert!(dbg.contains("Spend"), "must show type parameter");
    }
}
