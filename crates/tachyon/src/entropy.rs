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
    use proptest::prelude::*;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{digest::poseidon, note, primitives::effect, testing::check};

    /// Alpha is a function of (theta, cm), sensitive to both, separated
    /// between spends and outputs by the Poseidon domain, and encoded as the
    /// Poseidon output so the circuit's base-field alpha is the signer's
    /// scalar.
    #[test]
    fn randomizers_are_domain_separated_functions_of_theta_and_cm() {
        check(256, any::<u64>(), |seed| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let (theta, other_theta) = (ActionEntropy::random(rng), ActionEntropy::random(rng));
            let (cm, other_cm) = (
                note::Commitment::from(Fp::random(&mut *rng)),
                note::Commitment::from(Fp::random(&mut *rng)),
            );
            let spend = |entropy: ActionEntropy, commitment| {
                Fq::from(entropy.randomizer::<effect::Spend>(commitment))
            };
            let output = |entropy: ActionEntropy, commitment| {
                Fq::from(entropy.randomizer::<effect::Output>(commitment))
            };

            prop_assert_eq!(spend(theta, cm), spend(theta, cm));
            prop_assert_ne!(spend(theta, cm), output(theta, cm));
            prop_assert_ne!(spend(theta, cm), spend(other_theta, cm));
            prop_assert_ne!(spend(theta, cm), spend(theta, other_cm));
            prop_assert_ne!(output(theta, cm), output(other_theta, cm));
            prop_assert_ne!(output(theta, cm), output(theta, other_cm));
            prop_assert_eq!(
                spend(theta, cm).to_repr(),
                poseidon::alpha_spend(theta.0, cm.into()).to_repr()
            );
            prop_assert_eq!(
                output(theta, cm).to_repr(),
                poseidon::alpha_output(theta.0, cm.into()).to_repr()
            );
            Ok(())
        });
    }

    /// `from_bytes` accepts exactly the canonical field encodings and returns
    /// the element they encode.
    #[test]
    fn from_bytes_accepts_exactly_canonical_encodings() {
        check(256, any::<[u8; 32]>(), |bytes| {
            let canonical: Option<Fp> = Fp::from_repr(bytes).into();
            prop_assert_eq!(
                ActionEntropy::from_bytes(bytes).map(|theta| theta.0),
                canonical
            );
            if let Some(element) = canonical {
                prop_assert_eq!(element.to_repr(), bytes);
            }
            Ok(())
        });
    }

    /// Debug output names the type, and for a randomizer its effect, and is
    /// the same for every value.
    #[test]
    fn debug_redacts_entropy_and_randomizers() {
        check(256, any::<u64>(), |seed| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let cm = note::Commitment::from(Fp::random(&mut *rng));
            let [theta, other] = [ActionEntropy::random(rng), ActionEntropy::random(rng)];
            let entropy = [theta, other].map(|value| alloc::format!("{value:?}"));
            prop_assert!(entropy[0].contains("ActionEntropy"));
            prop_assert_eq!(&entropy[0], &entropy[1]);
            let alpha = [theta, other]
                .map(|value| alloc::format!("{:?}", value.randomizer::<effect::Spend>(cm)));
            prop_assert!(alpha[0].contains("ActionRandomizer") && alpha[0].contains("Spend"));
            prop_assert_eq!(&alpha[0], &alpha[1]);
            Ok(())
        });
    }
}
