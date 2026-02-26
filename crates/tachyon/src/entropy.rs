//! Per-action randomizers and entropy.
//!
//! [`ActionEntropy`] ($\theta$) is per-action randomness chosen by the signer.
//! Combined with a note commitment it deterministically derives
//! [`SpendRandomizer`] or [`OutputRandomizer`].

use ff::{FromUniformBytes as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand::{CryptoRng, RngCore};

use crate::{
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
    pub fn spend_randomizer(&self, cm: &note::Commitment) -> SpendRandomizer {
        SpendRandomizer(derive_alpha(SPEND_ALPHA_PERSONALIZATION, self, cm))
    }

    /// Derive $\alpha$ for an output action.
    #[must_use]
    pub fn output_randomizer(&self, cm: &note::Commitment) -> OutputRandomizer {
        OutputRandomizer(derive_alpha(OUTPUT_ALPHA_PERSONALIZATION, self, cm))
    }
}

/// Spend-side randomizer $\alpha$ derived with spend personalization.
///
/// $\mathsf{rsk} = \mathsf{ask} + \alpha$, $\mathsf{rk} = \mathsf{ak} +
/// [\alpha]\,\mathcal{G}$.
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct SpendRandomizer(pub(crate) Fq);

/// Output-side randomizer $\alpha$ derived with output personalization.
///
/// $\mathsf{rsk} = \alpha$.
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct OutputRandomizer(pub(crate) Fq);

/// Bare $\alpha$ scalar for proof witness storage.
///
/// Spend and output are indistinguishable at the witness level.
#[derive(Clone, Copy, Debug)]
pub struct ActionRandomizer(Fq);

impl From<ActionRandomizer> for Fq {
    fn from(randomizer: ActionRandomizer) -> Self {
        randomizer.0
    }
}

impl From<SpendRandomizer> for ActionRandomizer {
    fn from(alpha: SpendRandomizer) -> Self {
        Self(alpha.0)
    }
}

impl From<OutputRandomizer> for ActionRandomizer {
    fn from(alpha: OutputRandomizer) -> Self {
        Self(alpha.0)
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
    use pasta_curves::{Fp, Fq};
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

        let spend_alpha: Fq = ActionRandomizer::from(theta.spend_randomizer(&cm)).into();
        let output_alpha: Fq = ActionRandomizer::from(theta.output_randomizer(&cm)).into();

        assert_ne!(spend_alpha, output_alpha);
    }

    #[test]
    fn randomizer_deterministic() {
        let mut rng = StdRng::seed_from_u64(101);
        let theta_a = ActionEntropy::random(&mut rng);
        let theta_b = ActionEntropy::random(&mut rng);
        let cm = test_cm();

        // Deterministic: same theta twice
        let first: Fq = ActionRandomizer::from(theta_a.spend_randomizer(&cm)).into();
        let second: Fq = ActionRandomizer::from(theta_a.spend_randomizer(&cm)).into();
        assert_eq!(first, second);

        // Sensitive: different theta
        let other: Fq = ActionRandomizer::from(theta_b.spend_randomizer(&cm)).into();
        assert_ne!(first, other);
    }
}
