//! Per-action randomizers and entropy.
//!
//! [`ActionEntropy`] ($\theta$) is per-action randomness chosen by the signer.
//! Combined with a note commitment it deterministically derives typed
//! randomizers:
//!
//! - [`SpendRandomizer`] — signs with $\mathsf{rsk} = \mathsf{ask} + \alpha$
//! - [`OutputRandomizer`] — converts to
//!   [`OutputSigningKey`](super::private::OutputSigningKey) for signing with
//!   $\mathsf{rsk} = \alpha$
//!
//! Both typed randomizers convert to [`ActionRandomizer`] (non-generic) for
//! storage in [`ActionPrivate`](crate::witness::ActionPrivate).

use ff::{FromUniformBytes as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand::{CryptoRng, RngCore};

use super::private;
use crate::{
    action::{self},
    bundle,
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
    clippy::field_scoped_visibility_modifiers,
    reason = "theta bytes accessed by derive_alpha in this module"
)]
pub struct ActionEntropy(pub(crate) [u8; 32]);

impl ActionEntropy {
    /// Sample fresh per-action entropy.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Derive $\alpha$ for a spend action.
    ///
    /// The resulting [`SpendRandomizer`] signs the bundle sighash when
    /// combined with a [`SpendAuthorizingKey`](private::SpendAuthorizingKey)
    /// via [`SpendRandomizer::sign`].
    #[must_use]
    pub fn spend_randomizer(&self, cm: &note::Commitment) -> SpendRandomizer {
        SpendRandomizer(derive_alpha(SPEND_ALPHA_PERSONALIZATION, self, cm))
    }

    /// Derive $\alpha$ for an output action.
    ///
    /// The resulting [`OutputRandomizer`] converts to
    /// [`OutputSigningKey`](private::OutputSigningKey) for signing
    /// and [`ActionRandomizer`] for witness storage.
    #[must_use]
    pub fn output_randomizer(&self, cm: &note::Commitment) -> OutputRandomizer {
        OutputRandomizer(derive_alpha(OUTPUT_ALPHA_PERSONALIZATION, self, cm))
    }
}

/// Spend-side randomizer $\alpha$ derived with spend personalization.
///
/// $\mathsf{rsk} = \mathsf{ask} + \alpha$, $\mathsf{rk} = \mathsf{ak} +
/// [\alpha]\,\mathcal{G}$.
///
/// Used in:
/// - [`SpendAuthorizingKey::derive_action_private`](private::SpendAuthorizingKey::derive_action_private)
///   — compile-time enforced (only accepts `&SpendRandomizer`)
/// - [`SpendValidatingKey::derive_action_public`](super::SpendValidatingKey::derive_action_public)
///   — compile-time enforced
/// - [`sign`](Self::sign) — convenience method
///
/// Converts to [`ActionRandomizer`] for witness storage via [`From`].
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
#[expect(
    clippy::module_name_repetitions,
    reason = "SpendRandomizer is the established protocol name"
)]
pub struct SpendRandomizer(pub(in crate::keys) Fq);

impl SpendRandomizer {
    /// Sign the bundle sighash with $\mathsf{rsk} = \mathsf{ask} + \alpha$.
    ///
    /// Returns the spend auth signature. The caller assembles the
    /// [`Action`](action::Action) separately (with `cv` computed at build
    /// time).
    pub fn sign<R: RngCore + CryptoRng>(
        self,
        ask: &private::SpendAuthorizingKey,
        sighash: bundle::SigHash,
        rng: &mut R,
    ) -> action::Signature {
        let rsk = ask.derive_action_private(&self);
        rsk.sign(rng, sighash)
    }
}

/// Output-side randomizer $\alpha$ derived with output personalization.
///
/// $\mathsf{rsk} = \alpha$ (no spend authority).
///
/// No signing methods — convert to
/// [`OutputSigningKey`](private::OutputSigningKey) for signing
/// and [`derive_action_public`](private::OutputSigningKey::derive_action_public).
///
/// Converts to [`ActionRandomizer`] for witness storage via [`From`].
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
#[expect(
    clippy::module_name_repetitions,
    reason = "OutputRandomizer is the established protocol name"
)]
pub struct OutputRandomizer(pub(in crate::keys) Fq);

/// Non-generic action randomizer for proof witness storage.
///
/// Carries the $\alpha$ scalar and its derivation path ([`Effect`]).
/// The circuit uses [`effect`](Self::effect) to select constraint sets
/// and reads the scalar for the alpha witness value.
///
/// Constructed from typed randomizers via [`From<SpendRandomizer>`] or
/// [`From<OutputRandomizer>`].
#[derive(Clone, Copy, Debug)]
#[expect(
    clippy::module_name_repetitions,
    reason = "ActionRandomizer is the established protocol name"
)]
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
