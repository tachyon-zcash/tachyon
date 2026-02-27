//! Per-action randomizers and entropy.
//!
//! [`ActionEntropy`] ($\theta$) is per-action randomness chosen by the signer.
//! Combined with a note commitment it deterministically derives
//! [`ActionRandomizer<K>`], parameterized by [`Spend`], [`Output`], or
//! [`Witness`]:
//!
//! - [`ActionRandomizer<Spend>`] — signs with $\mathsf{rsk} = \mathsf{ask} +
//!   \alpha$
//! - [`ActionRandomizer<Output>`] — derives $\mathsf{rk} = [\alpha]\mathcal{G}$
//!   and signs with $\mathsf{rsk} = \alpha$
//! - [`ActionRandomizer<Witness>`] — erased kind for proof construction; can
//!   derive `rk` but cannot sign

use core::marker::PhantomData;

use ff::{FromUniformBytes as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand::{CryptoRng, RngCore};

use super::{private, public};
use crate::{
    action, bundle,
    constants::{OUTPUT_ALPHA_PERSONALIZATION, SPEND_ALPHA_PERSONALIZATION},
    note, value,
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
    /// The resulting randomizer signs the bundle sighash when combined
    /// with a [`SpendAuthorizingKey`](private::SpendAuthorizingKey) via
    /// [`ActionRandomizer<Spend>::sign`].
    #[must_use]
    pub fn spend_randomizer(&self, cm: &note::Commitment) -> ActionRandomizer<Spend> {
        ActionRandomizer::new(derive_alpha(SPEND_ALPHA_PERSONALIZATION, self, cm))
    }

    /// Derive $\alpha$ for an output action.
    ///
    /// The resulting randomizer signs the bundle sighash directly and provides
    /// the public `rk` via [`ActionRandomizer<Output>::derive_rk`].
    /// $\mathsf{rsk} = \alpha$ (no spend authority).
    #[must_use]
    pub fn output_randomizer(&self, cm: &note::Commitment) -> ActionRandomizer<Output> {
        ActionRandomizer::new(derive_alpha(OUTPUT_ALPHA_PERSONALIZATION, self, cm))
    }
}

/// Marker: spend-side randomizer ($\mathsf{rsk} = \mathsf{ask} + \alpha$).
#[derive(Clone, Copy, Debug)]
pub struct Spend;

/// Marker: output-side randomizer ($\mathsf{rsk} = \alpha$).
#[derive(Clone, Copy, Debug)]
pub struct Output;

/// Marker: erased kind for proof witnesses.
///
/// An `ActionRandomizer<Witness>` can derive `rk` via
/// [`SpendValidatingKey::derive_action_public`](super::proof::SpendValidatingKey::derive_action_public)
/// but **cannot sign** — the signing path requires knowing whether the
/// action is a spend or output.
#[derive(Clone, Copy, Debug)]
pub struct Witness;

/// Per-action authorization randomizer $\alpha$, parameterized by kind.
///
/// - [`ActionRandomizer<Spend>`] — derived from spend entropy, signs with
///   $\mathsf{rsk} = \mathsf{ask} + \alpha$
/// - [`ActionRandomizer<Output>`] — derived from output entropy, derives
///   $\mathsf{rk} = [\alpha]\mathcal{G}$ and signs with $\mathsf{rsk} = \alpha$
/// - [`ActionRandomizer<Witness>`] — erased kind for proof construction; can
///   derive `rk` but cannot sign
///
/// Use [`From`] to erase into the witness kind.
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
#[expect(
    clippy::module_name_repetitions,
    reason = "ActionRandomizer is the established protocol name"
)]
pub struct ActionRandomizer<Kind>(pub(in crate::keys) Fq, PhantomData<Kind>);

impl<Kind> ActionRandomizer<Kind> {
    /// Construct from a raw scalar (crate-private).
    pub(crate) const fn new(scalar: Fq) -> Self {
        Self(scalar, PhantomData)
    }
}

/// Erase a spend randomizer to the witness kind.
impl From<ActionRandomizer<Spend>> for ActionRandomizer<Witness> {
    fn from(alpha: ActionRandomizer<Spend>) -> Self {
        Self::new(alpha.0)
    }
}

/// Erase an output randomizer to the witness kind.
impl From<ActionRandomizer<Output>> for ActionRandomizer<Witness> {
    fn from(alpha: ActionRandomizer<Output>) -> Self {
        Self::new(alpha.0)
    }
}

impl ActionRandomizer<Spend> {
    /// Sign the bundle sighash with $\mathsf{rsk} = \mathsf{ask} + \alpha$,
    /// producing a signed [`Action`](action::Action).
    ///
    /// The sighash must be computed from all effecting data before calling this
    /// method.
    pub fn sign<R: RngCore + CryptoRng>(
        self,
        ask: &private::SpendAuthorizingKey,
        cv: value::Commitment,
        rk: public::ActionVerificationKey,
        sighash: bundle::SigHash,
        rng: &mut R,
    ) -> action::Action {
        let rsk = ask.derive_action_private(&self);
        let sig = rsk.sign(rng, sighash);
        action::Action { cv, rk, sig }
    }
}

impl ActionRandomizer<Output> {
    /// Derive $\mathsf{rk} = [\alpha]\,\mathcal{G}$ for the assembly
    /// phase.
    #[must_use]
    pub fn derive_rk(&self) -> public::ActionVerificationKey {
        let rsk = private::ActionSigningKey::from_output_alpha(self.0);
        rsk.derive_action_public()
    }

    /// Sign the bundle sighash with $\mathsf{rsk} = \alpha$,
    /// producing a signed [`Action`](action::Action).
    ///
    /// Output-side counterpart of [`ActionRandomizer<Spend>::sign`]:
    /// both sign the same bundle sighash, but the output side requires
    /// no `ask` because $\mathsf{rsk} = \alpha$.
    pub fn sign<R: RngCore + CryptoRng>(
        self,
        cv: value::Commitment,
        rk: public::ActionVerificationKey,
        sighash: bundle::SigHash,
        rng: &mut R,
    ) -> action::Action {
        let rsk = private::ActionSigningKey::from_output_alpha(self.0);
        let sig = rsk.sign(rng, sighash);
        action::Action { cv, rk, sig }
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
