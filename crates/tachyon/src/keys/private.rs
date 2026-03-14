//! Private (signing) keys.

use core::marker::PhantomData;

use ff::{Field as _, FromUniformBytes as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand_core::{CryptoRng, RngCore};
use reddsa::orchard::{Binding, SpendAuth};

use super::{
    note::{NullifierKey, PaymentKey},
    proof, public,
};
use crate::{
    action, bundle,
    constants::PrfExpand,
    entropy::{OutputRandomizer, SpendRandomizer},
    value,
};

/// Marker type for spend-side action signing keys.
///
/// $\mathsf{rsk} = \mathsf{ask} + \alpha$ — requires spend authority.
#[derive(Clone, Copy, Debug)]
pub struct SpendAuthority;

/// Marker type for output-side action signing keys.
///
/// $\mathsf{rsk} = \alpha$ — no spend authority.
#[derive(Clone, Copy, Debug)]
pub struct OutputAuthority;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::SpendAuthority {}
    impl Sealed for super::OutputAuthority {}
}

/// Sealed trait constraining signing authority.
pub trait ActionAuthority: sealed::Sealed {
    /// The action effect this authority corresponds to.
    const EFFECT: action::Effect;
}

impl ActionAuthority for SpendAuthority {
    const EFFECT: action::Effect = action::Effect::Spend;
}

impl ActionAuthority for OutputAuthority {
    const EFFECT: action::Effect = action::Effect::Output;
}

/// A Tachyon spending key — raw 32-byte entropy.
///
/// The root key from which all other keys are derived. This key must
/// be kept secret as it provides full spending authority.
///
/// Matches Orchard's representation: raw `[u8; 32]` (not a field element),
/// preserving the full 256-bit key space.
///
/// Derives child keys via purpose-specific methods:
/// - [`derive_auth_private`](Self::derive_auth_private) →
///   [`SpendAuthorizingKey`] (`ask`)
/// - [`derive_nullifier_private`](Self::derive_nullifier_private) →
///   [`NullifierKey`] (`nk`)
/// - [`derive_payment_key`](Self::derive_payment_key) → [`PaymentKey`] (`pk`)
/// - [`derive_proof_private`](Self::derive_proof_private) →
///   [`ProofAuthorizingKey`] (`ak` + `nk`)
#[derive(Clone, Copy, Debug)]
pub struct SpendingKey([u8; 32]);

impl From<[u8; 32]> for SpendingKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl SpendingKey {
    /// Derive $\mathsf{ask}$ from $\mathsf{sk}$ with RedPallas sign
    /// normalization.
    ///
    /// # Key derivation (Orchard §4.2.3)
    ///
    /// $$\mathsf{ask} = \text{ToScalar}\bigl(\text{PRF}^{\text{expand}}_
    /// {\mathsf{sk}}([0\text{x}09])\bigr)$$
    ///
    /// BLAKE2b-512 of $(\mathsf{sk} \| \texttt{0x09})$, reduced to
    /// $\mathbb{F}_q$ via `from_uniform_bytes`.
    ///
    /// # Sign normalization (§5.4.7.1)
    ///
    /// RedPallas requires $\mathsf{ak} = [\mathsf{ask}]\,\mathcal{G}$ to
    /// have $\tilde{y} = 0$.  Pallas point compression (§5.4.9.7) encodes
    /// $\tilde{y}$ in bit 255 (byte 31, bit 7) of the 32-byte
    /// representation.  If $\tilde{y}(\mathsf{ak}) = 1$, we negate
    /// $\mathsf{ask}$: $[-\mathsf{ask}]\,\mathcal{G} =
    /// -[\mathsf{ask}]\,\mathcal{G}$ flips the y-coordinate sign.
    ///
    /// The SpendAuth basepoint $\mathcal{G}$ is hash-derived
    /// (`hash_to_curve("z.cash:Orchard")(b"G")`) and sealed inside
    /// reddsa's `private::Sealed` trait, so we must construct a
    /// `SigningKey` (which internally computes $[\mathsf{ask}]\,\mathcal{G}$)
    /// to obtain $\mathsf{ak}$ and inspect its encoding.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "PRF-derived scalars are valid signing keys"
    )]
    pub fn derive_auth_private(&self) -> SpendAuthorizingKey {
        // Derive ask scalar from sk via PRF (Orchard §4.2.3).
        let mut ask = Fq::from_uniform_bytes(&PrfExpand::ASK.with(&self.0));

        // Sign normalization (§5.4.7.1): ak must have tilde_y = 0.
        // Compute ak = [ask]G via reddsa (basepoint is sealed) and check
        // the y-sign bit (byte 31, bit 7 of the compressed encoding).
        let ak: [u8; 32] = reddsa::VerificationKey::from(
            &reddsa::SigningKey::<SpendAuth>::try_from(ask.to_repr())
                .expect("PRF-derived ask should be a valid RedPallas scalar"),
        )
        .into();
        if ak[31] >> 7u8 == 1u8 {
            ask = -ask;
        }

        // Build the final key from the sign-normalized scalar.
        SpendAuthorizingKey(
            reddsa::SigningKey::<SpendAuth>::try_from(ask.to_repr())
                .expect("sign-normalized ask should be a valid RedPallas scalar"),
        )
    }

    /// Derive `nk` from `sk`.
    ///
    /// `nk = ToBase(PRF^expand_sk([0x0a]))` — BLAKE2b-512 reduced to Fp.
    #[must_use]
    pub fn derive_nullifier_private(&self) -> NullifierKey {
        NullifierKey(Fp::from_uniform_bytes(&PrfExpand::NK.with(&self.0)))
    }

    /// Derive the payment key $\mathsf{pk}$ from $\mathsf{sk}$.
    ///
    /// $$\mathsf{pk} = \text{ToBase}\bigl(\text{PRF}^{\text{expand}}_
    /// {\mathsf{sk}}([0\text{x}0b])\bigr)$$
    ///
    /// BLAKE2b-512 of $(\mathsf{sk} \| \texttt{0x0b})$, reduced to
    /// $\mathbb{F}_p$ via `from_uniform_bytes`.
    ///
    /// This is deterministic: every note from the same `sk` shares the
    /// same `pk`. Tachyon removes per-note diversification from the core
    /// protocol; the wallet layer handles unlinkability via out-of-band
    /// payment protocols ("Tachyaction at a Distance", Bowe 2025).
    #[must_use]
    pub fn derive_payment_key(&self) -> PaymentKey {
        PaymentKey(Fp::from_uniform_bytes(&PrfExpand::PK.with(&self.0)))
    }

    /// Derive the proof authorizing key (`ak` + `nk`) for delegated proof
    /// construction.
    ///
    /// Combines [`derive_auth_private`](Self::derive_auth_private)
    /// → [`SpendAuthorizingKey::derive_auth_public`] with
    /// [`derive_nullifier_private`](Self::derive_nullifier_private).
    #[must_use]
    pub fn derive_proof_private(&self) -> proof::ProofAuthorizingKey {
        let ak = self.derive_auth_private().derive_auth_public();
        let nk = self.derive_nullifier_private();
        proof::ProofAuthorizingKey { ak, nk }
    }
}

/// The spend authorizing key `ask` — a long-lived signing key derived
/// from [`SpendingKey`].
///
/// Corresponds to the "spend authorizing key" in Orchard (§4.2.3).
/// Only used for spend actions — output actions do not require `ask`.
///
/// `ask` **cannot sign directly**. It must first be randomized into a
/// per-action [`ActionSigningKey<Spend>`] (`rsk`) via
/// [`derive_action_private`](Self::derive_action_private), which can then
/// sign. Per-action randomization ensures each `rk` is unlinkable to
/// `ak`, so observers cannot correlate actions to the same spending
/// authority.
///
/// `ask` derives [`SpendValidatingKey`](super::proof::SpendValidatingKey)
/// (`ak`) via [`derive_auth_public`](Self::derive_auth_public) — the
/// circuit witness that validates spend authorization.
#[derive(Clone, Copy, Debug)]
pub struct SpendAuthorizingKey(reddsa::SigningKey<SpendAuth>);

impl SpendAuthorizingKey {
    /// Derive the spend validating (public) key: `ak = [ask]G`.
    #[must_use]
    pub fn derive_auth_public(&self) -> proof::SpendValidatingKey {
        // reddsa::VerificationKey::from(&signing_key) performs [sk]G
        // (scalar-times-basepoint), not a trivial type conversion.
        proof::SpendValidatingKey(reddsa::VerificationKey::from(&self.0))
    }

    /// Derive the per-action private (signing) key: $\mathsf{rsk} =
    /// \mathsf{ask} + \alpha$.
    ///
    /// Only accepts [`SpendRandomizer`] — passing an output randomizer is
    /// a compile error.
    #[must_use]
    pub fn derive_action_private(
        &self,
        alpha: &SpendRandomizer,
    ) -> ActionSigningKey<SpendAuthority> {
        ActionSigningKey(self.0.randomize(&alpha.0), PhantomData)
    }
}

/// The per-action signing key `rsk` — ephemeral, parameterized by kind.
///
/// - [`ActionSigningKey<effect::Spend>`]: $\mathsf{rsk} = \mathsf{ask} +
///   \alpha$ — derived from [`SpendAuthorizingKey::derive_action_private`]
/// - [`ActionSigningKey<effect::Output>`]: $\mathsf{rsk} = \alpha$ — derived
///   from [`OutputRandomizer`]
///
/// Both variants sign via [`sign`](Self::sign) and derive `rk` via
/// [`derive_action_public`](Self::derive_action_public).
#[derive(Clone, Copy, Debug)]
pub struct ActionSigningKey<K: ActionAuthority>(reddsa::SigningKey<SpendAuth>, PhantomData<K>);

impl<K: ActionAuthority> ActionSigningKey<K> {
    /// Sign a transaction sighash with this action key.
    pub fn sign(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        sighash: &[u8; 32],
    ) -> action::Signature {
        action::Signature(self.0.sign(rng, sighash))
    }

    /// Sign an action plan, producing an authorized action.
    ///
    /// # Panics
    ///
    /// Panics if the plan's effect does not match this key's authority.
    pub fn sign_plan(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        plan: &action::Plan,
        sighash: &[u8; 32],
    ) -> action::Action {
        assert!(
            plan.effect == K::EFFECT,
            "plan effect must match signing key authority"
        );
        action::Action {
            cv: plan.cv(),
            rk: plan.rk,
            sig: self.sign(rng, sighash),
        }
    }

    /// Derive the per-action verification (public) key: `rk = [rsk]G`.
    #[must_use]
    pub fn derive_action_public(&self) -> public::ActionVerificationKey {
        // reddsa::VerificationKey::from(&signing_key) performs [sk]G
        // (scalar-times-basepoint), not a trivial type conversion.
        let vk = reddsa::VerificationKey::from(&self.0);
        public::ActionVerificationKey(vk)
    }
}

impl ActionSigningKey<OutputAuthority> {
    /// Create a new output action signing key from an output randomizer.
    #[must_use]
    pub fn new(alpha: OutputRandomizer) -> Self {
        alpha.into()
    }
}

impl From<OutputRandomizer> for ActionSigningKey<OutputAuthority> {
    fn from(alpha: OutputRandomizer) -> Self {
        #[expect(clippy::expect_used, reason = "specified behavior")]
        Self(
            reddsa::SigningKey::<SpendAuth>::try_from(alpha.0.to_repr())
                .expect("output randomizer should be a valid RedPallas signing key"),
            PhantomData,
        )
    }
}

/// Binding signing key $\mathsf{bsk}$ — the scalar sum of all value
/// commitment trapdoors in a bundle.
///
/// $$\mathsf{bsk} := \boxplus_i \mathsf{rcv}_i$$
///
/// (sum in $\mathbb{F}_q$, the Pallas scalar field)
///
/// The binding signature proves knowledge of $\mathsf{bsk}$, which is
/// an opening of the Pedersen commitment $\mathsf{bvk}$ to value 0.
/// By the **binding property** of the commitment scheme, it is
/// infeasible to find another opening to a different value — so value
/// balance is enforced.
///
/// ## Sighash
///
/// Both action signatures and the binding signature sign the same
/// transaction-level sighash. The sighash incorporates the bundle
/// commitment (and commitments from other pools). The stamp is
/// excluded from the bundle commitment because it is stripped during
/// aggregation.
#[derive(Clone, Copy, Debug)]
pub struct BindingSigningKey(reddsa::SigningKey<Binding>);

impl BindingSigningKey {
    /// Sign a transaction sighash with this binding key.
    pub fn sign(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        sighash: &[u8; 32],
    ) -> bundle::Signature {
        bundle::Signature(self.0.sign(rng, sighash))
    }

    /// Derive the binding verification (public) key:
    /// $\mathsf{bvk} = [\mathsf{bsk}]\,\mathcal{R}$.
    #[must_use]
    pub fn derive_binding_public(&self) -> public::BindingVerificationKey {
        public::BindingVerificationKey(reddsa::VerificationKey::from(&self.0))
    }
}

impl From<&[value::CommitmentTrapdoor]> for BindingSigningKey {
    /// Binding signing key is the scalar sum of all value commitment trapdoors.
    ///
    /// Every Pallas scalar field element, including zero, is a valid binding
    /// signing key. See Zcash protocol §4.14.
    fn from(trapdoors: &[value::CommitmentTrapdoor]) -> Self {
        let sum: Fq = trapdoors
            .iter()
            .fold(Fq::ZERO, |acc, rcv| acc + Into::<Fq>::into(*rcv));
        #[expect(
            clippy::expect_used,
            reason = "all Fq are valid RedPallas signing keys"
        )]
        Self(
            reddsa::SigningKey::<Binding>::try_from(sum.to_repr())
                .expect("all Fq are valid RedPallas signing keys"),
        )
    }
}
