//! Private (signing) keys.

use core::iter;

use ff::{Field as _, FromUniformBytes as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand::{CryptoRng, RngCore};
use reddsa::orchard::{Binding, SpendAuth};

use super::{
    note::{NullifierKey, PaymentKey},
    proof, public,
    randomizer::{ActionRandomizer, Spend},
};
use crate::{action, bundle, constants::PrfExpand, value};

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
/// - [`derive_nullifier_key`](Self::derive_nullifier_key) → [`NullifierKey`]
///   (`nk`)
/// - [`derive_payment_key`](Self::derive_payment_key) → [`PaymentKey`] (`pk`)
/// - [`derive_proof_authorizing_key`](Self::derive_proof_authorizing_key) →
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
            &reddsa::SigningKey::<SpendAuth>::try_from(ask.to_repr()).expect("valid scalar"),
        )
        .into();
        if ak[31] >> 7u8 == 1u8 {
            ask = -ask;
        }

        // Build the final key from the sign-normalized scalar.
        SpendAuthorizingKey(
            reddsa::SigningKey::<SpendAuth>::try_from(ask.to_repr()).expect("valid scalar"),
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
    /// [`derive_nullifier_key`](Self::derive_nullifier_key).
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
/// per-action [`ActionSigningKey`] (`rsk`) via
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
    #[must_use]
    pub fn derive_action_private(&self, alpha: &ActionRandomizer<Spend>) -> ActionSigningKey {
        ActionSigningKey(self.0.randomize(&alpha.0))
    }
}

/// The randomized action signing key `rsk` — per-action, ephemeral.
///
/// For spends: $\mathsf{rsk} = \mathsf{ask} + \alpha$. For outputs:
/// $\mathsf{rsk} = \alpha$ (no spend authority).
///
/// Public for flexibility, but intended for internal use. External callers
/// obtain signed [`Action`](action::Action)s via
/// [`ActionRandomizer<Spend>::sign`] or
/// [`ActionRandomizer<Output>::sign`](super::randomizer::ActionRandomizer<Output>::sign).
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct ActionSigningKey(pub(super) reddsa::SigningKey<SpendAuth>);

impl ActionSigningKey {
    /// Sign the bundle sighash with this randomized key.
    pub fn sign(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        sighash: bundle::SigHash,
    ) -> action::Signature {
        let msg: [u8; 64] = sighash.into();
        action::Signature(self.0.sign(rng, &msg))
    }

    /// Derive the per-action verification (public) key: `rk = [rsk]G`.
    #[must_use]
    pub fn derive_action_public(&self) -> public::ActionVerificationKey {
        // reddsa::VerificationKey::from(&signing_key) performs [sk]G
        // (scalar-times-basepoint), not a trivial type conversion.
        let vk = reddsa::VerificationKey::from(&self.0);
        public::ActionVerificationKey(vk)
    }

    /// Construct from a raw output alpha scalar ($\mathsf{rsk} = \alpha$).
    ///
    /// Used by [`ActionRandomizer<Output>`](super::randomizer::ActionRandomizer)
    /// methods where $\mathsf{rsk}$ is the alpha itself (no spend authority).
    #[expect(clippy::expect_used, reason = "specified behavior")]
    pub(super) fn from_output_alpha(alpha: Fq) -> Self {
        Self(
            reddsa::SigningKey::<SpendAuth>::try_from(alpha.to_repr())
                .expect("BLAKE2b-derived scalar yields valid signing key"),
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
/// ## Bundle sighash
///
/// Both action signatures and the binding signature sign the same
/// bundle-level digest:
///
/// `BLAKE2b-512("Tachyon-BndlHash", cv_1 || rk_1 || ... || cv_n || rk_n ||
/// value_balance)`
///
/// The stamp is excluded because it is stripped during aggregation.
#[derive(Clone, Copy, Debug)]
pub struct BindingSigningKey(reddsa::SigningKey<Binding>);

impl BindingSigningKey {
    /// Sign the bundle sighash.
    pub fn sign(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        sighash: bundle::SigHash,
    ) -> bundle::Signature {
        let msg: [u8; 64] = sighash.into();
        bundle::Signature(self.0.sign(rng, &msg))
    }

    /// Derive the binding verification (public) key:
    /// $\mathsf{bvk} = [\mathsf{bsk}]\,\mathcal{R}$.
    #[must_use]
    pub fn derive_binding_public(&self) -> public::BindingVerificationKey {
        public::BindingVerificationKey(reddsa::VerificationKey::from(&self.0))
    }
}

impl iter::Sum<value::CommitmentTrapdoor> for BindingSigningKey {
    /// $\mathsf{bsk} = \boxplus_i \mathsf{rcv}_i$ — scalar sum of all
    /// value commitment trapdoors ($\mathbb{F}_q$).
    fn sum<I: Iterator<Item = value::CommitmentTrapdoor>>(iter: I) -> Self {
        let sum: Fq = iter.fold(Fq::ZERO, |acc, rcv| acc + Into::<Fq>::into(rcv));
        #[expect(clippy::expect_used, reason = "specified behavior")]
        Self::try_from(sum).expect("sum of trapdoors is a valid signing key")
    }
}

impl TryFrom<Fq> for BindingSigningKey {
    type Error = reddsa::Error;

    fn try_from(el: Fq) -> Result<Self, Self::Error> {
        let inner = reddsa::SigningKey::<Binding>::try_from(el.to_repr())?;
        Ok(Self(inner))
    }
}
