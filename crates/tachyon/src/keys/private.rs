//! Private (signing) keys and randomizers.

use core::iter;

use ff::{Field as _, FromUniformBytes as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand::{CryptoRng, RngCore};
use reddsa::orchard::{Binding, SpendAuth};

use super::{
    note::{NullifierKey, PaymentKey},
    proof, public,
};

use crate::{
    action, bundle,
    constants::{ALPHA_PERSONALIZATION, PrfExpand},
    note, value,
};

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
/// - [`derive_proving_key`](Self::derive_proving_key) → [`ProvingKey`] (`ak` +
///   `nk`)
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
    pub fn derive_nullifier_key(&self) -> NullifierKey {
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

    /// Derive the proving key (`ak` + `nk`) for delegated proof construction.
    ///
    /// Combines [`derive_auth_private`](Self::derive_auth_private)
    /// → [`SpendAuthorizingKey::derive_auth_public`] with
    /// [`derive_nullifier_key`](Self::derive_nullifier_key).
    #[must_use]
    pub fn derive_proving_key(&self) -> proof::ProvingKey {
        let ak = self.derive_auth_private().derive_auth_public();
        let nk = self.derive_nullifier_key();
        proof::ProvingKey { ak, nk }
    }
}

/// The spend authorizing key `ask` — a long-lived signing key derived
/// from [`SpendingKey`].
///
/// `ask` **cannot sign directly**. It must first produce a per-action
/// [`RandomizedSigningKey`] (`rsk`) via
/// [`derive_action_private`](Self::derive_action_private), which can then sign.
///
/// This prevents accidentally using the long-lived key for signing.
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
    pub(crate) fn derive_action_private(&self, alpha: &ActionRandomizer) -> ActionSigningKey {
        ActionSigningKey(self.0.randomize(alpha.inner()))
    }
}

/// Randomized signing key `rsk = ask + alpha` — per-action, ephemeral.
///
/// This is the only key type that **can sign**. Produced by
/// [`ActionEntropy::authorize_spend`](crate::keys::ActionEntropy::authorize_spend)
/// (spends) or
/// [`ActionEntropy::authorize_output`](crate::keys::ActionEntropy::authorize_output)
/// (outputs).
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct ActionSigningKey(pub(super) reddsa::SigningKey<SpendAuth>);

impl ActionSigningKey {
    /// Sign `msg` with this randomized key.
    pub fn sign(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        sighash: action::SigHash,
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
}

/// Binding signing key $\mathsf{bsk}$ — the scalar sum of all value
/// commitment trapdoors in a bundle.
///
/// $$\mathsf{bsk} := \boxplus_i \mathsf{rcv}_i$$
///
/// (sum in $\mathbb{F}_q$, the Pallas scalar field)
///
/// The signer knows each $\mathsf{rcv}_i$ because they constructed
/// the actions. $\mathsf{bsk}$ is the discrete log of $\mathsf{bvk}$
/// with respect to $\mathcal{R}$ (the randomness generator from
/// [`VALUE_COMMITMENT_DOMAIN`]), because:
///
/// $$\mathsf{bvk} = \bigoplus_i \mathsf{cv}_i \ominus
///   \text{ValueCommit}_0(\mathsf{v\_{balance}})$$
/// $$= \sum_i \bigl([v_i]\,\mathcal{V} + [\mathsf{rcv}_i]\,\mathcal{R}\bigr) -
/// [\mathsf{v\_{balance}}]\,\mathcal{V}$$
///
/// $$= \bigl[\sum_i v_i - \mathsf{v\_{balance}}\bigr]\,\mathcal{V} +
/// \bigl[\sum_i \mathsf{rcv}_i\bigr]\,\mathcal{R}$$
///
/// $$= [0]\,\mathcal{V} + [\mathsf{bsk}]\,\mathcal{R} \qquad(\text{when }
/// \sum_i v_i = \mathsf{v\_{balance}})$$
///
/// The binding signature proves knowledge of $\mathsf{bsk}$, which is
/// an opening of the Pedersen commitment $\mathsf{bvk}$ to value 0.
/// By the **binding property** of the commitment scheme, it is
/// infeasible to find another opening to a different value — so value
/// balance is enforced.
///
/// ## Tachyon difference from Orchard
///
/// Tachyon signs
/// `BLAKE2b-512("Tachyon-BindHash", value_balance || action_sigs)`
/// rather than Orchard's `SIGHASH_ALL` transaction hash, because:
/// - Action sigs already bind $\mathsf{cv}$ and $\mathsf{rk}$ via
///   $H(\text{"Tachyon-SpendSig"},\; \mathsf{cv} \| \mathsf{rk})$
/// - The binding sig must be computable without the full transaction
/// - The stamp is excluded because it is stripped during aggregation
///
/// The BSK/BVK derivation math is otherwise identical to Orchard
/// (§4.14).
///
/// ## Type representation
///
/// Wraps `reddsa::SigningKey<Binding>`, which internally stores an
/// $\mathbb{F}_q$ scalar. The `Binding` parameterization uses
/// $\mathcal{R}^{\mathsf{Orchard}}$ as its generator (not the standard
/// basepoint $\mathcal{G}$), so
/// $[\mathsf{bsk}]\,\mathcal{R}$ yields $\mathsf{bvk}$.
#[derive(Clone, Copy, Debug)]
pub struct BindingSigningKey(reddsa::SigningKey<Binding>);

impl BindingSigningKey {
    /// Sign the binding sighash.
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
    ///
    /// Used for the §4.14 implementation fault check: the signer
    /// SHOULD verify that
    /// $\text{DerivePublic}(\mathsf{bsk}) = \mathsf{bvk}$ (i.e. the
    /// key derived from trapdoor sums matches the key derived from
    /// value commitments).
    #[must_use]
    pub fn derive_binding_public(&self) -> public::BindingVerificationKey {
        // reddsa::VerificationKey::from(&signing_key) computes [sk] P_G
        // where P_G = R^Orchard for the Binding parameterization.
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

/// Per-action entropy $\theta$ chosen by the signer (e.g. hardware wallet).
///
/// 32 bytes of randomness combined with a note commitment to
/// deterministically derive [`ActionRandomizer`] ($\alpha$).
/// The signer picks $\theta$ once; any device with $\theta$ and the
/// note can independently reconstruct $\alpha$.
///
/// This separation enables **hardware wallet signing without proof
/// construction**: the hardware wallet holds $\mathsf{ask}$ and $\theta$,
/// signs with $\mathsf{rsk} = \mathsf{ask} + \alpha$, and a separate
/// (possibly untrusted) device constructs the proof later using $\theta$
/// and $\mathsf{cmx}$ to recover $\alpha$
/// ("Tachyaction at a Distance", Bowe 2025).
#[derive(Clone, Copy, Debug)]
pub struct ActionEntropy([u8; 32]);

impl ActionEntropy {
    /// Sample fresh per-action entropy.
    pub fn random(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Authorize a spend action: derive $\alpha$ and $\mathsf{rsk} =
    /// \mathsf{ask} + \alpha$.
    ///
    /// Returns `(alpha, rsk)` — alpha for the proof witness, rsk for
    /// signing. Requires the spend authorizing key (`ask`).
    #[must_use]
    pub fn authorize_spend(
        &self,
        ask: &SpendAuthorizingKey,
        cmx: &note::Commitment,
    ) -> (ActionRandomizer, ActionSigningKey) {
        let alpha = ActionRandomizer::derive(self, cmx);
        let rsk = ask.derive_action_private(&alpha);
        (alpha, rsk)
    }

    /// Authorize an output action: derive $\alpha$ and $\mathsf{rsk} =
    /// \alpha$ (no spending authority).
    ///
    /// Returns `(alpha, rsk)` — alpha for the proof witness, rsk for
    /// signing. For outputs there is no `ask`; `rsk = alpha` directly.
    #[must_use]
    #[expect(clippy::expect_used, reason = "random scalar yields valid signing key")]
    pub fn authorize_output(&self, cmx: &note::Commitment) -> (ActionRandomizer, ActionSigningKey) {
        let alpha = ActionRandomizer::derive(self, cmx);
        let sk = reddsa::SigningKey::<SpendAuth>::try_from(alpha.inner().to_repr())
            .expect("random scalar yields valid signing key");
        (alpha, ActionSigningKey(sk))
    }
}

/// Per-action spend authorization randomizer $\alpha$.
///
/// Deterministically derived from [`ActionEntropy`] and a note commitment:
///
/// $$\alpha = \text{ToScalar}(\text{BLAKE2b-512}(\text{"Tachyon-AlphaDrv"},\;
///   \theta \| \mathsf{cmx}))$$
///
/// This binding lets a hardware wallet sign ($\mathsf{rsk} = \mathsf{ask} +
/// \alpha$) independently of the proof, which can be constructed later on a
/// separate device that knows $\theta$ and $\mathsf{cmx}$.
///
/// Produced internally by [`ActionEntropy::authorize_spend`] and
/// [`ActionEntropy::authorize_output`]. Returned in the tuple for use
/// as a proof witness and for prover-side `rk` derivation via
/// [`SpendValidatingKey::derive_action_public`](super::proof::SpendValidatingKey::derive_action_public).
///
/// Each action gets a fresh $\alpha$, ensuring $\mathsf{rk}$ is unlinkable to
/// $\mathsf{ak}$.
#[derive(Clone, Copy, Debug)]
pub struct ActionRandomizer(Fq);

impl ActionRandomizer {
    /// Access the inner scalar (crate-internal).
    pub(crate) const fn inner(&self) -> &Fq {
        &self.0
    }

    /// Derive $\alpha$ deterministically from per-action randomness and
    /// a note commitment.
    ///
    /// $$\alpha =
    /// \text{ToScalar}(\text{BLAKE2b-512}(\text{"Tachyon-AlphaDrv"},\;
    ///   \theta \| \mathsf{cmx}))$$
    #[must_use]
    fn derive(theta: &ActionEntropy, cmx: &note::Commitment) -> Self {
        let hash = blake2b_simd::Params::new()
            .hash_length(64)
            .personal(ALPHA_PERSONALIZATION)
            .to_state()
            .update(&theta.0)
            .update(&Fp::from(*cmx).to_repr())
            .finalize();
        Self(Fq::from_uniform_bytes(hash.as_array()))
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<Fq> for ActionRandomizer {
    /// Extract the raw scalar for circuit witness extraction.
    fn into(self) -> Fq {
        self.0
    }
}
