//! Private (signing) keys.

use core::iter;

use ff::{Field as _, FromUniformBytes as _, PrimeField as _};
use pasta_curves::Fq;
use rand::{CryptoRng, RngCore};
use reddsa::orchard::{Binding, SpendAuth};

use super::{
    note::{NullifierKey, PaymentKey},
    public::{BindingVerificationKey, RandomizedVerificationKey, SpendValidatingKey},
    signature::{BindingSignature, SpendAuthSignature},
};
use crate::{constants::PrfExpand, primitives::SpendAuthRandomizer, value};

/// A Tachyon spending key — raw 32-byte entropy.
///
/// The root key from which all other keys are derived. This key must
/// be kept secret as it provides full spending authority.
///
/// Matches Orchard's representation: raw `[u8; 32]` (not a field element),
/// preserving the full 256-bit key space.
///
/// Derives child keys via [`From`] / [`Into`]:
/// - [`SpendAuthorizingKey`] (`ask`)
/// - [`NullifierKey`] (`nk`)
/// - [`PaymentKey`] (`pk`)
#[derive(Clone, Copy, Debug)]
pub struct SpendingKey([u8; 32]);

impl From<[u8; 32]> for SpendingKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl SpendingKey {
    /// Derive $\mathsf{ask}$ from $\mathsf{sk}$, matching Orchard §4.2.3.
    ///
    /// 1. $\mathsf{ask} =
    ///    \text{ToScalar}(\text{PRF}^{\text{expand}}_{\mathsf{sk}}([0\
    ///    text{x}09]))$ BLAKE2b-512 reduced to $\mathbb{F}_q$ via
    ///    `from_uniform_bytes`.
    /// 2. Assert $\mathsf{ask} \neq 0$ (vanishingly unlikely from uniform PRF
    ///    output).
    /// 3. **Sign normalization**: if $\mathsf{ak} =
    ///    [\mathsf{ask}]\,\mathcal{G}$ has $\tilde{y} = 1$, negate
    ///    $\mathsf{ask}$ so that $\mathsf{ak}$ has $\tilde{y} = 0$. Required by
    ///    RedPallas.
    #[must_use]
    pub fn spend_authorizing_key(&self) -> SpendAuthorizingKey {
        let ask = Fq::from_uniform_bytes(&PrfExpand::ASK.with(&self.0));

        assert!(!bool::from(ask.is_zero()), "ask key should not be zero");
        #[expect(clippy::expect_used, reason = "specified behavior")]
        let ret = SpendAuthorizingKey(
            reddsa::SigningKey::<SpendAuth>::try_from(ask.to_repr())
                .expect("ask can derive a valid signing key"),
        );

        // Enforce $\tilde{y} = 0$ on ak: if the sign bit of ak's
        // y-coordinate is 1, negate ask so that $[\mathsf{ask}]\,\mathcal{G}$
        // has $\tilde{y} = 0$.
        if (<[u8; 32]>::from(ret.validating_key().0)[31] >> 7) == 1 {
            #[expect(clippy::unwrap_used, reason = "-ask ≠ 0 when ask ≠ 0")]
            SpendAuthorizingKey(
                reddsa::SigningKey::<SpendAuth>::try_from((-ask).to_repr()).unwrap(),
            )
        } else {
            ret
        }
    }

    /// Derive `nk` from `sk`.
    ///
    /// `nk = ToBase(PRF^expand_sk([0x0a]))` — BLAKE2b-512 reduced to Fp.
    #[must_use]
    pub fn nullifier_key(&self) -> NullifierKey {
        NullifierKey::from_sk(&self.0)
    }

    /// Derive `pk` from `sk`.
    ///
    /// `pk = ToBase(PRF^expand_sk([0x0b]))` — BLAKE2b-512 reduced to Fp.
    #[must_use]
    pub fn payment_key(&self) -> PaymentKey {
        PaymentKey::from_sk(&self.0)
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
    /// Derive the spend validating key: `ak = [ask]G`.
    #[must_use]
    pub fn validating_key(&self) -> SpendValidatingKey {
        // reddsa::VerificationKey::from(&signing_key) performs [sk]G
        // (scalar-times-basepoint), not a trivial type conversion.
        SpendValidatingKey(reddsa::VerificationKey::from(&self.0))
    }

    /// Derive the per-action private (signing) key: $\mathsf{rsk} =
    /// \mathsf{ask} + \alpha$.
    #[must_use]
    pub fn derive_action_private(&self, alpha: &SpendAuthRandomizer) -> RandomizedSigningKey {
        RandomizedSigningKey(self.0.randomize(alpha.inner()))
    }
}

/// Randomized signing key `rsk = ask + alpha` — per-action, ephemeral.
///
/// This is the only key type that **can sign**. Produced by
/// [`SpendAuthorizingKey::derive_action_private`] (spends) or
/// [`for_output`](Self::for_output) (outputs).
#[derive(Clone, Copy, Debug)]
pub struct RandomizedSigningKey(reddsa::SigningKey<SpendAuth>);

impl RandomizedSigningKey {
    /// Sign `msg` with this randomized key.
    pub fn sign(&self, rng: &mut (impl RngCore + CryptoRng), msg: &[u8]) -> SpendAuthSignature {
        SpendAuthSignature(self.0.sign(rng, msg))
    }

    /// Construct `rsk` for an output action (identity `ask`).
    ///
    /// For outputs there is no real `ask`; `rsk = alpha` directly,
    /// giving `rk = [alpha]G`.
    #[must_use]
    pub fn for_output(alpha: &SpendAuthRandomizer) -> Self {
        #[expect(clippy::expect_used, reason = "specified behavior")]
        let sk = reddsa::SigningKey::<SpendAuth>::try_from(alpha.inner().to_repr())
            .expect("random scalar yields valid signing key");
        Self(sk)
    }

    /// Derive the public key: `rk = [rsk]G`.
    #[must_use]
    pub fn public(&self) -> RandomizedVerificationKey {
        // reddsa::VerificationKey::from(&signing_key) performs [sk]G
        // (scalar-times-basepoint), not a trivial type conversion.
        let vk = reddsa::VerificationKey::from(&self.0);
        RandomizedVerificationKey(vk)
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
    pub fn sign(&self, rng: &mut (impl RngCore + CryptoRng), msg: &[u8]) -> BindingSignature {
        BindingSignature(self.0.sign(rng, msg))
    }

    /// Derive the binding verification key:
    /// $\mathsf{bvk} = [\mathsf{bsk}]\,\mathcal{R}$.
    ///
    /// Used for the §4.14 implementation fault check: the signer
    /// SHOULD verify that
    /// $\text{DerivePublic}(\mathsf{bsk}) = \mathsf{bvk}$ (i.e. the
    /// key derived from trapdoor sums matches the key derived from
    /// value commitments).
    #[must_use]
    pub fn verification_key(&self) -> BindingVerificationKey {
        // reddsa::VerificationKey::from(&signing_key) computes [sk] P_G
        // where P_G = R^Orchard for the Binding parameterization.
        BindingVerificationKey(reddsa::VerificationKey::from(&self.0))
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
