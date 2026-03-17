//! Custody keys — signing-device-only keys whose compromise means fund loss.
//!
//! These keys live on the signing device (e.g. hardware wallet) and never
//! leave it. They derive per-action signing keys and produce signatures.

use core::marker::PhantomData;

use ff::{FromUniformBytes as _, PrimeField as _};
// TODO(#39): replace halo2_poseidon with Ragu Poseidon params
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{Fp, Fq};

use super::{
    note::{Master, NoteKey},
    planner::{self, ActionSigningKey, NoteMasterKey},
};
use crate::{
    constants::{NOTE_MASTER_DOMAIN, PrfExpand},
    entropy::ActionRandomizer,
    note::NullifierTrapdoor,
    primitives::effect,
    reddsa,
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
/// - [`derive_nullifier_private`](Self::derive_nullifier_private) →
///   [`NullifierKey`] (`nk`)
/// - [`derive_payment_key`](Self::derive_payment_key) →
///   [`PaymentKey`](planner::PaymentKey) (`pk`)
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
    /// The reddsa::ActionAuth basepoint $\mathcal{G}$ is hash-derived
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
            &reddsa::SigningKey::<reddsa::ActionAuth>::try_from(ask.to_repr())
                .expect("PRF-derived ask should be a valid RedPallas scalar"),
        )
        .into();
        if ak[31] >> 7u8 == 1u8 {
            ask = -ask;
        }

        // Build the final key from the sign-normalized scalar.
        SpendAuthorizingKey(
            reddsa::SigningKey::<reddsa::ActionAuth>::try_from(ask.to_repr())
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
    pub fn derive_payment_key(&self) -> planner::PaymentKey {
        planner::PaymentKey(Fp::from_uniform_bytes(&PrfExpand::PK.with(&self.0)))
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
/// `ask` derives [`SpendValidatingKey`](private::SpendValidatingKey)
/// (`ak`) via [`derive_auth_public`](Self::derive_auth_public) — the
/// circuit witness that validates spend authorization.
#[derive(Clone, Copy, Debug)]
pub struct SpendAuthorizingKey(reddsa::SigningKey<reddsa::ActionAuth>);

impl SpendAuthorizingKey {
    /// Derive the spend validating (public) key: `ak = [ask]G`.
    #[must_use]
    pub fn derive_auth_public(&self) -> planner::SpendValidatingKey {
        // reddsa::VerificationKey::from(&signing_key) performs [sk]G
        // (scalar-times-basepoint), not a trivial type conversion.
        planner::SpendValidatingKey(reddsa::VerificationKey::from(&self.0))
    }

    /// Derive the per-action private (signing) key: $\mathsf{rsk} =
    /// \mathsf{ask} + \alpha$.
    ///
    /// Only accepts [`ActionRandomizer<Spend>`] — passing an output randomizer
    /// is a compile error.
    #[must_use]
    pub fn derive_action_private(
        &self,
        alpha: &ActionRandomizer<effect::Spend>,
    ) -> ActionSigningKey<effect::Spend> {
        ActionSigningKey(self.0.randomize(&alpha.0), PhantomData)
    }
}

/// A Tachyon nullifier deriving key.
///
/// Wallet-wide secret that derives per-note master keys. Its compromise
/// reveals all spending activity — it belongs on the custody device
/// alongside [`SpendingKey`].
///
/// $$\mathsf{mk} = \text{KDF}(\psi, \mathsf{nk})$$
///
/// The custody device derives `mk` from `nk` and the note's $\psi$
/// trapdoor, then hands `mk` to the planner.
#[derive(Clone, Copy, Debug)]
pub struct NullifierKey(pub(super) Fp);

impl NullifierKey {
    /// Derive the per-note master root key: $\mathsf{mk} = \text{KDF}(\psi,
    /// \mathsf{nk})$.
    ///
    /// `mk` is the root of the GGM tree for one note. It is used to:
    /// - Derive nullifiers directly: $\mathsf{nf} =
    ///   F_{\mathsf{mk}}(\text{flavor})$
    /// - Derive epoch-restricted prefix keys $\Psi_t$ for OSS delegation
    #[must_use]
    pub fn derive_note_private(&self, psi: &NullifierTrapdoor) -> NoteMasterKey {
        #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
        let personalization = Fp::from_u128(u128::from_le_bytes(*NOTE_MASTER_DOMAIN));
        NoteKey {
            inner: Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
                personalization,
                psi.0,
                self.0,
            ]),
            prefix: Master,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for NullifierKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use ff::PrimeField as _;

        serializer.serialize_bytes(&self.0.to_repr())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for NullifierKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use crate::serde_helpers::FpVisitor;

        deserializer.deserialize_bytes(FpVisitor).map(Self)
    }
}
