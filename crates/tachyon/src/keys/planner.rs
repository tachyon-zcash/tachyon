//! Private keys — user-device confidential keys that never leave the
//! user's control but do not directly confer signing authority.

use core::{iter::Sum, marker::PhantomData};

use ff::{Field as _, PrimeField as _};
use pasta_curves::{Fp, Fq};
use rand_core::{CryptoRng, RngCore};

use super::public;
use crate::{
    action, bundle,
    entropy::ActionRandomizer,
    primitives::effect::{self, Effect},
    reddsa, value,
};

/// The spend validating key $\mathsf{ak} = [\mathsf{ask}]\,\mathcal{G}$ —
/// the long-lived counterpart of
/// [`SpendAuthorizingKey`](super::custody::SpendAuthorizingKey).
///
/// Corresponds to the "spend validating key" in Orchard (§4.2.3).
/// Constrains per-action `rk` in the proof, tying accumulator activity
/// to the holder of `ask`.
///
/// `ak` **cannot verify action signatures directly** — the prover uses
/// [`derive_action_public`](Self::derive_action_public) to compute the
/// per-action `rk` for the proof witness. Component of
/// [`ProofAuthorizingKey`](super::delegate::ProofAuthorizingKey) for proof
/// authorization without spend authority.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct SpendValidatingKey(pub(super) reddsa::VerificationKey<reddsa::ActionAuth>);

impl SpendValidatingKey {
    /// Derive the per-action public (verification) key: $\mathsf{rk} =
    /// \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    ///
    /// Used by the prover (who has
    /// [`ProofAuthorizingKey`](super::delegate::ProofAuthorizingKey) containing
    /// `ak`) to compute the `rk` that the Ragu circuit constrains. During
    /// action construction the signer derives `rk` via
    /// [`ActionSigningKey::derive_action_public`] instead.
    #[must_use]
    pub fn derive_action_public(
        &self,
        alpha: &ActionRandomizer<effect::Spend>,
    ) -> public::ActionVerificationKey {
        public::ActionVerificationKey(self.0.randomize(&alpha.0))
    }
}

/// The per-action signing key `rsk` — ephemeral, parameterized by kind.
///
/// - [`ActionSigningKey<Spend>`]: $\mathsf{rsk} = \mathsf{ask} +
///   \alpha$ — derived from
///   [`SpendAuthorizingKey::derive_action_private`](super::custody::SpendAuthorizingKey::derive_action_private)
/// - [`ActionSigningKey<Output>`]: $\mathsf{rsk} = \alpha$ — derived from
///   [`ActionRandomizer<Output>`]
///
/// Both variants sign via [`sign`](Self::sign) and derive `rk` via
/// [`derive_action_public`](Self::derive_action_public).
#[derive(Clone, Copy, Debug)]
pub struct ActionSigningKey<K: Effect>(
    pub(super) reddsa::SigningKey<reddsa::ActionAuth>,
    pub(super) PhantomData<K>,
);

impl<K: Effect> ActionSigningKey<K> {
    /// Sign a transaction sighash with this action key.
    pub fn sign(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        sighash: &[u8; 32],
    ) -> action::Signature {
        action::Signature(self.0.sign(rng, sighash))
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

impl ActionSigningKey<effect::Output> {
    /// Create a new output action signing key from an output randomizer.
    #[must_use]
    #[expect(clippy::expect_used, reason = "specified behavior")]
    pub fn new(alpha: &ActionRandomizer<effect::Output>) -> Self {
        Self(
            reddsa::SigningKey::<reddsa::ActionAuth>::try_from(alpha.0.to_repr())
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
pub struct BindingSigningKey(reddsa::SigningKey<reddsa::BindingAuth>);

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

impl Sum<value::CommitmentTrapdoor> for BindingSigningKey {
    /// Binding signing key is the scalar sum of all value commitment trapdoors.
    ///
    /// Every Pallas scalar field element, including zero, is a valid binding
    /// signing key. See Zcash protocol §4.14.
    #[expect(
        clippy::expect_used,
        reason = "all Fq are valid RedPallas signing keys"
    )]
    fn sum<I: Iterator<Item = value::CommitmentTrapdoor>>(iter: I) -> Self {
        let sum: Fq = iter.fold(Fq::ZERO, |acc, rcv| acc + Into::<Fq>::into(rcv));
        Self(
            reddsa::SigningKey::<reddsa::BindingAuth>::try_from(sum.to_repr())
                .expect("all Fq are valid RedPallas signing keys"),
        )
    }
}

impl From<&[value::CommitmentTrapdoor]> for BindingSigningKey {
    /// Binding signing key is the scalar sum of all value commitment trapdoors.
    ///
    /// Every Pallas scalar field element, including zero, is a valid binding
    /// signing key. See Zcash protocol §4.14.
    fn from(trapdoors: &[value::CommitmentTrapdoor]) -> Self {
        trapdoors.iter().copied().sum()
    }
}

/// A Tachyon payment key — static per-spending-key recipient identifier.
///
/// Replaces Orchard's diversified transmission key $\mathsf{pk_d}$ and
/// the entire diversified address system. Tachyon removes the diversifier
/// $d$ because payment addresses are removed from the on-chain protocol
/// ("Tachyaction at a Distance", Bowe 2025):
///
/// > "The transmission key $\mathsf{pk_d}$ is substituted with a payment
/// > key $\mathsf{pk}$."
///
/// ## Derivation
///
/// Deterministic per-`sk`: $\mathsf{pk} =
/// \text{ToBase}(\text{PRF}^{\text{expand}}_{\mathsf{sk}}([0\text{x}0b]))$.
/// Every note from the same spending key shares the same `pk`. There is
/// no per-note diversification — unlinkability is the wallet layer's
/// responsibility, not the core protocol's.
///
/// ## Usage
///
/// The recipient's `pk` appears in the note and is committed to in the
/// note commitment. It is NOT an on-chain address; payment coordination
/// happens out-of-band via higher-level protocols (ZIP 321 payment
/// requests, ZIP 324 URI encapsulated payments).
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct PaymentKey(pub(crate) Fp);

#[cfg(feature = "serde")]
impl serde::Serialize for PaymentKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use ff::PrimeField as _;

        serializer.serialize_bytes(&self.0.to_repr())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PaymentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use crate::serde_helpers::FpVisitor;

        deserializer.deserialize_bytes(FpVisitor).map(Self)
    }
}

/// Per-note master root key $\mathsf{mk} = \text{KDF}(\psi, \mathsf{nk})$.
///
/// Root of the GGM tree PRF for a single note. Derived by the custody device
/// from [`NullifierKey`](super::custody::NullifierKey) and the note's $\psi$
/// trapdoor.
///
/// ## Delegation chain
///
/// ```text
/// nk + psi → mk (per-note root, user device)
///              ├── nf = F_mk(flavor)     nullifier for a specific epoch
///              └── psi_t = GGM(mk, t)    prefix key for epochs e ≤ t (OSS)
/// ```
///
/// `mk` is not stored or transmitted — the user device derives it
/// ephemerally when needed. The OSS receives only the prefix keys.
pub type NoteMasterKey = super::note::NoteKey<super::note::Master>;

/// Error from deserializing a [`NoteMasterKey`].
pub type NoteKeyError = super::note::NoteKeyError;

#[cfg(test)]
mod tests {
    use core::num::NonZeroU8;

    use super::*;
    use crate::{
        keys::{custody::NullifierKey, note::Prefix},
        note::NullifierTrapdoor,
        primitives::Epoch,
    };

    #[test]
    fn derive_note_private_deterministic() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk1 = nk.derive_note_private(&psi);
        let mk2 = nk.derive_note_private(&psi);
        assert_eq!(mk1, mk2);
    }

    #[test]
    fn different_psi_different_mk() {
        let nk = NullifierKey(Fp::from(42u64));
        let mk1 = nk.derive_note_private(&NullifierTrapdoor::from(Fp::from(1u64)));
        let mk2 = nk.derive_note_private(&NullifierTrapdoor::from(Fp::from(2u64)));
        assert_ne!(mk1, mk2);
    }

    #[test]
    fn different_epochs_different_nullifiers() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);
        assert_ne!(
            mk.derive_nullifier(Epoch::from(0u32)),
            mk.derive_nullifier(Epoch::from(1u32)),
        );
    }

    /// Prefix key (index 0) produces same nullifier as master key for
    /// epochs within the authorized range.
    #[test]
    fn prefix_matches_master_at_index_zero() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);

        // depth=26 → window of 64 epochs at index 0 → epochs [0..=63]
        let prefix = Prefix::new(NonZeroU8::new(26u8).unwrap(), 0).unwrap();
        let dk = &mk.derive_note_delegates([prefix])[0];

        for epoch in 0..64u32 {
            assert_eq!(
                mk.derive_nullifier(Epoch::from(epoch)),
                dk.derive_nullifier(Epoch::from(epoch)).unwrap(),
                "mismatch at epoch {epoch}"
            );
        }
    }

    /// Prefix key at a non-zero index produces same nullifiers as
    /// master key for epochs within its range.
    #[test]
    fn prefix_matches_master_at_nonzero_index() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);

        // depth=26 → window of 64 epochs at index 1 → epochs [64..=127]
        let prefix = Prefix::new(NonZeroU8::new(26u8).unwrap(), 1).unwrap();
        let dk = &mk.derive_note_delegates([prefix])[0];

        for epoch in 64..128u32 {
            assert_eq!(
                mk.derive_nullifier(Epoch::from(epoch)),
                dk.derive_nullifier(Epoch::from(epoch)).unwrap(),
                "mismatch at epoch {epoch}"
            );
        }
    }

    /// Prefix cover produces same nullifiers as master for all
    /// epochs in the covered range.
    #[test]
    fn cover_matches_master() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);

        let prefixes = Prefix::tight(0, 100);
        for dk in &mk.derive_note_delegates(prefixes) {
            for epoch in dk.prefix.first()..=dk.prefix.last() {
                assert_eq!(
                    mk.derive_nullifier(Epoch::from(epoch)),
                    dk.derive_nullifier(Epoch::from(epoch)).unwrap(),
                    "mismatch at epoch {epoch} with delegate {dk:?}"
                );
            }
        }
    }

    /// A prefix key returns `None` for epochs outside its authorized range.
    #[test]
    fn prefix_rejects_outside_range() {
        let nk = NullifierKey(Fp::from(42u64));
        let psi = NullifierTrapdoor::from(Fp::from(99u64));
        let mk = nk.derive_note_private(&psi);

        // depth=26 index=0 → epochs [0..=63]
        let prefix = Prefix::new(NonZeroU8::new(26u8).unwrap(), 0).unwrap();
        let dk = &mk.derive_note_delegates([prefix])[0];

        // epoch 64 is outside the authorized range
        assert!(dk.derive_nullifier(Epoch::from(64u32)).is_none());
    }
}
