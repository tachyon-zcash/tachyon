#![expect(
    clippy::field_scoped_visibility_modifiers,
    reason = "implement key relationships within submodule"
)]

//! Public (verification) keys.

#![allow(clippy::from_over_into, reason = "restricted conversions")]

use pasta_curves::{EpAffine, group::GroupEncoding as _};
use reddsa::orchard::{Binding, SpendAuth};

use super::signature::{BindingSignature, SpendAuthSignature};
use crate::{primitives::SpendAuthRandomizer, value};

/// The spend validating key `ak = [ask]G` — the public counterpart of
/// [`SpendAuthorizingKey`](super::SpendAuthorizingKey).
///
/// `ak` **cannot verify action signatures directly**. The prover uses
/// [`derive_action_public`](Self::derive_action_public) to compute the
/// per-action [`RandomizedVerificationKey`] (`rk`) for the proof witness.
///
/// ## Current uses
///
/// - Component of [`ProvingKey`](super::ProvingKey) (proof delegation without
///   spend authority)
///
/// ## Planned uses
///
/// - **Proof-side `rk` derivation**: the prover recomputes $\alpha =
///   \text{derive}(\theta, \mathsf{cmx})$ via [`SpendAuthRandomizer::derive`],
///   then derives $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$ via
///   [`derive_action_public`](Self::derive_action_public).
#[derive(Clone, Copy, Debug)]
pub struct SpendValidatingKey(pub(super) reddsa::VerificationKey<SpendAuth>);

impl SpendValidatingKey {
    /// Derive the per-action public (verification) key: $\mathsf{rk} =
    /// \mathsf{ak} + [\alpha]\,\mathcal{G}$.
    ///
    /// Used by the prover (who has [`ProvingKey`](super::ProvingKey) containing
    /// `ak`) to compute the `rk` that the Ragu circuit constrains. During
    /// action construction the signer derives `rk` via
    /// [`RandomizedSigningKey::public`](super::RandomizedSigningKey::public)
    /// instead.
    #[must_use]
    pub fn derive_action_public(&self, alpha: &SpendAuthRandomizer) -> RandomizedVerificationKey {
        RandomizedVerificationKey(self.0.randomize(alpha.inner()))
    }
}

impl Into<[u8; 32]> for SpendValidatingKey {
    fn into(self) -> [u8; 32] {
        self.0.into()
    }
}

/// Randomized verification key `rk = ak + [alpha]G` — per-action, public.
///
/// This is the only key type that **can verify** action signatures.
/// Goes into [`Action`](crate::Action). Terminal type — no further
/// derivation.
#[derive(Clone, Copy, Debug)]
pub struct RandomizedVerificationKey(pub(super) reddsa::VerificationKey<SpendAuth>);

impl RandomizedVerificationKey {
    /// Verify a spend authorization signature.
    pub fn verify(&self, msg: &[u8], sig: &SpendAuthSignature) -> Result<(), reddsa::Error> {
        self.0.verify(msg, &sig.0)
    }
}

impl Into<[u8; 32]> for RandomizedVerificationKey {
    fn into(self) -> [u8; 32] {
        self.0.into()
    }
}

impl TryFrom<[u8; 32]> for RandomizedVerificationKey {
    type Error = reddsa::Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        reddsa::VerificationKey::<SpendAuth>::try_from(bytes).map(Self)
    }
}

/// Binding verification key $\mathsf{bvk}$ — derived from value
/// commitments.
///
/// $$\mathsf{bvk} := \left(\bigoplus_i \mathsf{cv}_i\right) \ominus
///   \text{ValueCommit}_0\!\left(\mathsf{v\_{balance}}\right)$$
///
/// That is: sum all action value commitments (Pallas curve points),
/// then subtract the deterministic commitment to the value balance
/// with zero randomness. This key is **not encoded in the
/// transaction** — validators recompute it from public data (§4.14).
///
/// When the transaction is correctly constructed,
/// $\mathsf{bvk} = [\mathsf{bsk}]\,\mathcal{R}$ because the
/// $\mathcal{V}$-component cancels
/// ($\sum_i v_i = \mathsf{v\_{balance}}$), leaving only the
/// $\mathcal{R}$-component
/// $[\sum_i \mathsf{rcv}_i]\,\mathcal{R} = [\mathsf{bsk}]\,\mathcal{R}$.
///
/// A validator checks balance by verifying:
/// $\text{BindingSig.Validate}_{\mathsf{bvk}}(\text{sighash},
///   \text{bindingSig}) = 1$
///
/// ## Type representation
///
/// Wraps `reddsa::VerificationKey<Binding>`, which internally stores
/// a Pallas curve point (EpAffine, encoded as 32 compressed bytes).
#[derive(Clone, Copy, Debug)]
pub struct BindingVerificationKey(pub(super) reddsa::VerificationKey<Binding>);

impl BindingVerificationKey {
    /// Derive the binding verification key from public action data.
    ///
    /// $$\mathsf{bvk} = \left(\bigoplus_i \mathsf{cv}_i\right) \ominus
    ///   \text{ValueCommit}_0\!\left(\mathsf{v\_{balance}}\right)$$
    ///
    /// This is the validator-side derivation similar to Orchard. (§4.14). The
    /// result should equal $[\mathsf{bsk}]\,\mathcal{R}$ when the signer
    /// constructed the bundle correctly.
    #[must_use]
    pub fn derive(actions: &[crate::Action], value_balance: i64) -> Self {
        let cv_sum: value::Commitment = actions.iter().map(|action| action.cv).sum();
        let balance_commit = value::Commitment::balance(value_balance);
        let bvk_point: EpAffine = (cv_sum - balance_commit).into();
        let bvk_bytes: [u8; 32] = bvk_point.to_bytes();

        #[expect(clippy::expect_used, reason = "specified behavior")]
        Self(
            reddsa::VerificationKey::<Binding>::try_from(bvk_bytes)
                .expect("derived bvk is a valid verification key"),
        )
    }

    /// Verify a binding signature.
    pub fn verify(&self, msg: &[u8], sig: &BindingSignature) -> Result<(), reddsa::Error> {
        self.0.verify(msg, &sig.0)
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "default ne/assert impls are correct"
)]
impl PartialEq for BindingVerificationKey {
    fn eq(&self, other: &Self) -> bool {
        <[u8; 32]>::from(self.0) == <[u8; 32]>::from(other.0)
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "default assert_receiver_is_total_eq is correct"
)]
impl Eq for BindingVerificationKey {}

impl From<BindingVerificationKey> for [u8; 32] {
    fn from(bvk: BindingVerificationKey) -> Self {
        bvk.0.into()
    }
}

impl TryFrom<[u8; 32]> for BindingVerificationKey {
    type Error = reddsa::Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        reddsa::VerificationKey::<Binding>::try_from(bytes).map(Self)
    }
}
