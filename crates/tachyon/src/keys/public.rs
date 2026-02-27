//! Public (verification) keys.

use pasta_curves::{EpAffine, group::GroupEncoding as _};
use reddsa::orchard::{Binding, SpendAuth};
use serde::{Deserialize, Serialize};

use crate::{action, action::Action, bundle, value};

/// The randomized action verification key `rk` — per-action, public.
///
/// This is the only key type that **can verify** action signatures.
/// Goes into [`Action`](crate::Action). Terminal type — no further
/// derivation.
///
/// Both spend and output actions produce an `rk`
/// ("Tachyaction at a Distance", Bowe 2025):
///
/// - **Spend**: $\mathsf{rk} = \mathsf{ak} + [\alpha]\,\mathcal{G}$ — requires
///   knowledge of $\mathsf{ask}$
/// - **Output**: $\mathsf{rk} = [\alpha]\,\mathcal{G}$ — no spending authority
///   needed
///
/// This unification lets consensus treat all actions identically while
/// the type system enforces the authority boundary at construction time.
#[derive(Clone, Copy, Debug)]
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
pub struct ActionVerificationKey(pub(super) reddsa::VerificationKey<SpendAuth>);

impl PartialEq for ActionVerificationKey {
    fn eq(&self, other: &Self) -> bool {
        let self_bytes: [u8; 32] = (*self).into();
        let other_bytes: [u8; 32] = (*other).into();
        self_bytes == other_bytes
    }
}

impl Eq for ActionVerificationKey {}

impl serde::Serialize for ActionVerificationKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bytes: [u8; 32] = (*self).into();
        bytes.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ActionVerificationKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Self::try_from(bytes).map_err(serde::de::Error::custom)
    }
}

impl ActionVerificationKey {
    /// Verify an action signature.
    pub fn verify(
        &self,
        sighash: action::SigHash,
        sig: &action::Signature,
    ) -> Result<(), reddsa::Error> {
        let msg: [u8; 64] = sighash.into();
        self.0.verify(&msg, &sig.0)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for ActionVerificationKey {
    fn into(self) -> [u8; 32] {
        self.0.into()
    }
}

impl TryFrom<[u8; 32]> for ActionVerificationKey {
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
#[expect(clippy::field_scoped_visibility_modifiers, reason = "for internal use")]
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
    pub fn derive(actions: &[Action], value_balance: i64) -> Self {
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
    pub fn verify(
        &self,
        sighash: bundle::SigHash,
        sig: &bundle::Signature,
    ) -> Result<(), reddsa::Error> {
        let msg: [u8; 64] = sighash.into();
        self.0.verify(&msg, &sig.0)
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
