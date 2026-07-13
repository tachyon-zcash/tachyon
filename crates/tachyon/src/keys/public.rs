//! Public (verification) keys.

use core::cmp::Eq as CoreTotalEq;

use derive_more::{Debug, Display, PartialEq};
use pasta_curves::{EpAffine, group::GroupEncoding as _};

use crate::{
    action::{self, Action},
    bundle, reddsa, value,
};

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
#[derive(Clone, Copy, Debug, Display, PartialEq)]
#[display("ActionVerificationKey({:?})", reddsa::VerificationKeyBytes::from(self.0))]
pub struct ActionVerificationKey(pub(crate) reddsa::VerificationKey<reddsa::ActionAuth>);

impl CoreTotalEq for ActionVerificationKey {}

impl ActionVerificationKey {
    /// Verify an action signature against a transaction sighash.
    pub fn verify(&self, sighash: &[u8; 32], sig: &action::Signature) -> Result<(), reddsa::Error> {
        self.0.verify(sighash, &sig.0)
    }
}

impl From<ActionVerificationKey> for [u8; 32] {
    fn from(avk: ActionVerificationKey) -> Self {
        avk.0.into()
    }
}

impl TryFrom<[u8; 32]> for ActionVerificationKey {
    type Error = reddsa::Error;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        reddsa::VerificationKey::<reddsa::ActionAuth>::try_from(bytes).map(Self)
    }
}

/// Decompress the verification key to an affine curve point.
impl From<ActionVerificationKey> for EpAffine {
    fn from(key: ActionVerificationKey) -> Self {
        let bytes: [u8; 32] = key.0.into();
        Self::from_bytes(&bytes).expect("verification key is a valid curve point")
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
/// $\text{BindingSig.Validate}_{\mathsf{bvk}}(\mathsf{sighash},
///   \text{bindingSig}) = 1$
///
/// ## Type representation
///
/// Wraps `reddsa::VerificationKey<reddsa::BindingAuth>`, which internally
/// stores a Pallas curve point (EpAffine, encoded as 32 compressed bytes).
#[derive(Clone, Copy, Debug, Display, PartialEq)]
#[display("BindingVerificationKey({:?})", reddsa::VerificationKeyBytes::from(self.0))]
pub struct BindingVerificationKey(pub(super) reddsa::VerificationKey<reddsa::BindingAuth>);

impl CoreTotalEq for BindingVerificationKey {}

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
    pub fn derive(actions: &[Action], value_balance: value::Balance) -> Self {
        let cv_sum: value::Commitment = actions.iter().map(|action| action.cv).sum();
        let cvb = value::Trapdoor::ZERO.commit(value_balance);
        Self::from(EpAffine::from(cv_sum - cvb))
    }

    /// Verify a binding signature against a transaction sighash.
    pub fn verify(&self, sighash: &[u8; 32], sig: &bundle::Signature) -> Result<(), reddsa::Error> {
        self.0.verify(sighash, &sig.0)
    }
}

impl From<EpAffine> for BindingVerificationKey {
    fn from(point: EpAffine) -> Self {
        let bvk_bytes: [u8; 32] = point.to_bytes();

        #[expect(clippy::expect_used, reason = "specified behavior")]
        Self(
            reddsa::VerificationKey::<reddsa::BindingAuth>::try_from(bvk_bytes)
                .expect("EpAffine point should be a valid RedPallas verification key"),
        )
    }
}
