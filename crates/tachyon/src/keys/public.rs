//! Public (verification) keys.

use pasta_curves::{EpAffine, group::GroupEncoding as _};

use crate::{action, action::Action, bundle, reddsa, value};

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
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ActionVerificationKey(pub(crate) reddsa::VerificationKey<reddsa::ActionAuth>);

impl ActionVerificationKey {
    /// Verify an action signature against a transaction sighash.
    pub fn verify(&self, sighash: &[u8; 32], sig: &action::Signature) -> Result<(), reddsa::Error> {
        self.0.verify(sighash, &sig.0)
    }
}

#[expect(
    clippy::missing_trait_methods,
    reason = "default assert_receiver_is_total_eq is correct"
)]
impl Eq for ActionVerificationKey {}

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
#[expect(clippy::expect_used, reason = "specified behavior")]
impl From<ActionVerificationKey> for EpAffine {
    fn from(key: ActionVerificationKey) -> Self {
        let bytes: [u8; 32] = key.0.into();
        Self::from_bytes(&bytes)
            .into_option()
            .expect("verification key is a valid curve point")
    }
}

/// Derive the binding verification key from public bundle data.
///
/// $$\mathsf{bvk} = \left(\bigoplus_i \mathsf{cv}_i\right) \ominus
///   \text{ValueCommit}_0\!\left(\mathsf{v\_{balance}}\right)$$
///
/// The result should equal $[\mathsf{bsk}]\,\mathcal{R}$ if the signer
/// constructed the bundle correctly, similar to Orchard's binding key
/// derivation (Protocol §4.14)
#[must_use]
pub fn derive_bvk(
    action_cvs: impl Iterator<Item = value::Commitment>,
    value_balance: i64,
) -> EpAffine {
    let cv_sum: value::Commitment = action_cvs.sum();
    let cb0 = value::Commitment::balance(value_balance);
    EpAffine::from(cv_sum - cb0)
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
#[derive(Clone, Copy, Debug)]
pub struct BindingVerificationKey(pub(super) reddsa::VerificationKey<reddsa::BindingAuth>);

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
        let cvs = actions.iter().map(|action| action.cv);
        Self::from(derive_bvk(cvs, value_balance))
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

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use crate::{
        entropy::ActionEntropy,
        keys::private,
        note::{self, Note},
        primitives::effect,
        value,
    };

    use super::*;

    /// ActionVerificationKey serialization round-trip: key → bytes → key.
    #[test]
    fn action_verification_key_roundtrip() {
        let mut rng = StdRng::seed_from_u64(42);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let ask = sk.derive_auth_private();
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(1000u64),
            psi: note::NullifierTrapdoor::from(Fp::random(&mut rng)),
            rcm: note::CommitmentTrapdoor::from(Fp::random(&mut rng)),
        };
        let theta = ActionEntropy::random(&mut rng);
        let alpha = theta.randomizer::<effect::Spend>(&note.commitment());
        let rsk = ask.derive_action_private(&alpha);
        let rk = rsk.derive_action_public();

        let bytes: [u8; 32] = rk.into();
        let recovered = ActionVerificationKey::try_from(bytes).unwrap();
        assert_eq!(rk, recovered);
    }

    /// Invalid bytes must be rejected by ActionVerificationKey::try_from.
    #[test]
    fn action_verification_key_rejects_invalid_bytes() {
        ActionVerificationKey::try_from([0xFFu8; 32]).unwrap_err();
    }

    /// derive_bvk from public data must match signer's bvk.
    #[test]
    fn derive_bvk_matches_signer() {
        let mut rng = StdRng::seed_from_u64(42);
        let rcv_a = value::CommitmentTrapdoor::random(&mut rng);
        let rcv_b = value::CommitmentTrapdoor::random(&mut rng);
        let cv_a = rcv_a.commit(100);
        let cv_b = rcv_b.commit(-100);

        let bsk = private::BindingSigningKey::from([rcv_a, rcv_b].as_slice());
        let bvk_signer = bsk.derive_binding_public();
        let bvk_verifier = BindingVerificationKey::from(derive_bvk([cv_a, cv_b].into_iter(), 0));

        assert_eq!(bvk_signer, bvk_verifier);
    }

    /// Binding signature verification must fail with wrong sighash.
    #[test]
    fn binding_signature_rejects_wrong_sighash() {
        let mut rng = StdRng::seed_from_u64(42);
        let rcv = value::CommitmentTrapdoor::random(&mut rng);
        let bsk = private::BindingSigningKey::from([rcv].as_slice());
        let bvk = bsk.derive_binding_public();

        let sig = bsk.sign(&mut rng, &[0xAAu8; 32]);
        bvk.verify(&[0xBBu8; 32], &sig).unwrap_err();
    }
}
