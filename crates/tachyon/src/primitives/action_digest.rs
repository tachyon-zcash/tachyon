use ff::{Field as _, PrimeField as _};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{
    EpAffine, Fp,
    arithmetic::{Coordinates, CurveAffine as _},
};

use crate::{
    Action, action::Plan as ActionPlan, constants::ACTION_DIGEST_PERSONALIZATION, keys::public,
    value,
};

/// Digest a single action into the accumulation domain.
///
/// $$ \mathsf{action\_acc} = \prod_i
/// \bigl(\text{Poseidon}_\text{Tachyon-ActnDgst}(\mathsf{cv}_i \|
/// \mathsf{rk}_i) + 1\bigr) $$
///
/// # Panics
///
/// Panics if the digest is zero. Do not digest a preimage for zero.
fn digest_action(cv: Coordinates<EpAffine>, rk: Coordinates<EpAffine>) -> ActionDigest {
    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    let personalization = Fp::from_u128(u128::from_le_bytes(*ACTION_DIGEST_PERSONALIZATION));

    let hash = Hash::<_, P128Pow5T3, ConstantLength<5>, 3, 2>::init().hash([
        personalization,
        *cv.x(),
        *cv.y(),
        *rk.x(),
        *rk.y(),
    ]);

    assert!(!hash.is_zero_vartime(), "sell now");

    ActionDigest(hash)
}

/// Order-independent accumulator of one or more actions.
/// $$\mathsf{action\_acc} = \prod_i
///     \text{Poseidon}(\text{domain},\; \mathsf{cv}_i \| \mathsf{rk}_i)$$
///
/// Each action's $(\mathsf{cv}, \mathsf{rk})$ is hashed. Multiple digests
/// combine via field multiplication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionDigest(Fp);

/// Errors from action digest computation.
#[derive(Debug)]
pub enum ActionDigestError {
    /// The cv is the identity point, so the digest cannot be computed.
    IdentityCv,
    /// The rk is the identity point, so the digest cannot be computed.
    IdentityRk,
}

impl ActionDigest {
    /// Digest a single action's $(\mathsf{cv}, \mathsf{rk})$ pair.
    pub fn new(
        cv: value::Commitment,
        rk: public::ActionVerificationKey,
    ) -> Result<Self, ActionDigestError> {
        let cv_coords = EpAffine::from(cv)
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::IdentityCv)?;
        let rk_coords = EpAffine::from(rk)
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::IdentityRk)?;

        Ok(digest_action(cv_coords, rk_coords))
    }

    /// Combine two digests.
    #[must_use]
    pub fn accumulate(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl FromIterator<Self> for ActionDigest {
    fn from_iter<I: IntoIterator<Item = Self>>(iter: I) -> Self {
        iter.into_iter().fold(Self::default(), Self::accumulate)
    }
}

/// The identity element for accumulation (currently `Fp::ONE`).
impl Default for ActionDigest {
    fn default() -> Self {
        Self(Fp::ONE)
    }
}

impl TryFrom<&ActionPlan> for ActionDigest {
    type Error = ActionDigestError;

    fn try_from(plan: &ActionPlan) -> Result<Self, Self::Error> {
        let cv_coords = EpAffine::from(plan.cv())
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::IdentityCv)?;
        let rk_coords = EpAffine::from(plan.rk)
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::IdentityRk)?;

        Ok(digest_action(cv_coords, rk_coords))
    }
}

impl TryFrom<&Action> for ActionDigest {
    type Error = ActionDigestError;

    fn try_from(action: &Action) -> Result<Self, Self::Error> {
        let cv_coords = EpAffine::from(action.cv)
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::IdentityCv)?;
        let rk_coords = EpAffine::from(action.rk)
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::IdentityRk)?;
        Ok(digest_action(cv_coords, rk_coords))
    }
}

impl From<ActionDigest> for [u8; 32] {
    fn from(digest: ActionDigest) -> Self {
        digest.0.to_repr()
    }
}

impl TryFrom<&[u8; 32]> for ActionDigest {
    type Error = &'static str;

    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        let fp: Fp = Option::from(Fp::from_repr(*bytes)).ok_or("invalid field element")?;
        if fp.is_zero_vartime() {
            return Err("zero digest");
        }
        Ok(Self(fp))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ActionDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use ff::PrimeField as _;

        serializer.serialize_bytes(&self.0.to_repr())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ActionDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use crate::serde_helpers::FpVisitor;

        deserializer.deserialize_bytes(FpVisitor).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fp;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        entropy::ActionEntropy,
        keys::private,
        note::{self, CommitmentTrapdoor, Note, NullifierTrapdoor},
        value,
    };

    /// Build a (cv, rk) pair from a note, random rcv, and random theta.
    fn make_action_parts(
        rng: &mut StdRng,
        sk: &private::SpendingKey,
        val: u64,
        psi: Fp,
        rcm: Fp,
    ) -> (value::Commitment, public::ActionVerificationKey) {
        let note = Note {
            pk: sk.derive_payment_key(),
            value: note::Value::from(val),
            psi: NullifierTrapdoor::from(psi),
            rcm: CommitmentTrapdoor::from(rcm),
        };
        let rcv = value::CommitmentTrapdoor::random(rng);
        let cv = rcv.commit_spend(note);
        let theta = ActionEntropy::random(rng);
        let alpha = theta.output_randomizer(&note.commitment());
        let rk = private::ActionSigningKey::new(alpha).derive_action_public();
        (cv, rk)
    }

    /// Digest merge is commutative: A·B == B·A.
    #[test]
    fn digest_commutative() {
        let mut rng = StdRng::seed_from_u64(200);
        let sk = private::SpendingKey::from([0x42u8; 32]);

        let (cv_a, rk_a) = make_action_parts(&mut rng, &sk, 1000, Fp::ZERO, Fp::ZERO);
        let (cv_b, rk_b) = make_action_parts(&mut rng, &sk, 700, Fp::ONE, Fp::ONE);

        let digest_a = ActionDigest::new(cv_a, rk_a).unwrap();
        let digest_b = ActionDigest::new(cv_b, rk_b).unwrap();

        assert_eq!(digest_a.accumulate(digest_b), digest_b.accumulate(digest_a));
    }

    /// Different (cv, rk) pairs produce different digests.
    #[test]
    fn distinct_actions_distinct_digests() {
        let mut rng = StdRng::seed_from_u64(201);
        let sk = private::SpendingKey::from([0x42u8; 32]);

        let (cv_a, rk_a) = make_action_parts(&mut rng, &sk, 1000, Fp::ZERO, Fp::ZERO);
        let (cv_b, rk_b) = make_action_parts(&mut rng, &sk, 700, Fp::ONE, Fp::ONE);

        assert_ne!(
            ActionDigest::new(cv_a, rk_a).unwrap(),
            ActionDigest::new(cv_b, rk_b).unwrap()
        );
    }

    /// Identity element: merging with identity is a no-op.
    #[test]
    fn identity_element() {
        let mut rng = StdRng::seed_from_u64(202);
        let sk = private::SpendingKey::from([0x42u8; 32]);

        let (cv, rk) = make_action_parts(&mut rng, &sk, 500, Fp::ZERO, Fp::ZERO);
        let digest = ActionDigest::new(cv, rk).unwrap();

        assert_eq!(digest.accumulate(ActionDigest::default()), digest);
        assert_eq!(ActionDigest::default().accumulate(digest), digest);
    }

    /// Empty accumulation produces the identity.
    #[test]
    fn empty_accumulate_is_identity() {
        let acc: ActionDigest = vec![].into_iter().collect();
        assert_eq!(acc, ActionDigest::default());
    }

    /// Identity cv is rejected.
    #[test]
    fn digest_rejects_identity_cv() {
        use pasta_curves::group::prime::PrimeCurveAffine as _;

        let mut rng = StdRng::seed_from_u64(203);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let (_, rk) = make_action_parts(&mut rng, &sk, 500, Fp::ZERO, Fp::ZERO);
        let cv = value::Commitment::from(EpAffine::identity());
        assert!(matches!(
            ActionDigest::new(cv, rk),
            Err(ActionDigestError::IdentityCv)
        ));
    }

    /// Identity rk is rejected.
    #[test]
    fn digest_rejects_identity_rk() {
        let mut rng = StdRng::seed_from_u64(204);
        let sk = private::SpendingKey::from([0x42u8; 32]);
        let (cv, _) = make_action_parts(&mut rng, &sk, 500, Fp::ZERO, Fp::ZERO);
        let rk = public::ActionVerificationKey::try_from([0u8; 32]).unwrap();
        assert!(matches!(
            ActionDigest::new(cv, rk),
            Err(ActionDigestError::IdentityRk)
        ));
    }
}
