use core::{error::Error, fmt};

use ff::PrimeField as _;
// TODO(#39): replace halo2_poseidon with Ragu Poseidon params
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{
    EpAffine, Fp,
    arithmetic::{Coordinates, CurveAffine as _},
};

use crate::{
    Action, action, constants::ACTION_DIGEST_PERSONALIZATION, keys::public,
    primitives::effect::Effect, value,
};

/// Digest a single action into the accumulation domain.
///
/// $$ \mathsf{action\_acc} = \prod_i
/// \bigl(\text{Poseidon}_\text{Tachyon-ActnDgst}(\mathsf{cv}_i \|
/// \mathsf{rk}_i) + 1\bigr) $$
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

    ActionDigest(hash)
}

/// Poseidon digest of a single action's $(\mathsf{cv}, \mathsf{rk})$ pair.
///
/// Each action produces one digest, which serves as a root in the
/// accumulator polynomial. Multiple actions are accumulated via
/// polynomial commitment, not on this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionDigest(Fp);

/// Errors from action digest computation.
#[derive(Clone, Copy, Debug)]
pub enum ActionDigestError {
    /// The cv is the identity point, so the digest cannot be computed.
    IdentityCv,
    /// The rk is the identity point, so the digest cannot be computed.
    IdentityRk,
}

impl fmt::Display for ActionDigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            | Self::IdentityCv => write!(f, "cv is the identity point"),
            | Self::IdentityRk => write!(f, "rk is the identity point"),
        }
    }
}

impl Error for ActionDigestError {}

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
}

/// Extract the inner field element (polynomial root).
impl From<ActionDigest> for Fp {
    fn from(digest: ActionDigest) -> Self {
        digest.0
    }
}

impl<E: Effect + 'static> TryFrom<&action::Plan<E>> for ActionDigest {
    type Error = ActionDigestError;

    fn try_from(plan: &action::Plan<E>) -> Result<Self, Self::Error> {
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
        keys::{custody, planner},
        note::{self, CommitmentTrapdoor, Note, NullifierTrapdoor},
        primitives::effect,
        value,
    };

    /// Build a (cv, rk) pair from a note, random rcv, and random theta.
    fn make_action_parts(
        rng: &mut StdRng,
        sk: &custody::SpendingKey,
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
        let value: i64 = note.value.into();
        let cv = rcv.commit(value);
        let theta = ActionEntropy::random(rng);
        let alpha = theta.randomizer::<effect::Output>(&note.commitment());
        let rk = planner::ActionSigningKey::new(&alpha).derive_action_public();
        (cv, rk)
    }

    /// Different (cv, rk) pairs produce different digests.
    #[test]
    fn distinct_actions_distinct_digests() {
        let mut rng = StdRng::seed_from_u64(201);
        let sk = custody::SpendingKey::from([0x42u8; 32]);

        let (cv_a, rk_a) = make_action_parts(&mut rng, &sk, 1000, Fp::ZERO, Fp::ZERO);
        let (cv_b, rk_b) = make_action_parts(&mut rng, &sk, 700, Fp::ONE, Fp::ONE);

        assert_ne!(
            ActionDigest::new(cv_a, rk_a).unwrap(),
            ActionDigest::new(cv_b, rk_b).unwrap()
        );
    }

    /// Identity cv is rejected.
    #[test]
    fn digest_rejects_identity_cv() {
        use pasta_curves::group::prime::PrimeCurveAffine as _;

        let mut rng = StdRng::seed_from_u64(203);
        let sk = custody::SpendingKey::from([0x42u8; 32]);
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
        let sk = custody::SpendingKey::from([0x42u8; 32]);
        let (cv, _) = make_action_parts(&mut rng, &sk, 500, Fp::ZERO, Fp::ZERO);
        let rk =
            public::ActionVerificationKey(reddsa::VerificationKey::try_from([0u8; 32]).unwrap());
        assert!(matches!(
            ActionDigest::new(cv, rk),
            Err(ActionDigestError::IdentityRk)
        ));
    }
}
