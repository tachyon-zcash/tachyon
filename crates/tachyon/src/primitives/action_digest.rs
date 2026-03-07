use ff::{Field as _, PrimeField as _};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{EpAffine, Fp, arithmetic::CurveAffine as _};

use crate::{
    Action, action::Plan as ActionPlan, constants::ACTION_DIGEST_PERSONALIZATION, keys::public,
    value,
};

/// Digest a single action's `(cv, rk)` pair via Poseidon.
///
/// Returns `Poseidon(domain, cv_x, cv_y, rk_x, rk_y) + 1`.
///
/// The `+1` offset guarantees a nonzero output, preventing product
/// collapse in multiplicative accumulation (a single zero would
/// annihilate the entire accumulator).
///
/// Returns an error if either point is the identity. Adversarial
/// inputs can encode identity points, so callers must handle this.
fn digest_action(
    cv: value::Commitment,
    rk: public::ActionVerificationKey,
) -> Result<Fp, ActionDigestError> {
    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    let personalization = Fp::from_u128(u128::from_le_bytes(*ACTION_DIGEST_PERSONALIZATION));

    let (cv_x, cv_y) = {
        let point: EpAffine = cv.into();
        let coords = point
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::InvalidValueCommitment)?;
        (*coords.x(), *coords.y())
    };

    let (rk_x, rk_y) = {
        let point: EpAffine = rk.into();
        let coords = point
            .coordinates()
            .into_option()
            .ok_or(ActionDigestError::InvalidVerificationKey)?;
        (*coords.x(), *coords.y())
    };

    Ok(
        Hash::<_, P128Pow5T3, ConstantLength<5>, 3, 2>::init().hash([
            personalization,
            cv_x,
            cv_y,
            rk_x,
            rk_y,
        ]) + Fp::ONE,
    )
}

/// Errors from action digest computation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActionDigestError {
    /// Value commitment is the identity point.
    InvalidValueCommitment,
    /// Verification key is the identity point.
    InvalidVerificationKey,
}

/// Order-independent digest of one or more actions.
///
/// Each action's $(\mathsf{cv}, \mathsf{rk})$ pair is hashed to a nonzero
/// field element via Poseidon. Multiple digests combine via field
/// multiplication (commutative, order-independent):
///
/// $$\mathsf{action\_acc} = \prod_i (H_i + 1)$$
///
/// The accumulation scheme is accessed through
/// [`accumulate`](Self::accumulate), [`Default`], and [`FromIterator`]
/// so that the underlying operation can be changed without affecting
/// callers.
///
/// ## Dual role
///
/// The same $\mathsf{action\_acc}$ enters both:
/// - the **bundle commitment** (via BLAKE2b, feeding the transaction sighash
///   that all signatures sign), and
/// - the **PCD stamp header** (the Ragu proof's public output that the verifier
///   reconstructs from visible actions).
///
/// The verifier computes $\mathsf{action\_acc}$ once and uses it for both
/// checks, so a modified action breaks both the sighash and the stamp.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionDigest(Fp);

impl ActionDigest {
    /// Digest a single action's $(\mathsf{cv}, \mathsf{rk})$ pair.
    pub fn new(
        cv: value::Commitment,
        rk: public::ActionVerificationKey,
    ) -> Result<Self, ActionDigestError> {
        digest_action(cv, rk).map(Self)
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
        digest_action(plan.cv(), plan.rk).map(Self)
    }
}

impl TryFrom<&Action> for ActionDigest {
    type Error = ActionDigestError;

    fn try_from(action: &Action) -> Result<Self, Self::Error> {
        digest_action(action.cv, action.rk).map(Self)
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
        Option::from(Fp::from_repr(*bytes))
            .ok_or("invalid field element")
            .map(Self)
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
}
