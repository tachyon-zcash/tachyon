use core::{iter, ops};

use ff::{Field as _, PrimeField as _};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{EpAffine, Fp, arithmetic::CurveAffine as _};

use crate::{
    Action, action::Plan as ActionPlan, constants::ACTION_DIGEST_PERSONALIZATION, keys::public,
    value,
};

/// Digest a single action's `(cv, rk)` pair via Poseidon.
///
/// The digest may be accumulated via field addition (commutative,
/// order-independent).
///
/// # Panics
///
/// Panics if either point is the identity (which should never happen
/// for action commitments or verification keys).
#[must_use]
fn digest_action(cv: value::Commitment, rk: public::ActionVerificationKey) -> Fp {
    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    let personalization = Fp::from_u128(u128::from_le_bytes(*ACTION_DIGEST_PERSONALIZATION));

    let (cv_x, cv_y) = {
        let point: EpAffine = cv.into();
        #[expect(clippy::expect_used, reason = "specified behavior")]
        let coords = point
            .coordinates()
            .into_option()
            .expect("action value commitment must not be the identity point");
        (*coords.x(), *coords.y())
    };

    let (rk_x, rk_y) = {
        let point: EpAffine = rk.into();
        #[expect(clippy::expect_used, reason = "specified behavior")]
        let coords = point
            .coordinates()
            .into_option()
            .expect("verification key must not be the identity point");
        (*coords.x(), *coords.y())
    };

    Hash::<_, P128Pow5T3, ConstantLength<5>, 3, 2>::init().hash([
        personalization,
        cv_x,
        cv_y,
        rk_x,
        rk_y,
    ])
}

/// Order-independent digest of one or more actions.
///
/// Each action's $(\mathsf{cv}, \mathsf{rk})$ pair is hashed to a field
/// element via Poseidon. Multiple digests combine via field addition
/// (commutative):
///
/// $$\mathsf{action\_acc} = \sum_i H_i$$
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
    #[must_use]
    pub fn new(cv: value::Commitment, rk: public::ActionVerificationKey) -> Self {
        Self(digest_action(cv, rk))
    }
}

impl From<&ActionPlan> for ActionDigest {
    fn from(plan: &ActionPlan) -> Self {
        Self(digest_action(plan.cv(), plan.rk))
    }
}

impl From<&Action> for ActionDigest {
    fn from(action: &Action) -> Self {
        Self(digest_action(action.cv, action.rk))
    }
}

impl From<&[Action]> for ActionDigest {
    fn from(actions: &[Action]) -> Self {
        actions.iter().map(Self::from).sum()
    }
}

impl ops::Add for ActionDigest {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl iter::Sum for ActionDigest {
    /// $\sum_i H_i$ — field addition over all action digests.
    /// Identity element is zero.
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(Fp::ZERO), |acc, digest| acc + digest)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for ActionDigest {
    fn into(self) -> [u8; 32] {
        self.0.to_repr()
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

    /// Digest addition is commutative: A + B == B + A.
    #[test]
    fn digest_commutative() {
        let mut rng = StdRng::seed_from_u64(200);
        let sk = private::SpendingKey::from([0x42u8; 32]);

        let (cv_a, rk_a) = make_action_parts(&mut rng, &sk, 1000, Fp::ZERO, Fp::ZERO);
        let (cv_b, rk_b) = make_action_parts(&mut rng, &sk, 700, Fp::ONE, Fp::ONE);

        let digest_a = ActionDigest::new(cv_a, rk_a);
        let digest_b = ActionDigest::new(cv_b, rk_b);

        assert_eq!(digest_a + digest_b, digest_b + digest_a);
    }

    /// Different (cv, rk) pairs produce different digests.
    #[test]
    fn distinct_actions_distinct_digests() {
        let mut rng = StdRng::seed_from_u64(201);
        let sk = private::SpendingKey::from([0x42u8; 32]);

        let (cv_a, rk_a) = make_action_parts(&mut rng, &sk, 1000, Fp::ZERO, Fp::ZERO);
        let (cv_b, rk_b) = make_action_parts(&mut rng, &sk, 700, Fp::ONE, Fp::ONE);

        assert_ne!(ActionDigest::new(cv_a, rk_a), ActionDigest::new(cv_b, rk_b));
    }
}
