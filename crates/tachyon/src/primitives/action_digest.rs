use core::{iter, ops};

use pasta_curves::{
    EpAffine,
    arithmetic::CurveExt as _,
    group::{GroupEncoding as _, prime::PrimeCurveAffine as _},
    pallas,
};

use crate::{Action, action::Plan as ActionPlan, keys::public, value};

/// Digest a single action's `(cv, rk)` pair.
///
/// The digest may be accumulated via point addition (commutative,
/// order-independent).
///
/// ## This Is A Placeholder
///
/// Currently uses `pallas::Point::hash_to_curve`. The final implementation
/// should use a Poseidon-based multiset hash.  Poseidon is desired because the
/// Ragu leaf circuit will compute this digest inside the SNARK proof, where
/// hash-to-curve (SWU map) would be prohibitively expensive.
///
/// Only the body of this function will change; the [`ActionDigest`] type, its
/// `Add`/`Sum` impls, serialization, and all call sites remain the same.
#[must_use]
fn digest_action(cv: value::Commitment, rk: public::ActionVerificationKey) -> EpAffine {
    let hasher = pallas::Point::hash_to_curve("just pretend this is poseidon");
    let cv_bytes: [u8; 32] = EpAffine::from(cv).to_bytes();
    let rk_bytes: [u8; 32] = rk.0.into();
    let msg = [cv_bytes, rk_bytes].concat();
    let hash = hasher(&msg);
    hash.into()
}

/// Order-independent digest of one or more actions.
///
/// Each action's $(\mathsf{cv}, \mathsf{rk})$ pair is hashed. Multiple digests
/// combine via point addition (commutative):
///
/// $$\mathsf{action\_acc} = \sum_i P_i$$
///
/// A single action's hash output is a one-element digest; an accumulated sum is
/// a multi-element digest. Both have the same type.
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
///
/// ## Hash function
///
/// Currently uses hash-to-curve as a placeholder. The final
/// implementation will use Poseidon (see `digest_action` for
/// details). The type, traits, and call sites are stable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionDigest(EpAffine);

impl ActionDigest {
    /// Digest a single action's $(\mathsf{cv}, \mathsf{rk})$ pair.
    ///
    /// See `digest_action` for the hash function.
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
        Self((self.0 + rhs.0).into())
    }
}

impl iter::Sum for ActionDigest {
    /// $\sum_i P_i$ — point addition over all action digests.
    /// Identity element is the point at infinity.
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self(EpAffine::identity()), |acc, digest| acc + digest)
    }
}

#[expect(clippy::from_over_into, reason = "restrict conversion")]
impl Into<[u8; 32]> for ActionDigest {
    fn into(self) -> [u8; 32] {
        self.0.to_bytes()
    }
}

impl TryFrom<&[u8; 32]> for ActionDigest {
    type Error = &'static str;

    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        EpAffine::from_bytes(bytes)
            .into_option()
            .ok_or("invalid curve point")
            .map(Self)
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use pasta_curves::{Fp, Fq};
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
        rcm: Fq,
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

        let (cv_a, rk_a) = make_action_parts(&mut rng, &sk, 1000, Fp::ZERO, Fq::ZERO);
        let (cv_b, rk_b) = make_action_parts(&mut rng, &sk, 700, Fp::ONE, Fq::ONE);

        let digest_a = ActionDigest::new(cv_a, rk_a);
        let digest_b = ActionDigest::new(cv_b, rk_b);

        assert_eq!(digest_a + digest_b, digest_b + digest_a);
    }

    /// Different (cv, rk) pairs produce different digests.
    #[test]
    fn distinct_actions_distinct_digests() {
        let mut rng = StdRng::seed_from_u64(201);
        let sk = private::SpendingKey::from([0x42u8; 32]);

        let (cv_a, rk_a) = make_action_parts(&mut rng, &sk, 1000, Fp::ZERO, Fq::ZERO);
        let (cv_b, rk_b) = make_action_parts(&mut rng, &sk, 700, Fp::ONE, Fq::ONE);

        assert_ne!(ActionDigest::new(cv_a, rk_a), ActionDigest::new(cv_b, rk_b),);
    }
}
