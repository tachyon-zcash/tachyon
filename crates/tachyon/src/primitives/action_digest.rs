use derive_more::{Debug, Display, Eq as TotalEq, Error, From, Into, PartialEq};
use pasta_curves::{EpAffine, Fp, arithmetic::CurveAffine as _};

use crate::{digest::poseidon, keys::public, value};

/// Poseidon digest of a single action's $(\mathsf{cv}, \mathsf{rk})$ pair.
///
/// Each action produces one digest, which serves as a root in the
/// accumulator polynomial. Multiple actions are accumulated via
/// polynomial commitment, not on this type. A fee digest
/// $d_\mathsf{fee}$ joins the same action set.
#[derive(Clone, Copy, Debug, From, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct ActionDigest(Fp);

/// Errors from action digest computation.
#[derive(Clone, Copy, Debug, Display, Error)]
pub enum ActionDigestError {
    /// The cv is the identity point, so the digest cannot be computed.
    #[display("cv is the identity point")]
    IdentityCv,
    /// The rk is the identity point, so the digest cannot be computed.
    #[display("rk is the identity point")]
    IdentityRk,
}

impl ActionDigest {
    /// Digest a single action's $(\mathsf{cv}, \mathsf{rk})$ pair.
    ///
    /// # Errors
    ///
    /// Returns [`ActionDigestError`] if either point is the identity, which
    /// has no affine coordinates to absorb.
    pub fn try_new(
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
        Ok(Self(poseidon::action_digest(cv_coords, rk_coords)))
    }
}

#[cfg(test)]
mod tests {
    use rand::{CryptoRng, SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        entropy::ActionEntropy,
        keys::private,
        note::{self, Note},
        nullifier,
        primitives::effect,
        value,
    };

    fn make_action_parts<RNG: CryptoRng>(
        rng: &mut RNG,
        val: u64,
    ) -> (value::Commitment, public::ActionVerificationKey) {
        let sk = private::SpendingKey::random(rng);
        let note = Note {
            pk: sk.derive_payment_key(),
            value: value::Positive::try_from(val).expect("fixture value is within monetary bounds"),
            psi: nullifier::Trapdoor::random(rng),
            rcm: note::CommitmentTrapdoor::random(rng),
        };
        let rcv = value::Trapdoor::random(rng);
        let cv = rcv.commit(note.value);
        let theta = ActionEntropy::random(rng);
        let alpha = theta.randomizer::<effect::Output>(note.commitment());
        let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
        (cv, rk)
    }

    /// Different (cv, rk) pairs produce different digests.
    #[test]
    fn distinct_actions_distinct_digests() {
        let rng = &mut StdRng::seed_from_u64(0);
        let (cv_a, rk_a) = make_action_parts(rng, 1000);
        let (cv_b, rk_b) = make_action_parts(rng, 700);

        assert_ne!(
            ActionDigest::try_new(cv_a, rk_a).expect("fixture points are non-identity"),
            ActionDigest::try_new(cv_b, rk_b).expect("fixture points are non-identity")
        );
    }

    /// Identity cv is rejected.
    #[test]
    fn digest_rejects_identity_cv() {
        let rng = &mut StdRng::seed_from_u64(0);
        let (_, rk) = make_action_parts(rng, 500);
        let cv = value::Commitment::default();
        assert!(matches!(
            ActionDigest::try_new(cv, rk),
            Err(ActionDigestError::IdentityCv)
        ));
    }

    /// Identity rk is rejected.
    #[test]
    fn digest_rejects_identity_rk() {
        let rng = &mut StdRng::seed_from_u64(0);
        let (cv, _) = make_action_parts(rng, 500);
        let rk = public::ActionVerificationKey(
            reddsa::VerificationKey::try_from([0u8; 32])
                .expect("identity encoding is a valid RedPallas verification key"),
        );
        assert!(matches!(
            ActionDigest::try_new(cv, rk),
            Err(ActionDigestError::IdentityRk)
        ));
    }
}
