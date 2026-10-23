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
        Ok(Self(poseidon::action_digest(cv_coords, rk_coords)))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::{CryptoRng, SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{
        constants::MAX_MONEY,
        entropy::ActionEntropy,
        keys::private,
        note::{self, Note},
        nullifier,
        primitives::effect,
        testing::check,
        value,
    };

    fn make_action_parts<RNG: CryptoRng>(
        rng: &mut RNG,
        val: u64,
    ) -> (value::Commitment, public::ActionVerificationKey) {
        let sk = private::SpendingKey::random(rng);
        let note = Note {
            pk: sk.derive_payment_key(),
            value: value::Positive::try_from(val).unwrap(),
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

    /// The digest binds both halves of the action: swapping in another cv or
    /// another rk gives another digest. Either half at the identity has no
    /// coordinates to absorb.
    #[test]
    fn the_digest_binds_cv_and_rk() {
        let strategy = (any::<u64>(), 0..=MAX_MONEY, 0..=MAX_MONEY);
        check(256, strategy, |(seed, amount, other_amount)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let (cv, rk) = make_action_parts(rng, amount);
            let (other_cv, other_rk) = make_action_parts(rng, other_amount);
            let digest = ActionDigest::new(cv, rk).unwrap();
            prop_assert_ne!(digest, ActionDigest::new(other_cv, rk).unwrap());
            prop_assert_ne!(digest, ActionDigest::new(cv, other_rk).unwrap());

            let identity_cv = value::Commitment::default();
            let Err(ActionDigestError::IdentityCv) = ActionDigest::new(identity_cv, rk) else {
                panic!("an identity cv must be refused");
            };
            let identity_rk = public::ActionVerificationKey(
                reddsa::VerificationKey::try_from([0u8; 32]).unwrap(),
            );
            let Err(ActionDigestError::IdentityRk) = ActionDigest::new(cv, identity_rk) else {
                panic!("an identity rk must be refused");
            };
            Ok(())
        });
    }
}
