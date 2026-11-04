use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    constants::MAX_MONEY,
    entropy::ActionEntropy,
    keys::private,
    note::{self, Note},
    nullifier,
    primitives::effect,
    value,
};

#[test]
fn the_digest_binds_cv_and_rk() {
    let rng = &mut StdRng::seed_from_u64(0);
    let identity_cv = value::Commitment::default();
    let identity_rk =
        public::ActionVerificationKey(reddsa::VerificationKey::try_from([0u8; 32]).unwrap());
    for (amount, other_amount) in [(0, MAX_MONEY), (1000, 1000)] {
        let [(cv, rk), (other_cv, other_rk)] = [amount, other_amount].map(|val| {
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
        });
        let digest = ActionDigest::new(cv, rk).unwrap();
        assert_ne!(
            digest,
            ActionDigest::new(other_cv, rk).unwrap(),
            "values {amount} and {other_amount}: another cv"
        );
        assert_ne!(
            digest,
            ActionDigest::new(cv, other_rk).unwrap(),
            "values {amount} and {other_amount}: another rk"
        );

        let Err(ActionDigestError::IdentityCv) = ActionDigest::new(identity_cv, rk) else {
            panic!("value {amount}: an identity cv must be refused");
        };
        let Err(ActionDigestError::IdentityRk) = ActionDigest::new(cv, identity_rk) else {
            panic!("value {amount}: an identity rk must be refused");
        };
    }
}
