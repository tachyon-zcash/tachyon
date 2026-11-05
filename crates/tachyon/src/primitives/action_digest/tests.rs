use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    entropy::ActionEntropy,
    keys::private,
    note::{self, Note},
    nullifier,
    primitives::effect,
    value,
};

#[test]
fn distinct_actions_distinct_digests() {
    let rng = &mut StdRng::seed_from_u64(0);
    let [(cv_a, rk_a), (cv_b, rk_b)] = [1000, 700].map(|val| {
        let sk = private::SpendingKey::random(rng);
        let note = Note {
            pk: sk.derive_payment_key(),
            value: value::Positive::try_from(val).unwrap(),
            psi: nullifier::Trapdoor::random(rng),
            rcm: note::CommitmentTrapdoor::random(rng),
        };
        let cv = value::Trapdoor::random(rng).commit(note.value);
        let alpha = ActionEntropy::random(rng).randomizer::<effect::Output>(note.commitment());
        (
            cv,
            private::ActionSigningKey::new(&alpha).derive_action_public(),
        )
    });

    assert_ne!(
        ActionDigest::new(cv_a, rk_a).unwrap(),
        ActionDigest::new(cv_b, rk_b).unwrap()
    );
}

#[test]
fn digest_rejects_identity_cv() {
    let rng = &mut StdRng::seed_from_u64(0);
    let note = Note {
        pk: private::SpendingKey::random(rng).derive_payment_key(),
        value: value::Positive::try_from(500u64).unwrap(),
        psi: nullifier::Trapdoor::random(rng),
        rcm: note::CommitmentTrapdoor::random(rng),
    };
    let alpha = ActionEntropy::random(rng).randomizer::<effect::Output>(note.commitment());
    let rk = private::ActionSigningKey::new(&alpha).derive_action_public();
    let Err(ActionDigestError::IdentityCv) = ActionDigest::new(value::Commitment::default(), rk)
    else {
        panic!();
    };
}

#[test]
fn digest_rejects_identity_rk() {
    let rng = &mut StdRng::seed_from_u64(0);
    let cv = value::Trapdoor::random(rng).commit(value::Positive::try_from(500u64).unwrap());
    let rk = public::ActionVerificationKey(reddsa::VerificationKey::try_from([0u8; 32]).unwrap());
    let Err(ActionDigestError::IdentityRk) = ActionDigest::new(cv, rk) else {
        panic!();
    };
}
