use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;

use super::*;
use crate::{
    entropy::ActionEntropy,
    keys::{private, public},
    note,
    pasta::Fp,
    primitives::{Tachygram, effect},
    value,
};

#[test]
#[should_panic(expected = "cv must not be the identity")]
fn digest_panics_on_identity_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let cm = note::Commitment::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let rk = private::ActionSigningKey::new(
        &ActionEntropy::random::<effect::Output>(rng, cm).randomizer::<effect::Output>(cm),
    )
    .derive_action_public();
    let pair = (Tachygram::random(rng), Tachygram::random(rng));

    let _digest = ActionDigest::new(value::Commitment::default(), rk, pair);
}

#[test]
#[should_panic(expected = "rk must not be the identity")]
fn digest_panics_on_identity_verification_key() {
    let rng = &mut StdRng::seed_from_u64(0);
    let cv = value::Trapdoor::random(rng).commit(value::Positive::try_from(500u64).unwrap());
    let identity_rk =
        public::ActionVerificationKey(reddsa::VerificationKey::try_from([0u8; 32]).unwrap());
    let pair = (Tachygram::random(rng), Tachygram::random(rng));

    let _digest = ActionDigest::new(cv, identity_rk, pair);
}
