use core::assert_matches;

use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;

use super::*;
use crate::{entropy::ActionEntropy, keys::private, note, pasta::Fp, primitives::effect, value};

#[test]
fn digest_rejects_identity_points() {
    let rng = &mut StdRng::seed_from_u64(0);
    let cv = value::Trapdoor::random(rng).commit(value::Positive::try_from(500u64).unwrap());
    let cm = note::Commitment::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let rk = private::ActionSigningKey::new(
        &ActionEntropy::random(rng).randomizer::<effect::Output>(cm),
    )
    .derive_action_public();
    let identity_rk =
        public::ActionVerificationKey(reddsa::VerificationKey::try_from([0u8; 32]).unwrap());

    assert_matches!(
        ActionDigest::new(value::Commitment::default(), rk),
        Err(ActionDigestError::IdentityCv)
    );
    assert_matches!(
        ActionDigest::new(cv, identity_rk),
        Err(ActionDigestError::IdentityRk)
    );
}
