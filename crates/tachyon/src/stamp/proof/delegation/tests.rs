use alloc::string::ToString as _;

use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    keys::{SpendValidatingKey, private::SpendingKey},
    reddsa,
    stamp::proof::PROOF_SYSTEM,
};

#[test]
fn note_seed_rejects_an_identity_authorizing_key_at_point_allocation() {
    let rng = &mut StdRng::seed_from_u64(0);
    let supplied = (
        value::Positive::try_from(500).unwrap(),
        nullifier::Trapdoor::random(rng),
        note::CommitmentTrapdoor::from(Fp::ONE),
        SpendingKey::random(rng).derive_proof_private(),
    );
    let (control, ()) = PROOF_SYSTEM.seed(rng, NoteSeed, supplied).unwrap();
    assert!(PROOF_SYSTEM.verify(&control, &mut *rng).unwrap());
    let mut bad = supplied;
    bad.3.ak = SpendValidatingKey(reddsa::VerificationKey::try_from([0u8; 32]).unwrap());
    assert!(matches!(
        PROOF_SYSTEM.seed(rng, NoteSeed, bad),
        Err(ragu_core::Error::InvalidWitness(message)) if message.to_string() == "point at infinity cannot be witnessed"
    ));
}
