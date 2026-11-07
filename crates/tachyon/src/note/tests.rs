use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::value;

#[test]
fn distinct_rcm_distinct_commitments() {
    let rng = &mut StdRng::seed_from_u64(0);
    let note = Note {
        pk: PaymentKey::random(rng),
        value: value::Positive::try_from(100u64).unwrap(),
        psi: nullifier::Trapdoor::random(rng),
        rcm: CommitmentTrapdoor::random(rng),
    };
    let other = Note {
        rcm: CommitmentTrapdoor::random(rng),
        ..note
    };

    assert_ne!(note.commitment(), other.commitment());
}
