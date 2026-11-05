use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::value;

#[test]
fn distinct_rcm_distinct_commitments() {
    let rng = &mut StdRng::seed_from_u64(0);
    let pk = PaymentKey::random(rng);
    let psi = nullifier::Trapdoor::random(rng);

    let note1 = Note {
        pk,
        value: value::Positive::try_from(100u64).unwrap(),
        psi,
        rcm: CommitmentTrapdoor::random(rng),
    };
    let note2 = Note {
        pk,
        value: value::Positive::try_from(100u64).unwrap(),
        psi,
        rcm: CommitmentTrapdoor::random(rng),
    };

    assert_ne!(note1.commitment(), note2.commitment());
}
