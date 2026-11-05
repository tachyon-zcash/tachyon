use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{constants::MAX_MONEY, value};

#[test]
fn positive_value_accepts_max() {
    value::Positive::try_from(MAX_MONEY).unwrap();
}

#[test]
fn positive_value_rejects_over_max() {
    assert_eq!(
        value::Positive::try_from(MAX_MONEY + 1),
        Err(value::OutOfRange)
    );
}

#[test]
fn positive_value_accepts_zero() {
    value::Positive::try_from(0u64).unwrap();
}

#[test]
fn positive_value_rejects_negative() {
    assert_eq!(value::Positive::try_from(-1i64), Err(value::OutOfRange));
}

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
