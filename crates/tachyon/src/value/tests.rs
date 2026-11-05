use rand::{SeedableRng as _, rngs::StdRng};

use super::*;

#[test]
fn balance_zero_is_identity() {
    assert_eq!(Trapdoor::ZERO.commit(Balance::ZERO), Commitment::default());
}

#[test]
fn commit_homomorphic_binding_property() {
    let rng = &mut StdRng::seed_from_u64(0);
    let rcv_a = Trapdoor::random(rng);
    let cv_a = rcv_a.commit(Balance::try_from(100).unwrap());
    let rcv_b = Trapdoor::random(rng);
    let cv_b = rcv_b.commit(Balance::try_from(200).unwrap());

    let remainder = cv_a + cv_b - Trapdoor::ZERO.commit(Balance::try_from(300).unwrap());

    let rcv_sum: Fq = Into::<Fq>::into(rcv_a) + Into::<Fq>::into(rcv_b);

    assert_eq!(remainder, ValueCommitment(*VALUE_COMMIT_R * rcv_sum));
}

#[test]
fn debug_value_trapdoor_redacts_scalar() {
    let rcv = ValueTrapdoor(Fq::from(0xFACEu64));
    assert_eq!(alloc::format!("{rcv:?}"), "ValueTrapdoor(..)");
}

#[test]
fn positive_spans_zero_to_max_money() {
    for (input, accepted) in [
        (Positive::try_from(0u64), true),
        (Positive::try_from(MAX_MONEY), true),
        (Positive::try_from(MAX_MONEY + 1), false),
        (Positive::try_from(-1i64), false),
    ] {
        assert_eq!(input.is_ok(), accepted);
    }
}
