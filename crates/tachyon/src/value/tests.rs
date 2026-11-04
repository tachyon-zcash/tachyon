use rand::{SeedableRng as _, rngs::StdRng};

use super::*;

const MAX: i64 = MAX_MONEY.cast_signed();

#[test]
fn a_value_holds_exactly_its_range() {
    for (value, positive, negative, balance) in [
        (-MAX - 1, false, false, false),
        (-MAX, false, true, true),
        (-1, false, true, true),
        (0, true, true, true),
        (1, true, false, true),
        (MAX, true, false, true),
        (MAX + 1, false, false, false),
    ] {
        assert_eq!(Positive::try_from(value).is_ok(), positive, "{value}");
        assert_eq!(Negative::try_from(value).is_ok(), negative, "{value}");
        assert_eq!(Balance::try_from(value).is_ok(), balance, "{value}");
        assert_eq!(
            Balance::try_from(i128::from(value)).is_ok(),
            balance,
            "{value} as i128"
        );
    }
    assert_eq!(u64::from(Positive::try_from(MAX_MONEY).unwrap()), MAX_MONEY);
    assert_eq!(Positive::try_from(MAX_MONEY + 1), Err(OutOfRange));
    assert_eq!(Positive::try_from(u64::MAX), Err(OutOfRange));
    assert_eq!(Balance::try_from(i128::MAX), Err(OutOfRange));
    assert_eq!(
        Balance::try_from(-1i32).unwrap(),
        -Balance::try_from(1).unwrap()
    );
}

#[test]
fn negation_mirrors_the_range() {
    assert_eq!(-Positive::MAX, Negative::MIN);
    assert_eq!(-Negative::MIN, Positive::MAX);
    assert_eq!(-Balance::MAX, Balance::MIN);
    assert_eq!(Balance::from(Negative::MIN), Balance::MIN);
    assert_eq!(Balance::from(Positive::MAX), Balance::MAX);
    assert_eq!(i128::from(Balance::MIN), -i128::from(MAX));
    assert_eq!(Fq::from(Balance::MIN), -Fq::from(MAX_MONEY));
    assert_eq!(Fq::from(Balance::ZERO), Fq::ZERO);
}

#[test]
fn commitments_are_homomorphic() {
    assert_eq!(Trapdoor::ZERO.commit(Balance::ZERO), Commitment::default());

    let rng = &mut StdRng::seed_from_u64(0);
    let (rcv_a, rcv_b) = (Trapdoor::random(rng), Trapdoor::random(rng));
    let cv_a = rcv_a.commit(Balance::try_from(-100).unwrap());
    let cv_b = rcv_b.commit(Positive::try_from(300u64).unwrap());
    let remainder = cv_a + cv_b - Trapdoor::ZERO.commit(Balance::try_from(200).unwrap());
    let rcv_sum = Fq::from(rcv_a) + Fq::from(rcv_b);
    assert_eq!(remainder, ValueCommitment(*VALUE_COMMIT_R * rcv_sum));
}

#[test]
fn debug_redacts_trapdoors_and_commitments() {
    let rcv = Trapdoor::random(&mut StdRng::seed_from_u64(0));
    let cv = rcv.commit(Positive::try_from(1000u64).unwrap());
    assert_eq!(alloc::format!("{rcv:?}"), "ValueTrapdoor(..)");
    assert_eq!(alloc::format!("{cv:?}"), "ValueCommitment(..)");
}
