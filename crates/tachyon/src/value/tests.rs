use super::*;

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
