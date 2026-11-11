use super::*;

#[test]
fn epoch_difference_counts_the_span() {
    assert_eq!(u64::from(EpochIndex(7) - EpochIndex(3)), 4);
    assert_eq!(u64::from(EpochIndex(3) - EpochIndex(3)), 0);
}

#[test]
#[should_panic(expected = "epoch difference is positive")]
fn epoch_difference_rejects_reversed_operands() {
    let _: EpochDiff = EpochIndex(3) - EpochIndex(7);
}
