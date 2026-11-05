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

#[test]
#[should_panic(expected = "epoch index above EPOCH_MAX")]
fn new_rejects_an_index_past_the_final_epoch() {
    let _past_the_end = EpochIndex::new(EPOCH_MAX + 1);
}

#[test]
fn final_epoch_ends_at_the_final_block() {
    use crate::constants::BLOCK_MAX;

    assert_eq!(EpochIndex(EPOCH_MAX).last_block(), BlockHeight(BLOCK_MAX));
    assert_eq!(BlockHeight(BLOCK_MAX).epoch(), EpochIndex(EPOCH_MAX));
}

#[test]
fn next_stops_at_the_final_epoch() {
    assert_eq!(
        EpochIndex(EPOCH_MAX - 1).next(),
        Some(EpochIndex(EPOCH_MAX))
    );
    assert_eq!(EpochIndex(EPOCH_MAX).next(), None);
}
