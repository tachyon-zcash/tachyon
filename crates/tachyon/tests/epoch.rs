//! Tests run at the shipped epoch size.
#![cfg(test)]

use zcash_tachyon::{
    BlockHeight, EpochIndex,
    constants::{BLOCK_MAX, EPOCH_MAX},
};

#[test]
#[should_panic(expected = "epoch index above EPOCH_MAX")]
fn new_rejects_an_index_past_the_final_epoch() {
    let _past_the_end = EpochIndex::new(EPOCH_MAX + 1);
}

#[test]
fn final_epoch_ends_at_the_final_block() {
    assert_eq!(
        EpochIndex::new(EPOCH_MAX).last_block(),
        BlockHeight(BLOCK_MAX)
    );
    assert_eq!(BlockHeight(BLOCK_MAX).epoch(), EpochIndex::new(EPOCH_MAX));
}

#[test]
fn next_stops_at_the_final_epoch() {
    assert_eq!(
        EpochIndex::new(EPOCH_MAX - 1).next(),
        Some(EpochIndex::new(EPOCH_MAX))
    );
    assert_eq!(EpochIndex::new(EPOCH_MAX).next(), None);
}
