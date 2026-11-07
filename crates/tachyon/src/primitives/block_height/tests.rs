use super::*;
use crate::constants::BLOCK_MAX;

#[test]
fn next_stops_at_the_final_block() {
    assert_eq!(
        BlockHeight(BLOCK_MAX - 1).next(),
        Some(BlockHeight(BLOCK_MAX))
    );
    assert_eq!(BlockHeight(BLOCK_MAX).next(), None);
}

#[test]
fn prev_stops_at_the_genesis_block() {
    assert_eq!(BlockHeight(1).prev(), Some(BlockHeight(0)));
    assert_eq!(BlockHeight(0).prev(), None);
}
