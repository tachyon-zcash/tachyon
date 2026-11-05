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
