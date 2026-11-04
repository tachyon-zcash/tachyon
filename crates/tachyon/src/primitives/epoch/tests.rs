use super::*;
use crate::constants::BLOCK_MAX;

#[test]
fn an_epoch_spans_its_blocks() {
    for index in [0, 1, 96, EPOCH_MAX - 1, EPOCH_MAX] {
        let epoch = EpochIndex::new(index);
        let (first, last) = (epoch.first_block(), epoch.last_block());
        assert_eq!(
            last.0 - first.0,
            EPOCH_SIZE - 1,
            "epoch {index}: its length"
        );
        for offset in [0, 17, EPOCH_SIZE - 1] {
            assert_eq!(
                BlockHeight(first.0 + offset).epoch(),
                epoch,
                "epoch {index}: block {offset} maps back"
            );
        }
        assert!(
            first.is_first_in_epoch() && last.is_last_in_epoch(),
            "epoch {index}: its ends"
        );
        if let Some(next) = epoch.next() {
            assert_eq!(u32::from(next), index + 1, "epoch {index}: its successor");
            assert_eq!(
                next.first_block().prev(),
                Some(last),
                "epoch {index}: the successor starts right after"
            );
        } else {
            assert_eq!(index, EPOCH_MAX, "only the final epoch has no successor");
            assert_eq!(last, BlockHeight(BLOCK_MAX), "the final epoch's last block");
        }
    }
}

#[test]
fn epoch_difference_counts_the_span() {
    assert_eq!(u64::from(EpochIndex(7) - EpochIndex(3)), 4);
    assert_eq!(u64::from(EpochIndex(3) - EpochIndex(3)), 0);
    assert_eq!(
        u64::from(EpochIndex(EPOCH_MAX) - EpochIndex(0)),
        u64::from(EPOCH_MAX)
    );
}

#[test]
#[should_panic(expected = "epoch difference is positive")]
fn epoch_difference_rejects_reversed_operands() {
    let reversed = EpochIndex(3) - EpochIndex(7);
    panic!("reversed operands must not produce a difference, got {reversed:?}");
}

#[test]
#[should_panic(expected = "epoch index above EPOCH_MAX")]
fn new_rejects_an_index_past_the_final_epoch() {
    let past_the_end = EpochIndex::new(EPOCH_MAX + 1);
    panic!("an index above EPOCH_MAX is not an epoch, got {past_the_end:?}");
}
