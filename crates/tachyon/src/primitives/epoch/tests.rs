use alloc::vec::Vec;

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
fn epoch_index_round_trips_as_four_little_endian_bytes() {
    for (epoch, bytes) in [
        (EpochIndex(0), [0; 4]),
        (EpochIndex(0x0102), [0x02, 0x01, 0, 0]),
        (EpochIndex(EPOCH_MAX), EPOCH_MAX.to_le_bytes()),
    ] {
        let mut written = Vec::new();
        epoch.write(&mut written).unwrap();
        assert_eq!(written, bytes);
        assert_eq!(EpochIndex::read(written.as_slice()).unwrap(), epoch);
    }
}

#[test]
fn epoch_index_read_rejects_an_index_past_the_final_epoch() {
    EpochIndex::read((EPOCH_MAX + 1).to_le_bytes().as_slice()).unwrap_err();
    EpochIndex::read(u32::MAX.to_le_bytes().as_slice()).unwrap_err();
}
