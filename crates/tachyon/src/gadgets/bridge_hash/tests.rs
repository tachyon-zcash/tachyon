use alloc::string::ToString as _;

use super::*;

#[test]
fn setup_rejects_an_unexpected_stage_layout() {
    let probe = Pasta::host_generators(parameters::baked()).g()[0];
    let stage = bridge_hash::rx::<_, WalletRank>(probe).unwrap();
    assert!(matches!(
        Layout::pinned(probe, &stage, [16263, 32647]),
        Err(Error::Initialization(reason)) if reason.to_string() == "pinned bridge degrees changed"
    ));
}

#[test]
fn setup_rejects_a_mask_admitting_the_other_rank() {
    let probe = Pasta::host_generators(parameters::baked()).g()[0];
    let aggregator = Layout::pinned(
        probe,
        &bridge_hash::rx::<_, AggregatorRank>(probe).unwrap(),
        [16263, 32647],
    )
    .unwrap();
    // The aggregator stage's own degrees stand in for a degree its mask admits.
    assert!(matches!(
        aggregator.excludes::<AggregatorRank>(aggregator.degrees),
        Err(Error::Initialization(_))
    ));
    aggregator.excludes::<AggregatorRank>([3975, 8071]).unwrap();
}
