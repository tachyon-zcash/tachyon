use ragu::{
    circuits::polynomials,
    pasta::Pasta,
    pcd::profile::{Profiled, Standard},
};
use ragu_pcd::pasta::baked_aggregator;

use super::register_steps;

#[test]
fn steps_register_at_aggregator_rank() {
    register_steps::<Profiled<Pasta, Standard>, polynomials::AggregatorRank>()
        .unwrap()
        .finalize(baked_aggregator())
        .unwrap();
}
