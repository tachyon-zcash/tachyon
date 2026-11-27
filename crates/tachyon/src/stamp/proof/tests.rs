use ragu::{
    circuits::polynomials,
    pasta::Pasta,
    pcd::profile::{Profiled, Standard},
};

use super::register_steps;
use crate::pasta;

#[test]
fn steps_register_at_aggregator_rank() {
    register_steps::<Profiled<Pasta, Standard>, polynomials::AggregatorRank>()
        .unwrap()
        .finalize(pasta::baked())
        .unwrap();
}
