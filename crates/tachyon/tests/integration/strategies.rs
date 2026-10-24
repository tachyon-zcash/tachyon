//! Proptest strategies and the small helpers every property shares.
//!
//! Field elements, keys and notes come from a `StdRng` seeded by a generated
//! `u64`; the structural inputs (counts, values, epochs) are generated
//! directly, so they shrink.

extern crate alloc;

use alloc::{
    string::{String, ToString as _},
    vec::Vec,
};
use core::{fmt::Debug, iter};

use ff::Field as _;
use pasta_curves::Fp;
use proptest::{
    prelude::*,
    test_runner::{Config, TestCaseError, TestRunner},
};
use rand_core::CryptoRng;
use zcash_tachyon::{EpochIndex, Tachygram, constants::EPOCH_MAX};

/// Check `property` over `cases` inputs drawn from `strategy`.
///
/// # Panics
///
/// Panics with the shrunk failing input when the property fails.
pub fn check<S: Strategy<Value: Debug>>(
    cases: u32,
    strategy: S,
    property: impl Fn(S::Value) -> Result<(), TestCaseError>,
) {
    let mut runner = TestRunner::new(Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    });
    if let Err(err) = runner.run(&strategy, property) {
        panic!("{err}");
    }
}

/// Any epoch, weighted towards the first and the final.
pub fn epoch() -> impl Strategy<Value = EpochIndex> {
    prop_oneof![0..=EPOCH_MAX, Just(0), Just(EPOCH_MAX)].prop_map(EpochIndex::new)
}

/// `count` random tachygrams.
pub fn tachygrams<RNG: CryptoRng>(rng: &mut RNG, count: usize) -> Vec<Tachygram> {
    iter::repeat_with(|| Tachygram::from(Fp::random(&mut *rng)))
        .take(count)
        .collect()
}

/// The message of an `InvalidWitness` error.
///
/// # Panics
///
/// Panics on any other error.
pub fn invalid_witness(err: ragu_core::Error) -> String {
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    inner.to_string()
}

/// Assert each step result failed with its expected `InvalidWitness`
/// message, naming the case that did not.
///
/// # Panics
///
/// Panics when a case succeeded or failed otherwise.
pub fn assert_rejections<const N: usize>(cases: [(&str, ragu_core::Result<()>, &str); N]) {
    for (label, result, expected) in cases {
        let Err(err) = result else {
            panic!("{label}: the step accepted the corruption");
        };
        assert_eq!(invalid_witness(err), expected, "{label}");
    }
}
