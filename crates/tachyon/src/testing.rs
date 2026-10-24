//! Property checks for the unit tests.

use core::fmt::Debug;

use proptest::{
    strategy::Strategy,
    test_runner::{Config, TestCaseError, TestRunner},
};

/// Check `property` over `cases` inputs drawn from `strategy`.
///
/// # Panics
///
/// Panics with the shrunk failing input when the property fails.
pub(crate) fn check<S: Strategy<Value: Debug>>(
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
