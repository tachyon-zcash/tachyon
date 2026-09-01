#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::integer_division_remainder_used,
    clippy::integer_division,
    clippy::missing_assert_message,
    clippy::must_use_candidate,
    clippy::panic,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    missing_debug_implementations,
    missing_docs,
    unreachable_pub,
    reason = "test code"
)]

//! Integration tests, exercising the crate through its public surface.

#[cfg(test)]
mod bundle;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod proof;
#[cfg(test)]
mod qr;
#[cfg(test)]
mod stamp;
#[cfg(test)]
mod summary;
