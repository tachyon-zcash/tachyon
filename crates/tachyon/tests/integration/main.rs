#![allow(
    clippy::arithmetic_side_effects,
    clippy::integer_division,
    reason = "bounded integration fixture sizes and deliberate floor splits do not handle untrusted inputs"
)]
#![allow(
    clippy::as_conversions,
    reason = "fixed derivation widths and rates in integration fixtures fit u32"
)]
#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    missing_docs,
    unreachable_pub,
    reason = "test code"
)]

#[cfg(test)]
mod bundle;
#[cfg(test)]
mod evidence;
#[cfg(test)]
mod fee;
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
#[cfg(test)]
mod unmerge;
