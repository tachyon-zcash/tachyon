#![allow(
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::integer_division,
    clippy::panic,
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
