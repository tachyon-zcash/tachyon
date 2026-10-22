//! Polynomial encodings of collections.

pub(crate) mod indexed_multiset;
pub(crate) mod multiset;
mod polynomial;
pub(crate) mod qr;

pub(crate) use polynomial::{interpolate, poly_mul};
