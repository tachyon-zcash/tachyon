//! Tachyon's digest functions, organized by hash algorithm.
//!
//! Every protocol-defined hash in the crate is a named pure function in
//! one of these submodules. Domain separators and personalizations live
//! alongside the function that consumes them.

pub(crate) mod blake2b;
pub(crate) mod poseidon;
