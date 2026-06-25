//! Tachyon's digest and cipher functions, organized by algorithm.
//!
//! Every protocol-defined hash or keyed primitive in the crate is a named
//! pure function in one of these submodules. Domain separators and
//! personalizations live alongside the function that consumes them.

pub(crate) mod blake2b;
pub(crate) mod mimc;
pub(crate) mod poseidon;
