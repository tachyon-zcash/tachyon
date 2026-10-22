//! Internal serialization helpers for read/write encoding.

pub(crate) mod compact_size;
mod encoding;

pub(crate) use encoding::*;
