//! Mock PCD header — succinct representation of computation state.
//!
//! This is the mock equivalent of `ragu_pcd::Header`. Instead of encoding
//! data into circuit gadgets via a `Driver`, the mock header encodes data
//! to bytes for BLAKE2b binding verification.

extern crate alloc;

use alloc::vec::Vec;

/// Unique suffix distinguishing [`Header`] types.
///
/// Mirrors `ragu_pcd::header::Suffix`. Each header implementation must
/// use a distinct suffix so the proof system can distinguish them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Suffix(usize);

impl Suffix {
    /// Creates a new application-defined header suffix.
    #[must_use]
    pub const fn new(value: usize) -> Self {
        Self(value)
    }
}

/// A PCD header defining what data is carried by proofs.
///
/// Mirrors `ragu_pcd::Header`. Implementors define the data type and how
/// to encode it to bytes. In real Ragu, headers encode data into circuit
/// gadgets via a `Driver`; in the mock, they serialize to bytes for
/// BLAKE2b hashing.
///
/// The unit type `()` implements this trait as the trivial header
/// (carries no data), used as `Left`/`Right` for seed steps.
pub trait Header: Send + Sync + 'static {
    /// Unique suffix for this header type.
    const SUFFIX: Suffix;

    /// The data this header carries.
    type Data<'source>: Send + Clone;

    /// Encode header data to bytes for mock binding verification.
    fn encode(data: &Self::Data<'_>) -> Vec<u8>;
}

/// Trivial header that encodes no data.
///
/// Used as `Left`/`Right` for seed steps (no prior proofs).
impl Header for () {
    type Data<'source> = ();

    const SUFFIX: Suffix = Suffix(0);

    fn encode(_data: &()) -> Vec<u8> {
        Vec::new()
    }
}
