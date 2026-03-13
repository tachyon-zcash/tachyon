//! Mock PCD header — mirrors `ragu_pcd::Header`.

use alloc::vec::Vec;

/// Mirrors `ragu_pcd::header::Suffix`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Suffix(usize);

impl Suffix {
    #[must_use]
    pub const fn new(value: usize) -> Self {
        Self(value)
    }
}

/// Mirrors `ragu_pcd::Header`.
pub trait Header: Send + Sync + 'static {
    const SUFFIX: Suffix;
    type Data<'source>: Send + Clone;
    fn encode(data: &Self::Data<'_>) -> Vec<u8>;
}

/// Trivial header for seed steps.
impl Header for () {
    type Data<'source> = ();

    const SUFFIX: Suffix = Suffix(0);

    fn encode(_data: &()) -> Vec<u8> {
        Vec::new()
    }
}
