//! Mock Ragu PCD proof system — API-level mock of `ragu_pcd`.
// Lints that don't apply to a mock crate mirroring an external API.
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![expect(clippy::pub_use, reason = "crate public API re-exports")]
#![expect(clippy::module_name_repetitions, reason = "names mirror real ragu API")]
#![expect(clippy::missing_const_for_fn, reason = "mirrors non-const ragu API")]
#![expect(
    clippy::missing_trait_methods,
    reason = "default impls are fine in a mock"
)]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub use application::{Application, ApplicationBuilder};
pub use error::{Error, Result};
pub use generators::VESTA_GENERATORS;
pub use header::{Header, Suffix};
pub use proof::{Pcd, Proof};
pub use step::{Index, Step};

pub mod application;
pub mod error;
pub mod generators;
pub mod header;
pub mod proof;
pub mod step;

#[cfg(test)]
mod tests;
