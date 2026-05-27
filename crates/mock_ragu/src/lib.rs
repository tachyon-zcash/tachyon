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
pub use ctx::StepCtx;
pub use error::{Error, Result};
pub use header::{Header, Suffix};
pub use hooks::FrameworkHooks;
pub use polynomial::{Commitment, Polynomial, generators, poly_with_roots};
pub use proof::{Pcd, Proof};
pub use relations::{enforce_poly_concat, enforce_poly_product, enforce_poly_splice};
pub use step::{Index, Step};

pub mod application;
pub mod ctx;
pub mod error;
pub mod header;
pub mod hooks;
pub mod polynomial;
pub mod proof;
pub mod relations;
pub mod step;

#[cfg(test)]
mod tests;
