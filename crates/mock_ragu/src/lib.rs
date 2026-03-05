//! Mock Ragu PCD proof system.
//!
//! API-level mock of the Ragu Proof-Carrying Data framework for testing
//! the Tachyon protocol before the real Ragu implementation is available.
//!
//! ## Core types (mirroring `ragu_pcd`)
//!
//! - [`Header`] trait: defines data carried by proofs
//! - [`Step`] trait: defines computation nodes in the PCD graph
//! - [`ApplicationBuilder`] / [`Application`]: build and use a PCD application
//! - [`Proof`]: the proof bytes (128 bytes)
//! - [`Pcd`]: proof + header data bundle
//!
//! ## Utilities
//!
//! - [`accumulator`]: XOR-fold mock vector commitments

// Lints that don't apply to a mock crate mirroring an external API.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![expect(clippy::pub_use, reason = "crate public API re-exports")]
#![expect(clippy::module_name_repetitions, reason = "names mirror real ragu API")]
#![expect(clippy::missing_const_for_fn, reason = "mirrors non-const ragu API")]
#![expect(
    clippy::missing_trait_methods,
    reason = "default impls are fine in a mock"
)]

pub use application::{Application, ApplicationBuilder};
pub use error::ValidationError;
pub use header::{Header, Suffix};
pub use proof::{Pcd, Proof};
pub use step::{Index, Step};

pub mod accumulator;
pub mod application;
pub mod error;
pub mod header;
pub mod proof;
pub mod step;
