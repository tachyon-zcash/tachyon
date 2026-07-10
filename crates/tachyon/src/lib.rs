//! # tachyon
//!
//! The Tachyon shielded transaction protocol.
//!
//! Tachyon is a scaling solution for Zcash that enables:
//! - **Proof Aggregation**: Multiple Halo proofs aggregated into a single Ragu
//!   proof per block
//! - **Delegated Synchronization**: Wallets can outsource sync to untrusted
//!   services
//! - **Polynomial Accumulators**: Unified tracking of commitments and
//!   nullifiers via tachygrams
//!
//! ## Bundle States
//!
//! [`Bundle<S>`](Bundle) is parameterized by bundle state `S: BundleState`:
//!
//! - `Bundle<Unproven>` — actions signed but no proof yet
//! - `Bundle<ProofStamp>` — aggregate or self-contained, carries a
//!   [`ProofStamp`]
//! - `Bundle<PointerStamp>` — proof stamp replaced by the covering aggregate's
//!   [`PointerStamp`]
//! - [`TachyonBundle`] — enum of either wire form for mixed contexts
//!
//! ## Block Structure
//!
//! A block may contain stamped and stripped bundles. A stamped bundle's stamp
//! covers its own actions and those of associated stripped bundles.
//!
//! TODO: Block layout is not yet finalized, but provisionally: all adjuncts
//! should immediately follow the aggregate.
//!
//! ## Nomenclature
//!
//! All types in the `tachyon` crate, unless otherwise specified, are
//! Tachyon-specific types.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::pub_use, reason = "exporting items for consumers")]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod action;
pub mod bundle;
pub mod constants;
pub mod entropy;
pub mod keys;
pub mod note;
pub mod reddsa;
pub mod stamp;
pub mod value;
pub mod witness;

mod digest;
mod primitives;
mod relations;
mod serialization;

#[cfg(test)]
pub(crate) mod fixtures;

pub use action::{Action, Plan as ActionPlan};
pub use bundle::{Bundle, Plan as BundlePlan, TachyonBundle};
pub use note::Note;
pub use primitives::*;
pub use stamp::{PointerStamp, ProofStamp, Unproven};
