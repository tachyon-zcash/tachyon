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
//! [`Bundle<V>`](Bundle) uses an `Option<Stamp>` to track stamp disposition:
//!
//! - `Bundle<V>` with `stamp: Some(Stamp)` — self-contained with stamp
//! - `Bundle<V>` with `stamp: None` — stamp stripped, depends on aggregate
//!
//! ## Block Structure
//!
//! A block contains stamped and stripped bundles. An aggregate contains
//! stamped bundles whose stamps cover both their own actions and those 
//! of stripped bundles.
//!
//!
//! ## Nomenclature
//!
//! All types in the `tachyon` crate, unless otherwise specified, are
//! Tachyon-specific types.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::pub_use, reason = "exporting items for consumers")]

/// `todo!` macro: code after a `todo!()` call executes with stub values.
macro_rules! todo {
    ($($args:tt)*) => {
        println!("TODO: {}", $($args)*);
    };
}

pub mod action;
pub mod bundle;
pub mod constants;
pub mod custody;
pub mod keys;
pub mod note;
pub mod proof;
pub mod stamp;
pub mod value;
pub mod witness;

mod primitives;

pub use action::Action;
pub use bundle::Bundle;
pub use note::Note;
pub use primitives::{Anchor, Epoch, Tachygram};
pub use proof::Proof;
pub use stamp::Stamp;
