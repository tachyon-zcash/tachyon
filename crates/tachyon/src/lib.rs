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
//! [`Bundle<S>`](Bundle) is parameterized by stamp state `S: StampState`:
//!
//! - [`Stamped`] — `Bundle<Stamp>`, self-contained with stamp
//! - [`Stripped`] — `Bundle<Stampless>`, stamp stripped, depends on aggregate
//! - `Bundle<Option<Stamp>>` — erased stamp state for mixed contexts
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

/// `todo!` macro: code after a `todo!()` call executes with stub values.
macro_rules! todo {
    ($($args:tt)*) => {
        #[cfg(feature = "std")]
        ::std::eprintln!("TODO: {}", format_args!($($args)*));
    };
}

pub mod action;
pub mod bundle;
pub mod constants;
pub mod entropy;
pub mod keys;
pub mod note;
pub mod stamp;
pub mod value;
pub mod witness;

mod primitives;
#[cfg(feature = "serde")]
mod serde_helpers;

pub use action::{Action, Plan as ActionPlan};
pub use bundle::{Bundle, Plan as BundlePlan, Stamped, Stripped};
pub use note::Note;
pub use primitives::{
    ActionDigest, ActionDigestError, Anchor, Epoch, Tachygram,
    multiset::{self, Multiset},
};
pub use stamp::{BatchValidator, Stamp, proof::Proof};
