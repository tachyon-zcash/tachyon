//! # tachyon
//!
//! The Tachyon shielded transaction protocol.
//!
//! Tachyon is a scaling solution for Zcash that enables:
//! - **Proof Aggregation**: Multiple Halo proofs aggregated into a single Ragu proof per block
//! - **Delegated Synchronization**: Wallets can outsource sync to untrusted services
//! - **Polynomial Accumulators**: Unified tracking of commitments and nullifiers via tachygrams
//!
//! ## Bundle States
//!
//! [`Bundle<S, V>`](Bundle) uses type parameters to track stamp disposition
//! and value balance type:
//!
//! - [`StampedBundle<V>`] (`Bundle<Stamp, V>`) — self-contained with stamp
//! - [`StrippedBundle<V>`] (`Bundle<Stripped, V>`) — stamp stripped, depends on aggregate
//!
//! ## Block Structure
//!
//! A block contains stamped and stripped bundles. An aggregate is a
//! `(StampedBundle, Vec<StrippedBundle>)` — the stamped bundle's stamp
//! covers both its own actions and those of the stripped bundles.
//!
//!
//! ## Nomenclature
//!
//! All types in the `tachyon` crate, unless otherwise specified, are Tachyon-specific
//! types.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Temporary until we have more of the crate implemented.
#![allow(dead_code)]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod action;
pub mod bundle;
pub mod circuit;
pub mod constants;
pub mod keys;
pub mod note;
pub mod primitives;
pub mod proof;
pub mod stamp;

pub use action::Action;
pub use bundle::{BindingSignature, Bundle, Stamped, Stripped};
pub use keys::{
    Binding, RandomizedVerificationKey, SigningKey, SpendAuth, SpendAuthRandomizer,
    SpendAuthSignature, SpendAuthorizingKey, SpendValidatingKey, VerificationKey,
};
pub use note::{Note, NoteCommitment, Nullifier};
pub use primitives::{Anchor, Epoch, Tachygram};
pub use proof::Proof;
pub use stamp::Stamp;
