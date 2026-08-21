//! # tachyon
//!
//! The Tachyon shielded transaction protocol.

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
pub mod nullifier;
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
pub use bundle::{
    Bundle, LiftError, Plan as BundlePlan, SignatureError, TachyonBundle, VerificationError,
    VerifyCoverageError, VerifyPointersError, VerifyProofError,
};
pub use note::Note;
pub use primitives::*;
pub use serialization::compactsize::{CompactSize, CompactSizeError};
pub use stamp::{AggregateIdError, Plan as StampPlan, PointerStamp, ProofStamp, Unproven};
