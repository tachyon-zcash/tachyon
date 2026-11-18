//! Stamps and anchors.

pub mod proof;
mod stamps;

pub use stamps::{
    Compressed, Plan, Proof, ProofStamp, ProveError, StampState, StrippedStamp, Uncompressed,
};
