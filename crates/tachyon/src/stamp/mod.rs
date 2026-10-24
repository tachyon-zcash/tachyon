//! Stamps and anchors.

#![allow(clippy::module_name_repetitions, reason = "intentional names")]

pub mod proof;
mod stamps;

pub use stamps::{
    AggregateId, AggregateIdError, Plan, PointerStamp, ProofStamp, ProveError, StampState, Unproven,
};
