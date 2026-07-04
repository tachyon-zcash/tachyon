//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types and provides accumulator helpers for
//! stamp construction and verification.
//!
//! Step names follow a role grammar:
//!
//! - `Seed`: a base case with no PCD inputs, establishing a header from
//!   witnesses (`MasterSeed`, `AnchorSeed`, `UnspentSeed`, and their
//!   empty-block variants).
//! - `Init`: bootstrap a lineage from existing PCDs (`SpendableInit`).
//! - `Fuse`: compose two headers of the same family (`AnchorFuse`,
//!   `UnspentFuse`, `UnspentEpochFuse`, `EmitterKeysetFuse`).
//! - `Lift`: advance a spendable or stamp forward through the anchor chain, and
//!   nothing else (`SpendableLift`, `StampLift`).
//! - `Bind`: attach a lineage to certified material (`SpendBind`,
//!   `UnspentBind`).
//! - `Stamp`: produce or merge a public stamp header (`OutputStamp`,
//!   `SpendStamp`, `MergeStamp`).
//! - `Step`: certify a committed cipher trace (`KeyExpansionStep`,
//!   `NullifierDerivationStep`).
//!
//! The registration order below groups the derivation chain (indices 0..3),
//! the pool segments (3..11), the spendable lineage (11..13), and the stamp
//! producers (13..18), with `EmitterKeysetFuse` appended at 18; indices are
//! stable identifiers, not a dependency order.

extern crate alloc;

pub mod delegation;
pub mod pool;
pub mod spend;
pub mod spendable;
pub mod stamp;

#[cfg(test)]
mod tests;

use lazy_static::lazy_static;
pub use ragu::Proof;
use ragu::{Application, ApplicationBuilder};

fn make_app() -> Result<Application, ragu::Error> {
    ApplicationBuilder::new()
        .register(delegation::MasterSeed)?
        .register(delegation::KeyExpansionStep)?
        .register(delegation::NullifierDerivationStep)?
        .register(pool::AnchorSeed)?
        .register(pool::EmptyBlockAnchorSeed)?
        .register(pool::AnchorFuse)?
        .register(pool::UnspentSeed)?
        .register(pool::EmptyBlockUnspentSeed)?
        .register(pool::UnspentFuse)?
        .register(pool::UnspentEpochFuse)?
        .register(pool::UnspentBind)?
        .register(spendable::SpendableInit)?
        .register(spendable::SpendableLift)?
        .register(stamp::OutputStamp)?
        .register(spend::SpendBind)?
        .register(stamp::SpendStamp)?
        .register(stamp::MergeStamp)?
        .register(stamp::StampLift)?
        .register(delegation::EmitterKeysetFuse)?
        .finalize()
}

lazy_static! {
    pub(crate) static ref PROOF_SYSTEM: Application = {
        #[expect(
            clippy::expect_used,
            reason = "hardcoded step ordering must register cleanly"
        )]
        make_app().expect("registration of fixed step list must succeed")
    };
}
