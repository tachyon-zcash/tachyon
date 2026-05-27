//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types and provides accumulator helpers for
//! stamp construction and verification.

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
        .register(delegation::NfMasterSeed)?
        .register(delegation::NfPrefixStep)?
        .register(delegation::NullifierStep)?
        .register(delegation::NullifierFuse)?
        .register(pool::AnchorSeed)?
        .register(pool::EmptyBlockSeed)?
        .register(pool::AnchorFuse)?
        .register(pool::UnspentSeed)?
        .register(pool::EmptyBlockUnspentSeed)?
        .register(pool::UnspentFuse)?
        .register(pool::UnspentEpochFuse)?
        .register(pool::VerifyUnspent)?
        .register(spendable::SpendableInit)?
        .register(spendable::SpendableLift)?
        .register(stamp::OutputStamp)?
        .register(spend::SpendBind)?
        .register(stamp::SpendStamp)?
        .register(stamp::MergeStamp)?
        .register(stamp::StampLift)?
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
