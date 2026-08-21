//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types and provides accumulator helpers for
//! stamp construction and verification.

extern crate alloc;

pub mod delegation;
pub mod output;
pub mod pool;
pub mod spend;
pub mod spendable;
pub mod stamp;
pub mod summary;

#[cfg(test)]
mod tests;

use lazy_static::lazy_static;
pub use ragu::Proof;
use ragu::{Application, ApplicationBuilder};

fn make_app() -> Result<Application, ragu::Error> {
    ApplicationBuilder::new()
        .register(delegation::NfSboxStep)?
        .register(delegation::NfDerive)?
        .register(pool::AnchorSeed)?
        .register(pool::AnchorFuse)?
        .register(pool::UnspentSeed)?
        .register(pool::EndEpochUnspentSeed)?
        .register(pool::UnspentFuse)?
        .register(pool::UnspentBind)?
        .register(spendable::SpendableInit)?
        .register(spendable::SpendableLift)?
        .register(output::OutputBind)?
        .register(stamp::OutputStamp)?
        .register(spend::SpendBind)?
        .register(stamp::SpendStamp)?
        .register(stamp::MergeStamp)?
        .register(stamp::StampLift)?
        .register(delegation::NullifierFuse)?
        .register(summary::SummarySeed)?
        .register(summary::SummaryAdvance)?
        .register(pool::UnspentBatch)?
        .register(pool::UnspentAdvance)?
        .register(pool::UnspentEpochLift)?
        .register(spendable::SpendableBatch)?
        .register(spendable::SpendableAdvance)?
        .register(delegation::NfWrapStep)?
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
