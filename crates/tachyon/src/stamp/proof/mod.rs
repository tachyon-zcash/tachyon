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
pub mod unspent;

#[cfg(test)]
mod tests;

use lazy_static::lazy_static;
pub use mock_ragu::Proof;
use mock_ragu::{Application, ApplicationBuilder};

fn make_app() -> Result<Application, mock_ragu::Error> {
    ApplicationBuilder::new()
        .register(delegation::NfMasterSeed)?
        .register(delegation::NfMasterStep)?
        .register(delegation::NfPrefixStep)?
        .register(delegation::NullifierStep)?
        .register(delegation::DelegationStep)?
        .register(delegation::DelegateNfPrefixStep)?
        .register(delegation::DelegateNullifierStep)?
        .register(pool::InclusionShardFuse)?
        .register(pool::InclusionComplementSeed)?
        .register(pool::InclusionComplementStep)?
        .register(pool::ExclusionShardSeed)?
        .register(pool::ExclusionShardFuse)?
        .register(pool::AnchorSpanSeed)?
        .register(pool::AnchorSpanStep)?
        .register(pool::AnchorSpanFuse)?
        .register(unspent::EmptyBlockUnspentSeed)?
        .register(unspent::UnspentInit)?
        .register(unspent::UnspentFuse)?
        .register(spendable::SpendableInit)?
        .register(spendable::SpendableLift)?
        .register(spendable::RolloverFuse)?
        .register(spendable::DelegateRolloverFuse)?
        .register(spendable::SpendableRollover)?
        .register(spendable::SpendableEpochLift)?
        .register(stamp::OutputStamp)?
        .register(spend::SpendBind)?
        .register(stamp::SpendStamp)?
        .register(stamp::MergeStamp)?
        .register(stamp::StampLift)?
        .finalize()
}

lazy_static! {
    pub(crate) static ref PROOF_SYSTEM: Application = {
        #[expect(clippy::expect_used, reason = "mock registration is infallible")]
        make_app().expect("should work")
    };
}
