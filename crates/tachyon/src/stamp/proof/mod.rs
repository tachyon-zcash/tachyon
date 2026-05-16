//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types and provides accumulator helpers for
//! stamp construction and verification.

extern crate alloc;

pub mod delegation;
pub mod spend;
pub mod spendable;
pub mod stamp;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use delegation::{
    DelegateNfPrefixStep, DelegateNullifierStep, DelegationStep, NfMasterSeed, NfMasterStep,
    NfPrefixStep, NullifierStep,
};
use lazy_static::lazy_static;
pub use mock_ragu::Proof;
use mock_ragu::{Application, ApplicationBuilder};
use spend::SpendBind;
use spendable::{SpendableEpochLift, SpendableInit, SpendableLift, SpendableRollover};
use stamp::{MergeStamp, OutputStamp, SpendStamp, StampLift};

use crate::{
    action::Action,
    primitives::{ActionAcc, ActionDigest, ActionDigestError},
};

/// Build the action accumulator polynomial from the public actions list.
pub fn compute_action_acc(actions: &[Action]) -> Result<ActionAcc, ActionDigestError> {
    let digests: Vec<ActionDigest> = actions
        .iter()
        .map(ActionDigest::try_from)
        .collect::<Result<_, ActionDigestError>>()?;
    Ok(ActionAcc::from(&*digests))
}

lazy_static! {
    pub(crate) static ref PROOF_SYSTEM: Application = {
        #[expect(clippy::expect_used, reason = "mock registration is infallible")]
        ApplicationBuilder::new()
            .register(NfMasterSeed)
            .expect("register NfMasterSeed")
            .register(NfMasterStep)
            .expect("register NfMasterStep")
            .register(OutputStamp)
            .expect("register OutputStamp")
            .register(NfPrefixStep)
            .expect("register NfPrefixStep")
            .register(NullifierStep)
            .expect("register NullifierStep")
            .register(DelegateNullifierStep)
            .expect("register DelegateNullifierStep")
            .register(SpendBind)
            .expect("register SpendBind")
            .register(SpendableInit)
            .expect("register SpendableInit")
            .register(SpendableRollover)
            .expect("register SpendableRollover")
            .register(SpendableLift)
            .expect("register SpendableLift")
            .register(SpendableEpochLift)
            .expect("register SpendableEpochLift")
            .register(SpendStamp)
            .expect("register SpendStamp")
            .register(MergeStamp)
            .expect("register MergeStamp")
            .register(StampLift)
            .expect("register StampLift")
            .register(DelegationStep)
            .expect("register DelegationStep")
            .register(DelegateNfPrefixStep)
            .expect("register DelegateNfPrefixStep")
            .finalize()
            .expect("finalize")
    };
}
