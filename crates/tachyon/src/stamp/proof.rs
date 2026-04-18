//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types and provides accumulator helpers for
//! stamp construction and verification.

use ff::Field as _;
use lazy_static::lazy_static;
pub use mock_ragu::Proof;
use mock_ragu::{Application, ApplicationBuilder};
use pasta_curves::Fp;

use crate::{
    action::Action,
    primitives::{ActionDigest, ActionDigestError, Tachygram},
    stamp::{
        delegation::{DelegationSeed, DelegationStep, NullifierStep},
        header::{MergeStamp, OutputStamp, SpendStamp, StampLift},
        pool::{PoolSeed, PoolStep},
        spend::{SpendBind, SpendNullifier, SpendNullifierFuse},
        spendable::{SpendableEpochLift, SpendableInit, SpendableLift, SpendableRollover},
    },
};

/// Compute the raw Fp product accumulator over action digests.
pub fn compute_action_acc(actions: &[Action]) -> Result<Fp, ActionDigestError> {
    let mut acc = Fp::ONE;
    for action in actions {
        let digest = ActionDigest::try_from(action)?;
        acc *= Fp::from(digest);
    }
    Ok(acc)
}

/// Compute the raw Fp product accumulator over tachygrams.
pub(super) fn compute_tachygram_acc(tachygrams: &[Tachygram]) -> Fp {
    tachygrams
        .iter()
        .fold(Fp::ONE, |acc, tg| acc * Fp::from(*tg))
}

lazy_static! {
    pub(super) static ref PROOF_SYSTEM: Application = {
        #[expect(clippy::expect_used, reason = "mock registration is infallible")]
        ApplicationBuilder::new()
            .register(DelegationSeed)
            .expect("register DelegationSeed")
            .register(SpendNullifier)
            .expect("register SpendNullifier")
            .register(OutputStamp)
            .expect("register OutputStamp")
            .register(PoolSeed)
            .expect("register PoolSeed")
            .register(DelegationStep)
            .expect("register DelegationStep")
            .register(NullifierStep)
            .expect("register NullifierStep")
            .register(PoolStep)
            .expect("register PoolStep")
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
            .register(SpendNullifierFuse)
            .expect("register SpendNullifierFuse")
            .register(SpendStamp)
            .expect("register SpendStamp")
            .register(MergeStamp)
            .expect("register MergeStamp")
            .register(StampLift)
            .expect("register StampLift")
            .finalize()
            .expect("finalize")
    };
}
