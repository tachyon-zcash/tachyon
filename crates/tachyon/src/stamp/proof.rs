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
        block::{BlockBindPool, BlockSubsetEmpty, BlockSubsetFuse, BlockSubsetLeaf},
        delegation::{DelegationSeed, DelegationStep, NullifierStep},
        exclusion::{
            ExclusionFuse, ExclusionLeaf, ExclusionSetExtract, ExclusionSetFuse, ExclusionSetLeaf,
            NullifierExclusionFuse, SpendableExclusionFuse,
        },
        header::{MergeStamp, OutputStamp, SpendStamp, StampLift},
        pool::{PoolSeed, PoolStep},
        spend::{SpendBind, SpendNullifier, SpendNullifierFuse},
        spendable::{SpendableEpochLift, SpendableInit, SpendableLift, SpendableRollover},
    },
};

/// Per-step subset size for `SpendableInit` and exclusion leaves.
pub(crate) const BLOCK_POLY_N: usize = 64;

/// Fixed nullifier batch size for the sync-service exclusion set path.
pub(crate) const BATCH_M: usize = 64;

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
            .register(SpendableInit::<BLOCK_POLY_N>)
            .expect("register SpendableInit")
            .register(SpendableLift)
            .expect("register SpendableLift")
            .register(SpendableRollover)
            .expect("register SpendableRollover")
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
            .register(ExclusionLeaf::<BLOCK_POLY_N>)
            .expect("register ExclusionLeaf")
            .register(ExclusionFuse)
            .expect("register ExclusionFuse")
            .register(ExclusionSetLeaf::<BLOCK_POLY_N, BATCH_M>)
            .expect("register ExclusionSetLeaf")
            .register(ExclusionSetFuse::<BATCH_M>)
            .expect("register ExclusionSetFuse")
            .register(ExclusionSetExtract::<BATCH_M>)
            .expect("register ExclusionSetExtract")
            .register(NullifierExclusionFuse)
            .expect("register NullifierExclusionFuse")
            .register(SpendableExclusionFuse)
            .expect("register SpendableExclusionFuse")
            .register(BlockSubsetLeaf::<BLOCK_POLY_N>)
            .expect("register BlockSubsetLeaf")
            .register(BlockSubsetEmpty)
            .expect("register BlockSubsetEmpty")
            .register(BlockSubsetFuse)
            .expect("register BlockSubsetFuse")
            .register(BlockBindPool)
            .expect("register BlockBindPool")
            .finalize()
            .expect("finalize")
    };
}
