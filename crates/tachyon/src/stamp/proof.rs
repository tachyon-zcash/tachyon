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
        coverage::{
            CoverageEmpty, CoverageFuse, CoverageLeaf, ExclusionFinalize, ExclusionLeaf,
            InclusionBindNullifier, InclusionFinalize, InclusionLeaf,
        },
        delegation::{DelegationSeed, DelegationStep, NullifierStep},
        exclusion::{
            ExclusionFuse, ExclusionSetExtract, ExclusionSetFuse, ExclusionSetLeaf,
            NullifierExclusionFuse, SpendableExclusionFuse,
        },
        header::{MergeStamp, OutputStamp, SpendStamp, StampLift},
        pool::{PoolSeed, PoolStep},
        spend::{SpendBind, SpendNullifier, SpendNullifierFuse},
        spendable::{SpendableEpochLift, SpendableLift, SpendableRollover},
    },
};

/// Tachygrams per leaf of the membership proof trees.
///
/// Any membership test is ultimately over a tree of buckets this size,
/// witnessed by `CoverageLeaf`, `InclusionLeaf`, or `ExclusionLeaf`.
///
/// The tradeoff is leaf cost vs more leaves.
pub(crate) const COVERAGE_CHUNK: usize = 16;

/// Nullifiers per sync-service exclusion batch.
///
/// Controls the amortization width of `ExclusionSetLeaf`,
/// `ExclusionSetFuse`, and `ExclusionSetExtract`. Within each batch the
/// sync service evaluates one sub-block's polynomial at this many
/// nullifiers, sharing the polynomial construction cost across all of
/// them.
///
/// Biased conservatively: larger values improve amortization but produce
/// heavier per-step witnesses (up to `2 × SYNC_CHUNK` field elements in
/// the fuse and extract steps) and yield fewer, coarser work units for
/// parallelism.
///
/// Must satisfy `COVERAGE_CHUNK * SYNC_CHUNK ≤ per-step constraint
/// budget`.
pub(crate) const SYNC_CHUNK: usize = 64;

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
            .register(CoverageLeaf::<COVERAGE_CHUNK>)
            .expect("register CoverageLeaf")
            .register(InclusionLeaf::<COVERAGE_CHUNK>)
            .expect("register InclusionLeaf")
            .register(ExclusionLeaf::<COVERAGE_CHUNK>)
            .expect("register ExclusionLeaf")
            .register(CoverageEmpty)
            .expect("register CoverageEmpty")
            .register(CoverageFuse)
            .expect("register CoverageFuse")
            .register(InclusionFinalize)
            .expect("register InclusionFinalize")
            .register(InclusionBindNullifier)
            .expect("register InclusionBindNullifier")
            .register(ExclusionFinalize)
            .expect("register ExclusionFinalize")
            .register(ExclusionFuse)
            .expect("register ExclusionFuse")
            .register(ExclusionSetLeaf::<COVERAGE_CHUNK, SYNC_CHUNK>)
            .expect("register ExclusionSetLeaf")
            .register(ExclusionSetFuse::<SYNC_CHUNK>)
            .expect("register ExclusionSetFuse")
            .register(ExclusionSetExtract::<SYNC_CHUNK>)
            .expect("register ExclusionSetExtract")
            .register(NullifierExclusionFuse)
            .expect("register NullifierExclusionFuse")
            .register(SpendableExclusionFuse)
            .expect("register SpendableExclusionFuse")
            .finalize()
            .expect("finalize")
    };
}
