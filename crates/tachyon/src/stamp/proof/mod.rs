//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types and provides accumulator helpers for
//! stamp construction and verification.
//!
//! `Step::INDEX` runs from zero without gaps, and [`make_app`] registers the
//! steps in that order; `ApplicationBuilder` rejects any other sequence.
//! `Header::SUFFIX` runs from zero without gaps too. Adding or removing
//! either renumbers the tail.

extern crate alloc;

pub mod delegation;
pub mod pool;
pub mod qr;
pub mod spend;
pub mod spendable;
pub mod stamp;
pub mod summary;

use lazy_static::lazy_static;
pub use ragu::Proof;
use ragu::{Application, ApplicationBuilder};

fn make_app() -> Result<Application, ragu_core::Error> {
    ApplicationBuilder::new()
        .register(delegation::NoteSeed)?
        .register(delegation::NullifierDerive)?
        .register(pool::AnchorSeed)?
        .register(pool::AnchorFuse)?
        .register(pool::UnspentSeed)?
        .register(pool::EndEpochUnspentSeed)?
        .register(pool::UnspentFuse)?
        .register(pool::UnspentBind)?
        .register(spendable::SpendableInit)?
        .register(spendable::SpendableLift)?
        .register(stamp::OutputAction)?
        .register(spend::SpendBind)?
        .register(stamp::SpendAction)?
        .register(stamp::StampMerge)?
        .register(stamp::StampLift)?
        .register(delegation::NullifierFuse)?
        .register(summary::SummarySeed)?
        .register(summary::SummaryAdvance)?
        .register(pool::SummaryUnspentInit)?
        .register(spendable::SummarySpendableInit)?
        .register(qr::QrSummaryIntakeInit)?
        .register(qr::QrIntakeMerge)?
        .register(qr::QrIntakeSplit)?
        .register(qr::QrSideDescend)?
        .register(qr::QrUnspentInit)?
        .register(qr::QrBucketSeal)?
        .register(qr::QrStampIntakeSeed)?
        .register(spendable::QrSpendableInit)?
        .register(qr::QrBucketTreeInit)?
        .register(qr::QrBucketTreePairFuse)?
        .register(qr::QrBucketTreeFuse)?
        .register(qr::QrBucketTreeCap)?
        .register(qr::QrBucketTreeDescend)?
        .register(qr::QrBucketTreeOpen)?
        .register(qr::QrBucketTreePairInit)?
        .finalize()
}

lazy_static! {
    /// A static ref to the mock ragu application.
    pub static ref PROOF_SYSTEM: Application = {
        #[expect(
            clippy::expect_used,
            reason = "hardcoded step ordering must register cleanly"
        )]
        make_app().expect("registration of fixed step list must succeed")
    };
}
