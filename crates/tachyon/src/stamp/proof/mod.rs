//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types and provides accumulator helpers for
//! stamp construction and verification.
//!
//! `Step::INDEX` runs from zero without gaps, and the [`PROOF_SYSTEM`]
//! initializer registers the steps in that order; `ApplicationBuilder` rejects
//! any other sequence.
//! `Header::SUFFIX` runs from zero without gaps too.
//!
//! A step is named "noun + verb", where the noun is the header it **emits**,
//! not the one it reads. Most fuse steps read and emit the same header, which
//! leaves the rule invisible until one does not: `EvidenceTreeFuse` emits an
//! `EvidenceTree` and reads two `EvidenceTreePair`s, and `EvidenceTreePairFuse`
//! emits the pair. Three steps whose output is a part of what they read are
//! named for the input instead: `QrIntakeSplit`, `QrSideDescend` and
//! `EvidenceTreeOpen`.

extern crate alloc;

pub mod delegation;
pub mod evidence;
pub mod output;
pub mod pool;
pub mod qr;
pub mod spend;
pub mod spendable;
pub mod stamp;
pub mod summary;

use lazy_static::lazy_static;
pub use ragu::Proof;
use ragu::{Application, ApplicationBuilder};

lazy_static! {
    /// A static ref to the mock ragu application.
    pub static ref PROOF_SYSTEM: Application = {
        #[expect(
            clippy::expect_used,
            reason = "hardcoded step ordering must register cleanly"
        )]
        ApplicationBuilder::new()
            .register(delegation::NoteSeed).expect("registration of fixed step list must succeed")
            .register(delegation::NullifierDerive).expect("registration of fixed step list must succeed")
            .register(pool::UnspentFuse).expect("registration of fixed step list must succeed")
            .register(pool::UnspentBind).expect("registration of fixed step list must succeed")
            .register(spendable::SpendableInit).expect("registration of fixed step list must succeed")
            .register(spendable::SpendableLift).expect("registration of fixed step list must succeed")
            .register(output::OutputBind).expect("registration of fixed step list must succeed")
            .register(stamp::OutputAction).expect("registration of fixed step list must succeed")
            .register(spend::SpendBind).expect("registration of fixed step list must succeed")
            .register(stamp::SpendAction).expect("registration of fixed step list must succeed")
            .register(stamp::StampMerge).expect("registration of fixed step list must succeed")
            .register(stamp::StampLift).expect("registration of fixed step list must succeed")
            .register(delegation::NullifierFuse).expect("registration of fixed step list must succeed")
            .register(summary::SummarySeed).expect("registration of fixed step list must succeed")
            .register(summary::SummaryAdvance).expect("registration of fixed step list must succeed")
            .register(qr::QrSummaryIntake).expect("registration of fixed step list must succeed")
            .register(qr::QrIntakeMerge).expect("registration of fixed step list must succeed")
            .register(qr::QrIntakeSplit).expect("registration of fixed step list must succeed")
            .register(qr::QrSideDescend).expect("registration of fixed step list must succeed")
            .register(qr::QrUnspentInit).expect("registration of fixed step list must succeed")
            .register(qr::QrBucketSeal).expect("registration of fixed step list must succeed")
            .register(qr::QrStampIntakeSeed).expect("registration of fixed step list must succeed")
            .register(spendable::QrSpendableInit).expect("registration of fixed step list must succeed")
            .register(qr::QrEmptyIntakeSeed).expect("registration of fixed step list must succeed")
            .register(pool::UnspentLift).expect("registration of fixed step list must succeed")
            .register(evidence::EvidenceTreePairFuse).expect("registration of fixed step list must succeed")
            .register(evidence::EvidenceTreeFuse).expect("registration of fixed step list must succeed")
            .register(evidence::EvidenceTreeCap).expect("registration of fixed step list must succeed")
            .register(evidence::EvidenceTreeDescend).expect("registration of fixed step list must succeed")
            .register(evidence::EvidenceTreeOpen).expect("registration of fixed step list must succeed")
            .register(evidence::EvidenceTreeLeafPair).expect("registration of fixed step list must succeed")
            .register(pool::AnchorSpanSeed).expect("registration of fixed step list must succeed")
            .register(pool::AnchorSpanFuse).expect("registration of fixed step list must succeed")
            .register(stamp::FeeFuse).expect("registration of fixed step list must succeed")
            .register(stamp::ActionMerge).expect("registration of fixed step list must succeed")
            .register(stamp::ActionLift).expect("registration of fixed step list must succeed")
            .register(stamp::FeeSeed).expect("registration of fixed step list must succeed")
            .finalize()
            .expect("registration of fixed step list must succeed")
    };
}
