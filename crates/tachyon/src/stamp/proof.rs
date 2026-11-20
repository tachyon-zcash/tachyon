//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types.
//!
//! `Step::INDEX` runs from zero without gaps, and [`new_application`] registers
//! the steps in that order; `ApplicationBuilder` rejects any other sequence.
//! `Header::SUFFIX` runs from zero without gaps too.
//!
//! A step is named "noun + verb", where the noun is the header it **emits**,
//! not the one it reads. Most fuse steps read and emit the same header, which
//! leaves the rule invisible until one does not: `EvidenceTreeFuse` emits an
//! `EvidenceTree` and reads two `EvidenceTreePair`s, and `EvidenceTreePairFuse`
//! emits the pair. Three steps whose output is a part of what they read are
//! named for the input instead: `QrIntakeSplit`, `QrSideDescend` and
//! `EvidenceTreeOpen`.
//!
//! Steps relate polynomials through their openings at the challenge
//! $\zeta$, which the framework derives after committing every polynomial a
//! step opens. A product or root identity that holds at $\zeta$ therefore holds
//! as a polynomial identity, except with probability about
//! $\mathrm{deg}/|\mathbb{F}_p|$ (Schwartz-Zippel). The identity says which
//! polynomials it relates only through their commitments, so each step grounds
//! its operands in an input or output header, and each root it checks is fixed
//! before $\zeta$. A commitment that is only witnessed, or threaded onward
//! unchanged, binds nothing until a public input, a header or a consensus check
//! fixes it.
//!
//! # Header injectivity
//!
//! Ragu requires every header's `encode` to be injective in its `Data` and
//! cannot check it. Each header here has a tuple for `Data`, or the one
//! `Anchor` of `Actions`. `encode` allocates every component into elements of
//! its own, and the derived `Write` of the output gadget emits them in
//! declaration order. No element packs, sums or hashes two components, and the
//! element count is fixed. Two encodings are therefore equal only when they
//! agree component by component, and a header's encoding is injective when
//! each component's is. A component is one of three kinds:
//!
//! - A field element. `Anchor`, `Tachygram`, `note::Commitment`, `Nullifier`,
//!   `PaymentKey`, `NoteMasterKey`, `QrDiscriminant`, `EvidenceTreeRoot` and
//!   the two note trapdoors hold one `Fp` and nothing else. Each encodes as
//!   that element.
//! - An integer. `EpochIndex` wraps a `u32`, `value::Positive` wraps an `i64`
//!   that its constructors keep in `0..=MAX_MONEY`, and `QrProfile` is two
//!   `u32`s, `depth` and `bits`, each in its own element. Each integer widens
//!   to `u64` without loss, and distinct integers below $2^{64}$ are distinct
//!   in $\mathbb{F}_p$. The range checks `encode` emits constrain a prover's
//!   witness; the argument does not use them.
//! - A curve point. `TachygramSetBridge` and `value::Commitment` encode as
//!   affine coordinates $(x, y)$, two elements, and a point other than the
//!   identity is determined by its coordinates. Both types can hold the
//!   identity, which has no coordinates and no encoding: `encode` panics on an
//!   identity `TachygramSetBridge` and returns an error on an identity
//!   `value::Commitment`.
//!
//! Each `Header` implementation names the kind of every component it encodes.

#![allow(missing_debug_implementations, missing_docs, reason = "todo")]

pub mod delegation;
pub mod evidence;
pub mod output;
pub mod pool;
pub mod qr;
pub mod spend;
pub mod spendable;
pub mod stamp;
pub mod summary;

use alloc::boxed::Box;

use ragu::{AcceleratedProver, Application, ApplicationBuilder, ProductionRank, pasta::Pasta};

use crate::pasta;

/// Eight payload elements for QR split/selection and bucket headers and one
/// suffix element.
pub const HEADER_SIZE: usize = 9;

/// The Tachyon Ragu application, with accelerated proving and reference
/// verification kernels.
pub type App<'app> = Application<'app, Pasta, ProductionRank, HEADER_SIZE, AcceleratedProver>;

/// Builds the Tachyon application with the baked setup.
///
/// Building runs the full setup, so a caller builds one application per
/// worker, keeps it on that worker and lends `&app` to each proof
/// operation.
///
/// # Errors
///
/// Returns an error if step registration or application finalization fails.
#[expect(clippy::large_stack_frames, reason = "builder chain; runs once")]
pub fn new_application() -> Result<Box<App<'static>>, ragu::Error> {
    ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE, AcceleratedProver>::new()
        .register(delegation::NoteSeed)?
        .register(delegation::NullifierDerive)?
        .register(pool::UnspentFuse)?
        .register(pool::UnspentBind)?
        .register(spendable::SpendableInit)?
        .register(spendable::SpendableLift)?
        .register(output::OutputBind)?
        .register(stamp::OutputAction)?
        .register(spend::SpendBind)?
        .register(stamp::SpendAction)?
        .register(stamp::StampMerge)?
        .register(stamp::StampLift)?
        .register(delegation::NullifierFuse)?
        .register(summary::SummarySeed)?
        .register(summary::SummaryAdvance)?
        .register(qr::QrSummaryIntake)?
        .register(qr::QrIntakeMerge)?
        .register(qr::QrIntakeSplit)?
        .register(qr::QrSideDescend)?
        .register(qr::QrUnspentInit)?
        .register(qr::QrBucketSeal)?
        .register(qr::QrStampIntakeSeed)?
        .register(spendable::QrSpendableInit)?
        .register(qr::QrEmptyIntakeSeed)?
        .register(pool::UnspentLift)?
        .register(evidence::EvidenceTreePairFuse)?
        .register(evidence::EvidenceTreeFuse)?
        .register(evidence::EvidenceTreeCap)?
        .register(evidence::EvidenceTreeDescend)?
        .register(evidence::EvidenceTreeOpen)?
        .register(evidence::EvidenceTreeLeafPair)?
        .register(pool::AnchorSpanSeed)?
        .register(pool::AnchorSpanFuse)?
        .register(stamp::FeeFuse)?
        .register(stamp::ActionMerge)?
        .register(stamp::ActionLift)?
        .register(stamp::FeeSeed)?
        .register(stamp::StampUnmerge)?
        .register(qr::QrSideSelect)?
        .finalize(pasta::baked())
        .map(Box::new)
}
