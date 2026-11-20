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
//! Verifiers bind a PCD's data to its header by recomputing `encode` natively.
//! They ignore its constraints and take a routine's `Known` prediction in place
//! of running the routine. No two `Data` values, including values the circuit
//! rejects, may encode to the same field elements. Each header's `encode`
//! gives its injectivity argument field by field.
//!
//! A header consists of its `Output` gadget's elements, zero padding up to
//! `HEADER_SIZE - 1` elements, and the suffix element. The derived `Write`
//! writes each gadget field once in declaration order, and each array in index
//! order. Every field has a fixed width, so a field occupies the same element
//! indices in every header of its type. Each field's map is injective over its
//! Rust type and the fields' indices are disjoint, so the elements determine
//! the whole `Data`. `ApplicationBuilder` rejects two header types with one
//! suffix, and the suffix element separates header types whose other elements
//! match.
//!
//! The headers use four leaf encodings, each injective over its whole Rust
//! type:
//!
//! - An `Fp` newtype, directly or through `Tachygram`, is written as its inner
//!   element. The map is the identity.
//! - An `EpochIndex` or a `QrProfile` field is a `u32` written as its integer.
//!   Every `u32` is less than $p$.
//! - A `value::Positive` holds an `i64` and is written as its `unsigned_abs`.
//!   Every constructor holds the `i64` to `0..=MAX_MONEY`. On that range
//!   `unsigned_abs` is the identity, and `MAX_MONEY` is less than $p$.
//! - A Pallas point is written as its affine coordinates $(x, y)$, which
//!   determine the point. The identity has no affine coordinates.
//!   `Point::alloc` returns an error on the identity and the bridge hash fields
//!   panic on it, so the identity has no encoding.
//!
//! The range checks in `EpochIndex::alloc` and `Positive::alloc` constrain the
//! allocated element and keep that element as the header wire. No header wire
//! is a routine output, so no `Known` prediction stands in for a header
//! element.

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
