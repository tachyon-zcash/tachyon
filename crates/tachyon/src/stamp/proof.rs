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

use ragu_circuits::{polynomials::ProductionRank, staging::wire_degree};
use ragu_core::{Cycle as _, FixedGenerators as _, pasta::Pasta};
use ragu_pcd::{Application, ApplicationBuilder, RegistryTags};
use ragu_primitives::{ENDOSCALAR_BITS, ENDOSCALAR_PRODUCTS};
use udon::curve::{Affine as _, Projective as _};

use crate::{
    pasta,
    pasta::{EpAffine, EqAffine},
};

/// Eight payload elements for QR split/selection and bucket headers and one
/// suffix element.
pub const HEADER_SIZE: usize = 9;

/// Computes the value `Application::bridge_hash` returns, without an
/// application. The test in `proof/tests.rs` pins it to the application's
/// result.
///
/// # Panics
///
/// Panics if `commitment` is the identity.
pub(crate) fn bridge_hash(commitment: EqAffine) -> EpAffine {
    #[expect(
        clippy::expect_used,
        reason = "no set polynomial commits to the identity"
    )]
    let (x, y) = commitment
        .coordinates()
        .expect("tachygram set commitment is not the identity");
    // The bridge stage starts after the endoscalar values, rounded up to whole
    // gates.
    let x_wire = (ENDOSCALAR_BITS + ENDOSCALAR_PRODUCTS).next_multiple_of(2);
    let y_wire = x_wire + 1;
    let generators = Pasta::nested_generators(pasta::baked()).g();
    #[expect(
        clippy::expect_used,
        reason = "the baked setup holds a nested generator for every ProductionRank degree"
    )]
    let generator = |wire| {
        generators
            .get(wire_degree::<ProductionRank>(wire))
            .expect("the baked setup has the bridge generators")
    };
    let g_x = generator(x_wire);
    let g_y = generator(y_wire);
    (g_x.to_projective() * x + g_y.to_projective() * y).to_affine()
}

/// The Tachyon Ragu application.
pub type App<'app> = Application<'app, Pasta, ProductionRank, HEADER_SIZE>;

/// Builds the Tachyon application with the baked setup and fixed registry tags.
///
/// Building runs the full setup.
///
/// # Errors
///
/// Returns an error if step registration or application finalization fails.
#[expect(
    clippy::large_stack_frames,
    reason = "the by-value register chain keeps every intermediate builder in the debug frame; a Ragu issue tracks it"
)]
pub fn new_application() -> Result<Box<App<'static>>, ragu_core::Error> {
    // Registry tags use the fixed Tachyon beacon and configuration digest.
    let manifest = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(b"Tachyon PCD: Pasta, R13, H9, steps 0..38, ragu a73db816");
    let tags = RegistryTags::<Pasta>::from_beacon(b"Tachyon registry beacon", manifest.as_bytes());
    ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
        .with_registry_tags(tags, manifest.as_bytes())?
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

#[cfg(test)]
mod tests;
