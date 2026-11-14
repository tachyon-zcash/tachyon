//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types.
//!
//! `Step::INDEX` runs from zero without gaps, and [`make_app`] registers the
//! steps in that order; `ApplicationBuilder` rejects any other sequence.
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

use lazy_static::lazy_static;
use ragu::{Application, ApplicationBuilder, RegistryTags};
use ragu_circuits::{polynomials::ProductionRank, staging::wire_degree};
use ragu_core::{Cycle as _, FixedGenerators as _, pasta::Pasta};
use ragu_primitives::{ENDOSCALAR_BITS, ENDOSCALAR_PRODUCTS};
use udon::curve::{Affine as _, Projective as _};

use crate::{
    pasta,
    pasta::{EpAffine, EqAffine},
};

/// Eight payload elements for QR split/selection and bucket headers and one
/// suffix element.
pub const HEADER_SIZE: usize = 9;

/// Native mirror of Ragu's `Application::bridge_hash` using its baked setup.
/// Anchor folding and stamp verification need this without building an
/// application, including during `Step::polynomials`. A test pins the result
/// to the application's hash so layout changes cannot silently diverge.
///
/// Mirrors Ragu's crate-private
/// `ragu_pcd::internal::nested::stages::bridge_hash::digest`
/// (`crates/ragu_pcd/src/internal/nested/stages/bridge_hash.rs:83-103` at
/// `a1395401`). That function commits an unblinded stage polynomial holding
/// the point's two coordinates under the nested generators, giving
/// `x · G_i + y · G_j` (same file, line 9). The mock application computes the
/// same layout (`src/mock/application.rs:32, 270-279`).
///
/// # Panics
///
/// Panics if `commitment` is the identity, which has no affine coordinates
/// to hash. Every caller hashes a tachygram-set commitment, and no set
/// polynomial commits to the identity.
pub(crate) fn bridge_hash(commitment: EqAffine) -> EpAffine {
    #[expect(
        clippy::expect_used,
        reason = "no set polynomial commits to the identity"
    )]
    let (x, y) = commitment
        .coordinates()
        .expect("tachygram set commitment is not the identity");
    // The bridge stage's parent is the endoscalar stage (`bridge_hash.rs:50`),
    // which reserves `ENDOSCALAR_BITS + ENDOSCALAR_PRODUCTS` values after the
    // SYSTEM gate (`ragu_pcd/src/internal/endoscalar.rs:99-103`). Stage values
    // pack two per gate (`ragu_circuits/src/staging/mod.rs:471-475`), and a
    // stage's first reservation index is `2 · (skip_gates - 1)`
    // (`ragu_circuits/src/staging/layout.rs:128-130`). So the bridge stage
    // starts at the endoscalar value count rounded up to whole gates.
    let x_wire = (ENDOSCALAR_BITS + ENDOSCALAR_PRODUCTS).next_multiple_of(2);
    // The stage holds exactly the two coordinates (`bridge_hash.rs:54-56`),
    // x first, then y at the next reservation index.
    let y_wire = x_wire + 1;
    // `wire_degree` maps a reservation index to the polynomial degree that
    // carries it: an even index on its gate's a wire, an odd one on its d wire
    // (`ragu_circuits/src/staging/layout.rs:136-149`). The degree depends on
    // the rank, and Tachyon's application uses `ProductionRank`.
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
    // The commitment is the inner product of the stage polynomial with the
    // nested (Pallas) generators. Its only nonzero coefficients are the
    // Vesta point's coordinates, which are Pallas scalars.
    (g_x.to_projective() * x + g_y.to_projective() * y).to_affine()
}

fn make_app() -> Result<Application<'static, Pasta, ProductionRank, HEADER_SIZE>, ragu_core::Error>
{
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
}

lazy_static! {
    /// A static ref to the ragu application.
    pub static ref PROOF_SYSTEM: Application<'static, Pasta, ProductionRank, HEADER_SIZE> = {
        #[expect(
            clippy::expect_used,
            reason = "hardcoded step ordering must register cleanly"
        )]
        make_app().expect("registration of fixed step list must succeed")
    };
}

#[cfg(test)]
mod tests;
