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
use udon::curve::{Affine, Projective as _};

use crate::pasta;

/// Eight payload elements for QR split/selection and bucket headers and one
/// suffix element.
pub const HEADER_SIZE: usize = 9;

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
    /// The coordinates of the empty stamp's bridge hash: the bridge hash of
    /// the constant-one commitment, fixed by the baked parameters and
    /// production rank. Steps read it while the application registers them,
    /// so it is computed without one.
    static ref EMPTY_STAMP_BRIDGE_HASH: [pasta::Fp; 2] = {
        let params = pasta::baked();
        #[expect(clippy::expect_used, reason = "the fixed setup's first generator is finite")]
        let (x, y) = Pasta::host_generators(params)
            .g()
            .first()
            .and_then(Affine::coordinates)
            .expect("constant-one commitment is finite");
        // The bridge point follows the hoisted endoscalar's bits and products,
        // starting at the next reserved gate (two stage wires per gate).
        let first_wire = (ENDOSCALAR_BITS + ENDOSCALAR_PRODUCTS).next_multiple_of(2);
        let generators = Pasta::nested_generators(params).g();
        #[expect(clippy::expect_used, reason = "the production rank has both bridge generators")]
        let [left, right] = [first_wire, first_wire + 1].map(|wire| {
            generators
                .get(wire_degree::<ProductionRank>(wire))
                .expect("bridge generators exist at production rank")
                .to_projective()
        });
        #[expect(clippy::expect_used, reason = "the fixed setup's bridge hash is finite")]
        let coordinates = (left * x + right * y)
            .to_affine()
            .coordinates()
            .expect("constant-one bridge hash is finite");
        coordinates.into()
    };

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
