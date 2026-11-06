//! Tachyon proofs via Ragu PCD.
//!
//! Registers all PCD step types and provides accumulator helpers for
//! stamp construction and verification.
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

extern crate alloc;
use core::array;

pub mod delegation;
pub mod evidence;
pub mod output;
pub mod pool;
pub mod qr;
pub mod spend;
pub mod spendable;
pub mod stamp;
pub mod summary;

use alloc::vec::Vec;

use lazy_static::lazy_static;
use ragu::{Application, ApplicationBuilder};
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::pasta::Pasta;
use udon::{curve::Affine as _, field::Field as _};

use crate::pasta;

/// Application proof with the production polynomial rank.
pub type Proof = ragu::Proof<Pasta, ProductionRank>;

/// Prover-side conversion to ascending-degree coefficients.
fn coefficients(poly: &Polynomial<pasta::Fp, ProductionRank>) -> Vec<pasta::Fp> {
    let mut coefficients = poly.iter_coeffs().collect::<Vec<_>>();
    coefficients.truncate(
        coefficients
            .iter()
            .rposition(|coefficient| *coefficient != pasta::Fp::ZERO)
            .map_or(1, |index| index + 1),
    );
    coefficients
}

fn unit_polynomials() -> [Vec<pasta::Fp>; 3] {
    array::from_fn(|_| alloc::vec![pasta::Fp::ONE])
}

/// Application-wide encoded header width, including one suffix element.
///
/// | Header | Scalars | Pallas points | Host commitments | Payload |
/// | --- | ---: | ---: | ---: | ---: |
/// | unit | 0 | 0 | 0 | 0 |
/// | NoteSecret | 6 | 0 | 0 | 6 |
/// | NoteNullifiers | 3 | 0 | 1 | 5 |
/// | ArbitraryUnspent | 4 | 0 | 1 | 6 |
/// | NoteUnspent | 5 | 0 | 0 | 5 |
/// | NoteSpendable | 3 | 0 | 0 | 3 |
/// | SpendHeader | 5 | 1 | 0 | 7 |
/// | OutputHeader | 2 | 1 | 0 | 4 |
/// | Actions / Stamp | 1 | 0 | 2 | 5 |
/// | Summary | 3 | 0 | 1 | 5 |
/// | QrIntake / QrBucket | 6 | 0 | 1 | 8 |
/// | QrIntakeSides | 6 | 0 | 2 | 10 |
/// | EvidenceTree | 5 | 0 | 0 | 5 |
/// | EvidenceTreePair | 6 | 0 | 0 | 6 |
/// | AnchorSpan | 2 | 0 | 1 | 4 |
///
/// Points write two coordinates. A commitment writes the two coordinates of
/// its [`bridge_hash`].
/// QrIntakeSides requires ten payload elements, so eleven is minimal. Steps
/// have one application fragment.
pub const HEADER_SIZE: usize = 11;

fn make_app() -> Result<Application<'static, Pasta, ProductionRank, HEADER_SIZE>, ragu_core::Error>
{
    ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE>::new()
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
        .finalize(pasta::baked())
}

lazy_static! {
    /// A static ref to the mock ragu application.
    pub static ref PROOF_SYSTEM: Application<'static, Pasta, ProductionRank, HEADER_SIZE> = {
        #[expect(
            clippy::expect_used,
            reason = "hardcoded step ordering must register cleanly"
        )]
        make_app().expect("registration of fixed step list must succeed")
    };
}

/// The coordinates of [`PROOF_SYSTEM`]'s bridge hash of `commitment`.
///
/// # Errors
///
/// Returns an error if `commitment` is the identity.
pub(crate) fn bridge_hash(commitment: pasta::EqAffine) -> Result<[pasta::Fp; 2], ragu_core::Error> {
    PROOF_SYSTEM
        .bridge_hash(commitment)?
        .coordinates()
        .map(<[pasta::Fp; 2]>::from)
        .ok_or_else(|| ragu_core::Error::InvalidWitness("bridge hash is the identity".into()))
}
