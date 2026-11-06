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
use ragu_core::{Cycle as _, FixedGenerators as _, drivers::Driver, pasta::Pasta};
use ragu_primitives::Element;
use udon::field::Field as _;

use crate::{constants::EPOCH_MAX, digest::poseidon, pasta, relations::arithmetic::bounded};

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

/// Step admission checks, separate from the unrestricted protocol anchor hash.
fn enforce_stamp_domain<'dr, D: Driver<'dr, F = pasta::Fp>>(
    dr: &mut D,
    epoch: &Element<'dr, D>,
    bridge_hash: &[Element<'dr, D>; 2],
) -> ragu_core::Result<()> {
    let generator = *Pasta::host_generators(pasta::baked())
        .g()
        .first()
        .ok_or_else(|| ragu_core::Error::InvalidWitness("fixed generator table is empty".into()))?;
    let (low, high) = poseidon::bridge_hash(generator);
    let low_element = Element::constant(dr, low);
    let high_element = Element::constant(dr, high);
    let equal_low = bridge_hash[0].is_equal(dr, &mut (), &low_element)?;
    let equal_high = bridge_hash[1].is_equal(dr, &mut (), &high_element)?;
    equal_low
        .and(dr, &equal_high)?
        .element()
        .enforce_zero(dr)
        .map_err(|_err| ragu_core::Error::InvalidWitness("invalid anchor step".into()))?;
    bounded::<D, 32>(dr, epoch, u64::from(EPOCH_MAX))
}

/// Application-wide encoded header width, including one suffix element.
///
/// | Header | Scalars | Pallas points | Host commitments | Payload |
/// | --- | ---: | ---: | ---: | ---: |
/// | unit | 0 | 0 | 0 | 0 |
/// | NoteSecret | 6 | 0 | 0 | 6 |
/// | NoteNullifiers | 3 | 0 | 0 | 3 |
/// | ArbitraryUnspent | 4 | 0 | 0 | 4 |
/// | NoteUnspent | 5 | 0 | 0 | 5 |
/// | NoteSpendable | 3 | 0 | 0 | 3 |
/// | SpendHeader | 5 | 1 | 0 | 7 |
/// | OutputHeader | 2 | 1 | 0 | 4 |
/// | Actions | 1 | 0 | 0 | 1 |
/// | Stamp | 1 | 0 | 2 | 5 |
/// | Summary | 3 | 0 | 0 | 3 |
/// | QrIntake / QrIntakeSides | 6 | 0 | 0 | 6 |
/// | QrBucket | 6 | 0 | 1 | 8 |
/// | EvidenceTree | 5 | 0 | 0 | 5 |
/// | EvidenceTreePair | 6 | 0 | 0 | 6 |
/// | AnchorSpan | 2 | 0 | 0 | 2 |
///
/// Points write two coordinates; commitments write two compressed limbs.
/// Other headers' polynomials live in their slots, not on the header.
/// QrBucket writes its certified double commitment's two coordinates.
/// QrBucket requires eight payload elements, so nine is minimal. Steps
/// have one application fragment.
pub const HEADER_SIZE: usize = 9;

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
