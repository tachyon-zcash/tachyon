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
//! # Soundness
//!
//! A header field or an online polynomial stands for something else. A note
//! commitment stands for a note, an anchor for a pool history, an accumulator
//! for a multiset. The argument for such a value says what it stands for, how
//! it is built from that thing, which constraints force it to be built that
//! way, and why nothing else builds to the same value.
//!
//! The arguments sit on the items they are about and cite downward.
//!
//! - A digest, an encoding or a gadget states what its output determines.
//! - A header states, under **Injectivity**, what every verified PCD of that
//!   header asserts, and why each field and polynomial determines what it
//!   stands for.
//! - A step states, under **Soundness**, why its constraints make the output
//!   header's assertion follow from the input headers' assertions.
//!
//! An assertion is about the fields of one header, the polynomials in its
//! slots, and the other verified PCDs it names. It says nothing about the
//! published chain. The Proof Tree chapter of the book joins the assertions
//! to the consensus rules.
//!
//! A value *determines* a thing when two different things for one value give
//! a Poseidon collision or a discrete-log relation that the assumptions below
//! say nobody can produce.
//!
//! ## Assumptions
//!
//! - **Recursion.** Ragu is an argument of knowledge. Whoever produces a PCD
//!   that verifies can also produce the tree of steps that built it, with every
//!   step's wires, and every circuit in the tree is satisfied. This is what
//!   "its prover knows" means in a header's assertion. Each input a step reads
//!   is a verified PCD of the header the step declares. A value a step opens is
//!   the value of the polynomial that the step producing that slot committed.
//!   An output slot a step does not open holds the constant one. The two bridge
//!   hash wires a step reads are a bridge hash of the accumulator in that
//!   step's last output slot. No step circuit constrains them, and Ragu holds
//!   them to the slot. A header reaches a step or a verifier as [`HEADER_SIZE`]
//!   elements that end in its suffix, and no two headers share a suffix.
//!
//!   The tree holds the steps registered in [`new_application`] and two of
//!   Ragu's own. The bootstrap step outputs the unit header. Rerandomization
//!   reads a PCD of any header and outputs that header with the same fields,
//!   and it holds each output polynomial equal to the input's at its
//!   challenge. A header's documentation names the registered steps that
//!   output it, and rerandomization preserves every assertion they establish.
//!   This application registers no decompression step.
//! - **Poseidon.** Each tag absorbs a fixed number of elements. No two distinct
//!   triples of tag, absorbed elements of that number and squeeze position are
//!   known that give the same element. Given an element drawn at random, no
//!   absorbed elements can be found that give it (preimage resistance). Only
//!   [`AnchorSpanSeed`](pool::AnchorSpanSeed) uses preimage resistance.
//! - **Commitments.** No discrete-log relation is known among the generators of
//!   either curve. An accumulator is the sum $\sum_j c_j G_j$ of fixed host
//!   generators weighted by a polynomial's coefficients, without a blinding
//!   term, so an accumulator determines its polynomial among those of at most
//!   $2^{13}$ coefficients. A bridge hash commits to the two coordinates of an
//!   accumulator under the nested generators, so a bridge hash determines its
//!   accumulator. One accumulator has many bridge hashes.
//!   [`bridge_hash`](crate::bridge_hash) computes the one an honest prover
//!   uses. No discrete-log relation is known between the value commitment
//!   generators $\mathcal{V}$ and $\mathcal{R}$ either.
//! - **Challenge.** Ragu squeezes a step's challenge from a transcript and
//!   models that hash as a random oracle. The challenge is then uniform and
//!   independent of everything the transcript absorbed before it.
//!
//! ## Checks at the challenge
//!
//! Ragu draws a step's challenge $\zeta$ after it has committed the step's
//! output polynomials and staged values, and after both input proofs are
//! fixed. Input header fields, input polynomials, output polynomials, staged
//! values and constants are fixed before $\zeta$. A digest computed in the
//! circuit is fixed before $\zeta$ when every element it absorbs is. Any other
//! wire is the prover's choice with $\zeta$ in hand, the bridge hash and the
//! output header's fields included.
//!
//! A step that equates two expressions in openings at $\zeta$ equates two
//! polynomials at a random point. When every polynomial and coefficient in
//! them is fixed before $\zeta$, the two polynomials are equal, unless
//! $\zeta$ is a root of their difference. A product of two slots has degree
//! below $2^{14}$, so one attempt at one step meets a root with probability
//! below $2^{14}/p$, and the bound adds over the steps of a tree and over a
//! prover's attempts. Each step names the values its identities read and says
//! why each is fixed.
//!
//! An opening at any other point is the committed polynomial's value at that
//! point. A zero opening shows that the point is a root.

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

use ragu::{AcceleratedProver, Application, ApplicationBuilder, WalletRank, pasta::Pasta};

use crate::pasta;

/// Eight payload elements for QR split/selection and bucket headers and one
/// suffix element.
pub const HEADER_SIZE: usize = 9;

/// The Tachyon Ragu application, with accelerated proving and reference
/// verification kernels.
pub type App<'app> = Application<'app, Pasta, WalletRank, HEADER_SIZE, AcceleratedProver>;

/// Builds the Tachyon application with the baked setup.
///
/// Building runs the full setup, so a caller builds one application per
/// worker, keeps it on that worker and lends `&app` to each proof
/// operation.
///
/// # Errors
///
/// Returns an error if step registration or application finalization fails.
pub fn new_application() -> Result<Box<App<'static>>, ragu::Error> {
    ApplicationBuilder::<Pasta, WalletRank, HEADER_SIZE, AcceleratedProver>::new()
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
