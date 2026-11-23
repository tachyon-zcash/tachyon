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
//! A header field or an online polynomial stands for something else, such as
//! a note, a pool history or a multiset. The argument for it says what it
//! stands for, which constraints force that, and why nothing else gives the
//! same value. Each argument sits on the item it is about and cites the items
//! below it.
//!
//! - A digest, an encoding or a gadget states what its output determines.
//! - A header states, under **Injectivity**, what every verified PCD of that
//!   header asserts and what each field and polynomial stands for.
//! - A step states, under **Soundness**, which constraints give the output
//!   header's assertion.
//!
//! An assertion is about one header's fields and slots and the other verified
//! PCDs it names. It says nothing about the published chain.
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
//!   is a verified PCD of the header the step declares. A header reaches a step
//!   or a verifier as [`HEADER_SIZE`] elements that end in its suffix, and no
//!   two headers share a suffix. A value a step opens is the value of the
//!   polynomial that the step producing that slot committed. An output slot a
//!   step does not open holds the constant one, and no registered step can open
//!   a slot its header lists as `Padding`. The two bridge hash wires a step
//!   reads are a bridge hash of the accumulator in that step's last output
//!   slot. Ragu holds them to the slot, and no step circuit constrains them.
//!
//!   The tree holds the steps registered in [`new_application`], Ragu's
//!   bootstrap step, which outputs the unit header, and Ragu's rerandomization
//!   step, which `Application::rerandomize` runs twice in a row. That step
//!   outputs the header it reads with the same fields and holds each output
//!   polynomial equal to the input's at its challenge, so it preserves every
//!   assertion. A header's documentation therefore names only the registered
//!   steps that output it. The application proves in Ragu's standard profile,
//!   which has no decompression step.
//! - **Poseidon.** Each tag absorbs a fixed number of elements. No two distinct
//!   triples of tag, absorbed elements of that number and squeeze position are
//!   known that give the same element. [`AnchorSpanSeed`](pool::AnchorSpanSeed)
//!   alone needs more. Its argument models the stamp absorption digest as a
//!   random function, and it says so.
//! - **Commitments.** No discrete-log relation is known among the generators of
//!   either curve, nor between the value commitment generators $\mathcal{V}$
//!   and $\mathcal{R}$. An accumulator is the sum $\sum_j c_j G_j$ of host
//!   generators weighted by a polynomial's coefficients, without a blinding
//!   term. It determines its polynomial among those of at most $2^{13}$
//!   coefficients. A bridge hash commits to an accumulator's two coordinates
//!   under the nested generators and determines the accumulator. One
//!   accumulator has many bridge hashes, and
//!   [`bridge_hash`](crate::bridge_hash) computes the one an honest prover
//!   uses.
//! - **Challenge.** Ragu squeezes a step's challenge from a transcript and
//!   models that hash as a random oracle. The challenge is then uniform and
//!   independent of everything the transcript absorbed before it.
//!
//! ## Native encodings
//!
//! Ragu's verifier recomputes a header's elements from its native `Data` and
//! runs no constraint, so two `Data` values of one header must never encode
//! alike ([`Header`](ragu::header::Header)). Every header here gives each
//! part of its `Data` elements of its own, in a fixed order and number. Two
//! `Data` values then encode alike only if some part does, and no part does.
//!
//! - An epoch, a note value and each half of a profile are native integers, at
//!   most `EPOCH_MAX`, `MAX_MONEY` and $2^{32} - 1$. Each encodes as that
//!   integer in one element, below the modulus. No header packs two of them
//!   into one element.
//! - A value commitment and a bridge hash are points. A point encodes as its
//!   two affine coordinates, which determine it. The identity has no
//!   coordinates, and encoding it fails.
//! - Every other part wraps one field element and encodes as it.
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
//! polynomials at a random point. When everything in them is fixed before
//! $\zeta$, the polynomials are equal unless $\zeta$ is a root of their
//! difference. A product of two slots has degree below $2^{14}$, so one
//! attempt at one step meets a root with probability below $2^{14}/p$, and the
//! bound adds over the steps of a tree and a prover's attempts. Each step says
//! why the values its identities read are fixed.
//!
//! An opening at any other point is the committed polynomial's value at that
//! point. A zero opening shows that the point is a root.
//!
//! ## Zero tachygrams
//!
//! A [set polynomial](crate::collections::multiset) records a root and not
//! what the root was published as. A zero tachygram is the factor $X$ whether
//! it was meant as a note commitment, a padding tachygram, a nullifier or a
//! fee change commitment. The circuit that derives a tachygram holds it
//! nonzero. [`OutputBind`](output::OutputBind) holds the commitment and the
//! padding tachygram, [`SpendBind`](spend::SpendBind) both nullifiers, and
//! [`FeeFuse`](stamp::FeeFuse) and [`FeeSeed`](stamp::FeeSeed) the fee change
//! commitment. Every tachygram of a leaf of a verified
//! [`Stamp`](stamp::Stamp) is therefore nonzero, and zero is a root of no
//! tachygram set polynomial that a verifier recomputes from published
//! members.
//!
//! The arguments tell a note commitment, a padding tachygram and a nullifier
//! apart by their tags. A fee change commitment is a note commitment. A
//! padding tachygram or a nullifier equal to a note commitment is a Poseidon
//! collision, and so are two notes with one commitment. At zero the collision
//! is two preimages of zero, each found without the other. The Poseidon
//! assumption excludes it like any other collision. The constraints exclude
//! it without the assumption, because no step that derives a tachygram has an
//! assignment at zero.
//!
//! Without the constraints, a prover who knows one note whose padding
//! tachygram is zero and a second note whose commitment is zero outputs the
//! first. The stamp's polynomial then has the root zero.
//! [`SpendableInit`](spendable::SpendableInit) opens it at the second note's
//! commitment for zero, and the second note is spent though no output
//! created it and no binding signature balanced its value. A zero nullifier
//! gives the same root from a spend. A zero commitment or fee change
//! commitment gives it too, and the second note is then a different note
//! with the same commitment.

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
