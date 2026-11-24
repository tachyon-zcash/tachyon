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
//! Each header's **Injectivity** section states what its verified PCD asserts
//! about its fields, polynomials and input history, independently of the
//! published chain. Each step's **Soundness** section establishes its output
//! assertion from its constraints.
//!
//! A value *determines* a thing when two distinct things sharing that value
//! yield a Poseidon collision or a discrete-log relation that the assumptions
//! below say nobody can produce. This need not give a way to recover the thing.
//!
//! ## Assumptions
//!
//! - **Recursion.** Ragu is an argument of knowledge. Parties jointly producing
//!   a verified PCD know its step tree and satisfying wires. “Its prover knows”
//!   attributes a value, chain or PCD to the party running that step; extending
//!   a received PCD implies no knowledge of its witnesses ([full stamp
//!   proofs](self#full-proofs-between-parties)). Every step input is a verified
//!   PCD of the declared header. Headers reach steps and verifiers as
//!   [`HEADER_SIZE`] elements ending in a unique suffix. Opening a slot yields
//!   the evaluation of the polynomial committed when producing that slot.
//!   Unopened output slots hold the constant one, and no registered step can
//!   open a `Padding` slot. Ragu binds the two bridge hash wires to a bridge
//!   hash of the last output slot's accumulator outside the step circuit.
//!
//!   Every tree consists of steps registered in [`new_application`], Ragu's
//!   unit-header bootstrap step, and Ragu's rerandomization step, which
//!   `Application::rerandomize` runs twice in succession. Rerandomization
//!   preserves every assertion by copying its input header fields and equating
//!   each output polynomial with its input at the challenge, so header
//!   documentation lists only registered producers. The application uses Ragu's
//!   standard profile, which includes no decompression step.
//! - **Poseidon.** Each tag absorbs a fixed number of elements, and no two
//!   distinct triples of tag, fixed-length input and squeeze position are known
//!   to yield the same element. [`AnchorSpanSeed`](pool::AnchorSpanSeed) alone
//!   needs more and models the stamp absorption digest as a random function.
//! - **Commitments.** No discrete-log relation is known among either curve's
//!   generators or between the value commitment generators $\mathcal{V}$ and
//!   $\mathcal{R}$. An accumulator $\sum_j c_j G_j$ weights host generators by
//!   polynomial coefficients without a blinding term. It determines its
//!   polynomial among those of at most $2^{13}$ coefficients. A bridge hash
//!   commits to an accumulator's two coordinates under the nested generators
//!   and determines that accumulator. Many bridge hashes exist per accumulator,
//!   and honest provers compute [`bridge_hash`](crate::bridge_hash).
//! - **Challenge.** Ragu squeezes each step's challenge from a transcript hash
//!   modelled as a random oracle, making the challenge uniform and independent
//!   of prior transcript inputs.
//! - **Rerandomization (privacy only).** Wallet privacy relies on
//!   rerandomization hiding the input proof beyond the public header, online
//!   polynomials and shared bootstrap proof.
//!
//! ## Native encodings
//!
//! Ragu's verifier encodes native [`Header::Data`](ragu::header::Header)
//! without constraints, so distinct values of one header must encode
//! differently. Fields occupy disjoint slices of fixed size and order. Each
//! epoch, note value and profile half occupies one element as an integer
//! bounded by `EPOCH_MAX`, `MAX_MONEY` and $2^{32}-1$, respectively, below the
//! modulus. Value commitments and bridge hashes encode as two affine
//! coordinates determining the point; the identity cannot encode. Other fields
//! encode their wrapped element verbatim.
//!
//! ## Checks at the challenge
//!
//! Before drawing $\zeta$, Ragu fixes both input PCDs (headers and polynomials)
//! and commits the output polynomials and staged values. Constants and digests
//! of fixed inputs are fixed too. Other wires, including bridge hash and output
//! header fields, need not be fixed before $\zeta$.
//!
//! Two distinct polynomials fixed before $\zeta$ agree there only at a root
//! of their difference. A product of
//! two slots has degree below $2^{14}$, so one attempt at a false identity of
//! this degree passes with probability below $2^{14}/p$. These bounds add
//! across tree steps and prover attempts.
//!
//! Opening at any other point evaluates the committed polynomial there, so a
//! zero opening proves a root.
//!
//! ## Zero tachygrams
//!
//! [`OutputBind`](output::OutputBind) holds `cm` and `pad` nonzero,
//! [`SpendBind`](spend::SpendBind) both nullifiers, and
//! [`FeeFuse`](stamp::FeeFuse) and [`FeeSeed`](stamp::FeeSeed) the fee change
//! commitment. Thus no leaf of a verified [`Stamp`](stamp::Stamp) contributes a
//! zero root to the published [set polynomial](crate::collections::multiset).
//! Its factors record no roles: zero always contributes $X$.
//!
//! Matching a note commitment (including fee change) to another note's
//! commitment or to a differently tagged pad or nullifier requires a Poseidon
//! collision. At zero the nonzero checks exclude a match independently of
//! collision resistance: zero cannot be the published root that
//! [`SpendableInit`](spendable::SpendableInit) tests for membership.
//!
//! ## Full proofs between parties
//!
//! In this crate, lifting, merging and unmerging take an uncompressed stamp.
//! The crate can verify a compressed stamp proof but cannot decompress it.
//!
//! ### What a receiver can produce
//!
//! Only [`StampMerge`](stamp::StampMerge), [`StampLift`](stamp::StampLift) and
//! [`StampUnmerge`](stamp::StampUnmerge) read a [`Stamp`](stamp::Stamp) among
//! registered steps, while rerandomization reads any header. Holding a full
//! stamp proof lets a receiver run these operations and compress the result.
//! If the output stamp proof verifies, its leaves satisfy the `Stamp`
//! assertion regardless of who ran the step. A receiver can combine leaf
//! multisets of held stamps by sum and difference alongside leaves it proves
//! itself; it need not have proved the input leaves.
//!
//! Bundle signatures cover each action's `cv` and $\mathsf{rk}$ plus
//! $\mathsf{cv}_\mathsf{feemax}$, leaving the stamp, the fee and each action's
//! tachygram pair for the stamp's leaves to fix from their wires.
//!
//! - Fees apply after signing. Signatures fix the maximum via
//!   $\mathsf{cv}_\mathsf{feemax}$, while the stamp's fee leaf fixes the fee
//!   and fee change. Because only [`FeeFuse`](stamp::FeeFuse) and
//!   [`FeeSeed`](stamp::FeeSeed) produce fee leaves from max-fee-note wires,
//!   producing a new fee leaf requires the opening. Its holder can choose a fee
//!   up to the signed maximum for which the fee circuit has an assignment;
//!   reusing a previously proved leaf does not require the opening. To replace
//!   the fee on an existing stamp, the holder runs `FeeFuse` twice over one of
//!   its own actions at the stamp's anchor for the old and new fees, merging
//!   the new stamp in and unmerging the old one.
//! - Proving a new action leaf for a published $\mathsf{rk}$ requires $\theta$
//!   and `cm` ([`Actions`](stamp::Actions#injectivity)). A delegate given every
//!   wire of a spend and a valid spendable for a later epoch can re-prove it
//!   with the same `cv` and $\mathsf{rk}$ and a new nullifier pair. The signing
//!   key enters no step. Spending still requires the action signature.
//!
//! The full proof carries its header and both online polynomials. For a
//! verified stamp covering published bundles, the leaf digests bind the fee and
//! output notes, each spend's master key and value, and the value commitment
//! openings ([`Actions`](stamp::Actions#injectivity),
//! [`Stamp`](stamp::Stamp#injectivity)).
//!
//! ### What a party does
//!
//! - It lets a stamp proof leave only after rerandomization.
//!   [`Plan::prove`](crate::stamp::Plan::prove) rerandomizes the output of
//!   `FeeSeed` or `FeeFuse`.
//!   [`ProofStamp::merge`](crate::stamp::ProofStamp::merge) rerandomizes the
//!   merged stamp and `ProofStamp::unmerge` the quotient. `ProofStamp::lift`
//!   rerandomizes after the last span; with no spans it returns the original
//!   stamp without rerandomizing. A full proof that was not rerandomized holds
//!   in the clear its inputs' headers, the steps that made them and their
//!   instances, and its own opening points and values. For
//!   [`SpendBind`](spend::SpendBind) that is the spent note's opening and
//!   master key.
//! - It draws randomness for every proving call from an unpredictable source.
//! - It uses its release's shared bootstrap proof. Both rerandomization passes
//!   take that proof as their right input.
//! - It verifies every received stamp before extending it.

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
