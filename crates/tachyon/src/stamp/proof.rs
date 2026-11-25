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
//!   a received PCD implies no knowledge of its witnesses. Every step input is
//!   a verified PCD of the declared header. Headers reach steps and verifiers
//!   as [`HEADER_SIZE`] elements ending in a unique suffix. Opening a slot
//!   yields the evaluation of the polynomial committed when producing that
//!   slot. Unopened output slots hold the constant one, and no registered step
//!   can open a `Padding` slot. Ragu binds the two bridge hash wires to a
//!   bridge hash of the last output slot's accumulator outside the step
//!   circuit. Both applications register the same Tachyon steps alongside
//!   Ragu's unit-header bootstrap and rerandomization. The standard wallet
//!   profile has no decompression step. [`new_aggregator_application`] also
//!   admits decompression: it verifies a wallet proof under the captured wallet
//!   registry and binds the same header and both online commitments. Thus an
//!   import preserves the wallet assertion, just as rerandomization preserves
//!   the input header and each online polynomial. Header documentation lists
//!   only the Tachyon steps that produce the assertion.
//! - **Poseidon.** See [tagged hashing](crate::digest::poseidon#injectivity)
//!   and the [stamp-absorption random-function
//!   premise](pool::AnchorSpanSeed#soundness) used by `AnchorSpanSeed` alone.
//! - **Commitments.** See the binding of
//!   [accumulators](crate::TachygramSetCommit) and [bridge
//!   hashes](crate::primitives::TachygramSetBridge), and the [value commitment
//!   binding assumption](crate::value::ValueCommitment#binding).
//! - **Bridge generators.** Nobody knows a nontrivial relation among the nested
//!   generators that either rank's bridge stage can reach, the wallet and
//!   aggregator stages sharing one table. Only
//!   [`AnchorSpanSeed`](pool::AnchorSpanSeed) uses this, together with each
//!   rank's registered stage mask holding the other rank's coordinate degrees
//!   to zero, which [setup checks](crate::gadgets::bridge_hash) at the pinned
//!   Ragu revision.
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
//! of their difference. If the proving rank allows $N$ coefficients per slot
//! ($N = 2^{13}$ at wallet rank), a product of two slots has degree below $2N$.
//! One attempt at a false identity of this degree passes with probability below
//! $2N/p$ ($2^{14}/p$ at wallet rank). These bounds add
//! across tree steps and prover attempts. They cover any polynomial a prover
//! commits at its rank, although honest set polynomials stay below $2^{13}$
//! coefficients at either rank.
//!
//! Opening at any other point evaluates the committed polynomial there, so a
//! zero opening proves a root.
//!
//! A slot alone need not hold a product of monic linear factors. Steps can
//! establish that product by checking factors fixed before the challenge;
//! [`AnchorSpanSeed`](pool::AnchorSpanSeed) gives the separate argument for its
//! unfixed root. A verifier can also recompute the accumulator from published
//! members. Accumulators carry no member-kind tag; steps open slots by the kind
//! declared in `OnlinePolyCommit`.
//!
//! ## Chains in a step
//!
//! Steps can take the predecessor or epoch from the prover. Their digests
//! establish a chain without tying it to a pool history.
//!
//! A *stamp chain* of $k$ absorptions from $a_0$ to $a_k$ consists of an epoch
//! $e_i \leq \text{EPOCH\_MAX}$, a polynomial $P_i \notin \{0, 1\}$ and a
//! bridge hash $B_i$ of $P_i$'s accumulator at each $i \in 1..=k$, with
//! $a_i = \mathsf{st}(a_{i-1}, e_i, B_i)$. The chain is *in epoch* $e$ when
//! every $e_i$ equals $e$, and $k = 0$ sets $a_k = a_0$.
//!
//! `anchor_next_stamp` absorbs an anchor wire, an
//! [`EpochIndex`](crate::gadgets::epoch::EpochIndex) and two bridge hash wires
//! tied by [Recursion](self#assumptions) to the last output slot's accumulator,
//! except in [`AnchorSpanSeed`](pool::AnchorSpanSeed), which absorbs a point
//! derived from them that only a pool-history anchor makes a bridge hash.
//! Its polynomial is nonzero: the zero polynomial commits to the identity,
//! which lacks affine coordinates for a bridge hash. Each step also rules out
//! the constant one, as
//! [`Anchor::next_stamp`](crate::primitives::Anchor::next_stamp) rejects the
//! empty set. Only [`AnchorSpanSeed`](pool::AnchorSpanSeed) evaluates an
//! absorption inside a challenge identity.
//!
//! Steps taking a stamp polynomial from the prover do not establish that it is
//! a monic product of linear factors. Instead, they absorb a bridge hash of its
//! accumulator into an [`Anchor`](crate::primitives::Anchor), and a
//! pool-history anchor determines each preceding stamp's accumulator.
//!
//! If $a_k$ belongs to a pool history, [`Anchor`'s backward
//! injectivity](crate::Anchor#injectivity) matches the $k$
//! absorptions to its last $k$ entries behind $a_k$, including each stamp's
//! epoch $e_i$, canonical bridge hash $B_i$ and polynomial $P_i$. A non-genesis
//! $\mathsf{ep}(a,e)$ in that history is its boundary into $e$ from $a$.
//! Genesis $\mathsf{ep}(0,0)$ is no entry and does not make zero a history
//! anchor.

#![allow(missing_debug_implementations, missing_docs, reason = "todo")]

pub mod delegation;
pub mod evidence;
pub mod output;
pub mod pool;
pub mod qr;
pub mod spend;
pub mod spendable;
pub mod summary;
pub mod transaction;

use alloc::boxed::Box;

use polynomials::AggregatorRank;
use ragu::{
    AcceleratedProver, Application, ApplicationBuilder, Rank, WalletRank,
    circuits::polynomials,
    pasta::{Fp, Pasta},
    pcd::profile::{self, Aggregator, Decompression, Profiled},
};
use ragu_pcd::pasta::baked_aggregator;

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
    register_steps::<Pasta, WalletRank>()?
        .finalize(pasta::baked())
        .map(Box::new)
}

/// Builds the aggregator application with the baked aggregator setup.
///
/// It registers the same steps at aggregator rank and holds a wallet-rank
/// application under the same setup to verify and decompress wallet proofs.
///
/// # Errors
/// Returns a Ragu error if either registry or its decompression context cannot
/// be built.
#[expect(
    clippy::type_complexity,
    reason = "the rank and profile identify this application"
)]
pub fn new_aggregator_application<RNG: rand_core::CryptoRng>(
    rng: &mut RNG,
) -> ragu::Result<
    Box<
        Application<
            'static,
            Profiled<Pasta, Aggregator<HEADER_SIZE>>,
            AggregatorRank,
            HEADER_SIZE,
            AcceleratedProver,
        >,
    >,
> {
    let params = baked_aggregator();
    let wallet = register_steps::<Pasta, WalletRank>()?.finalize(params)?;
    let context = Decompression::new(wallet, rng)?;
    register_steps()?
        .finalize_with(params, context)
        .map(Box::new)
}

/// Registers the Tachyon steps in index order for the selected cycle and rank.
fn register_steps<C: profile::ProfiledCycle<Base = Pasta, CircuitField = Fp>, R: Rank>()
-> ragu::Result<ApplicationBuilder<'static, C, R, HEADER_SIZE, AcceleratedProver>> {
    ApplicationBuilder::new()
        .register(delegation::NoteSeed)?
        .register(delegation::NullifierDerive)?
        .register(pool::UnspentFuse)?
        .register(pool::UnspentBind)?
        .register(spendable::SpendableInit)?
        .register(spendable::SpendableLift)?
        .register(output::OutputBind)?
        .register(transaction::OutputAction)?
        .register(spend::SpendBind)?
        .register(transaction::SpendAction)?
        .register(transaction::TransactionMerge)?
        .register(transaction::TransactionLift)?
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
        .register(transaction::FeeFuse)?
        .register(transaction::ActionMerge)?
        .register(transaction::ActionLift)?
        .register(transaction::FeeSeed)?
        .register(transaction::TransactionUnmerge)?
        .register(qr::QrSideSelect)?
        .register(transaction::TransactionConvert)
}
