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
//! Each header field or online polynomial stands for an object such as a note,
//! a pool history or a multiset, and its documentation states what it stands
//! for, which constraints enforce that, and why no other object shares the same
//! value. Arguments sit on the items they describe and cite lower-level items.
//!
//! - Digests, encodings and gadgets state what their outputs determine.
//! - Headers state under **Injectivity** what every verified PCD of that header
//!   asserts and what each field and polynomial stands for.
//! - Steps state under **Soundness** which constraints establish the output
//!   header's assertion.
//!
//! Each assertion covers one header's fields, slots and named verified PCDs,
//! saying nothing about the published chain.
//!
//! A value *determines* a thing when two distinct things sharing that value
//! yield a Poseidon collision or a discrete-log relation that the assumptions
//! below say nobody can produce. This need not give a way to recover the thing.
//!
//! ## Assumptions
//!
//! - **Recursion.** Ragu is an argument of knowledge. Parties jointly producing
//!   a verified PCD can also produce the step tree that built it, with every
//!   step's wires satisfying its circuit. In a header's assertion, "its prover
//!   knows" means that the tree contains the named value, chain or verified
//!   PCD, known to the party that ran that step. Extending a received PCD
//!   credits the party only with the steps it ran and nothing beneath them
//!   ([full proofs](self#full-proofs-between-parties)). Ragu's book calls
//!   extraction a knowledge assumption and provides no end-to-end soundness
//!   argument across recursion. Every step input is a verified PCD of the
//!   declared header. Headers reach steps and verifiers as [`HEADER_SIZE`]
//!   elements ending in a unique suffix. Opening a slot yields the evaluation
//!   of the polynomial committed when producing that slot. Unopened output
//!   slots hold the constant one, and no registered step can open a `Padding`
//!   slot. Ragu constrains a step's two bridge hash wires to a bridge hash of
//!   the accumulator in the step's last output slot without step-circuit
//!   constraints.
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
//!
//! ## Native encodings
//!
//! Because Ragu's verifier recomputes header elements from native `Data`
//! without constraints, distinct `Data` values of one header must never encode
//! alike ([`Header`](ragu::header::Header)). Every header assigns each `Data`
//! part its own elements in a fixed count and order, and no part collides.
//!
//! - Epochs, note values and profile halves are native integers bounded by
//!   `EPOCH_MAX`, `MAX_MONEY` and $2^{32} - 1$. Each occupies its own element
//!   as that integer below the modulus, without packing two integers together.
//! - Value commitments and bridge hashes encode as their two affine
//!   coordinates, which determine the point, while encoding the identity fails.
//! - Every other part wraps one field element and encodes directly as it.
//!
//! ## Checks at the challenge
//!
//! Ragu draws a step's challenge $\zeta$ after fixing both input PCDs and
//! committing the step's output polynomials and staged values. Input header
//! fields, input and output polynomials, staged values, constants and any
//! in-circuit digest of fixed inputs are all fixed before $\zeta$. The prover
//! chooses every other wire with $\zeta$ in hand, including the bridge hash and
//! output header fields.
//!
//! Equating two expressions in openings at $\zeta$ compares two polynomials at
//! a random point. If the polynomials are distinct and fixed before $\zeta$,
//! the check passes only at a root of their nonzero difference. A product of
//! two slots has degree below $2^{14}$, so one attempt at a false identity of
//! this degree passes with probability below $2^{14}/p$. These bounds add
//! across tree steps and prover attempts. Each step explains why its identity
//! inputs are fixed.
//!
//! Opening at any other point evaluates the committed polynomial there, so a
//! zero opening proves a root.
//!
//! ## Zero tachygrams
//!
//! Every tachygram of every leaf in a verified [`Stamp`](stamp::Stamp) is
//! nonzero, and no tachygram set polynomial recomputed by a verifier from
//! published members has zero as a root. Because a
//! [set polynomial](crate::collections::multiset) records roots without their
//! published roles, a zero tachygram produces the factor $X$ whether intended
//! as a note commitment, padding tachygram, nullifier or fee change commitment.
//! Each tachygram-deriving circuit holds its output nonzero.
//! [`OutputBind`](output::OutputBind) constrains the commitment and padding
//! tachygram, [`SpendBind`](spend::SpendBind) constrains both nullifiers, and
//! [`FeeFuse`](stamp::FeeFuse) and [`FeeSeed`](stamp::FeeSeed) constrain the
//! fee change commitment.
//!
//! Distinct tags separate note commitments (including fee change commitments),
//! padding tachygrams and nullifiers. Matching a padding tachygram or nullifier
//! to a note commitment, or matching two notes' commitments, requires a
//! Poseidon collision. At zero, two independently found zero preimages would
//! collide. The Poseidon assumption rules this out alongside other collisions,
//! and the nonzero constraints rule it out unconditionally by leaving zero
//! unassigned.
//!
//! Without those constraints, a prover knowing a note with a zero padding
//! tachygram and a second note with a zero commitment could output the first
//! note, putting zero among the stamp polynomial's roots.
//! [`SpendableInit`](spendable::SpendableInit) would then open that polynomial
//! to zero at the second note's commitment, producing a spendable for a note
//! no output created and no binding signature balanced. Spending it still
//! requires a spend proof and authorization. A zero nullifier from a
//! spend, or a zero commitment or fee change commitment paired with a distinct
//! zero-commitment note, would permit the same spend.
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
//! Each step's soundness argument makes the output a verified `Stamp`
//! regardless of who runs it, combining leaf multisets of held stamps by sum
//! and difference alongside leaves the receiver proves itself. No argument here
//! assumes that a stamp's producer proved its leaves.
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
//!   and `cm` ([`Actions`](stamp::Actions#injectivity)). A party with every
//!   wire of a spend and a valid spendable for a later epoch can re-prove it
//!   with the same `cv` and $\mathsf{rk}$ and a new nullifier pair, so keeping
//!   those wires secret protects which pair a spend publishes and which epoch
//!   its bundle can enter. By design, a proving delegate holds those wires.
//!
//! ### What a full proof shows
//!
//! - Header fields and every coefficient of both online polynomials. For a
//!   `Stamp`, the covered bundles determine both polynomials and the published
//!   stamp supplies the anchor ([`Stamp`](stamp::Stamp#injectivity)).
//! - Commitments from Ragu's bootstrap proof, passed as the right input to both
//!   passes. Tachyon's default depends on the application, the Ragu version and
//!   its seeded generator implementation, marking the release and platform
//!   group in both uncompressed and compressed stamp proofs.
//! - Second-pass stage, trace and accumulator polynomials, which Ragu computes
//!   from first-pass commitments, challenges and values computed from the first
//!   pass's polynomials plus fresh randomness.
//!
//! Computing a compressed stamp proof from the full one reveals nothing
//! further.
//!
//! Under Ragu's standard profile, rerandomizing two valid inputs sharing a
//! header and online polynomials aims to produce outputs indistinguishable even
//! to the party that chose the inputs. However, `Application::rerandomize`
//! documents joint output hiding as unproved, Ragu's masking argument neither
//! establishes the joint output distribution nor rules out valid inputs that
//! defeat the masks, and Ragu's book states that the protocol lacks zero
//! knowledge, exposes witness polynomials uncompressed and their evaluations
//! compressed, and relies on an unaudited hiding argument.
//!
//! No header assertion depends on hiding. Each holds for every verified PCD of
//! that header regardless of what its holder learns. The spend and balance
//! arguments combine those assertions with the consensus rules. A spend
//! also requires an action signature whose signing key enters no step.
//!
//! Wallet privacy and a spend's published nullifier pair do depend on hiding in
//! both uncompressed and compressed forms. Ragu's stated indistinguishability
//! goal suffices for neither, because published bundles already fix the fee
//! note, every output note, each spend's master key and value, and every value
//! commitment opening ([`Actions`](stamp::Actions#injectivity)). Every valid
//! input shares those values, so rerandomization could leak them while meeting
//! the goal. Protecting them requires an unstated simulation property in which
//! a rerandomized stamp proof can be generated from the header, online
//! polynomials, bootstrap proof and fresh randomness alone, without the input.
//!
//! If simulation fails, rerandomization leaks at most what its input contains.
//! Wallets normally rerandomize a `FeeFuse` or `FeeSeed` output. `FeeFuse`
//! records the step that built `Actions` (distinguishing a single spend from an
//! output), stages the max fee note's `pk`, `psi`, `rcm` and value, and folds
//! the wallet tree, which may include third-party spans and sync segments.
//! `FeeSeed` has no `Actions` input and stages only `pk`, `psi` and `rcm`;
//! its note value is constrained to zero. Aggregators rerandomize a merge, lift
//! or unmerge of received stamps, or their own `FeeSeed` output.
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
//! - It uses its release's shared bootstrap proof rather than a custom one that
//!   would mark its stamps in both forms. Ragu advises sharing one pinned
//!   bootstrap proof across compatible wallets and leaves provisioning open.
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
