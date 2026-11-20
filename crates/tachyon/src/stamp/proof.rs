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
//! Steps relate polynomials through their openings at the challenge
//! $\zeta$, which the framework derives after committing every polynomial a
//! step opens. A product or root identity that holds at $\zeta$ therefore holds
//! as a polynomial identity, except with probability about
//! $\mathrm{deg}/|\mathbb{F}_p|$ (Schwartz-Zippel). The identity says which
//! polynomials it relates only through their commitments, so each step grounds
//! its operands in an input or output header, and each root it checks is fixed
//! before $\zeta$. A commitment that is only witnessed, or threaded onward
//! unchanged, binds nothing until a public input, a header or a consensus check
//! fixes it.
//!
//! # Header injectivity
//!
//! Ragu requires every header's `encode` to be injective in its `Data`, since
//! verifiers bind a proof's data by recomputing the encoding natively. Each
//! `Data` component here takes elements of its own, in a fixed order and
//! number. Integers (`EpochIndex`, a note's value, the `depth` and `bits` of
//! `QrProfile`) lie below $2^{64}$ and embed in $\mathbb{F}_p$ exactly. A point
//! encodes as its affine $(x, y)$. The identity has no affine coordinates, and
//! `encode` rejects it.
//!
//! A header binds what its elements stand for. Most elements are derived
//! values. Each derivation binds its inputs under one or two of the following
//! assumptions.
//!
//! - **Poseidon.** Each hash in `digest::poseidon` starts its sponge from its
//!   own 16-byte tag in the capacity. Each absorbs a fixed number of elements,
//!   the length of its array argument. The sponge absorbs no length. The fixed
//!   width keeps the inputs of one tag apart, and the tags keep the hashes
//!   apart. The assumption is that no one finds two distinct triples of tag,
//!   input and squeeze position with equal outputs.
//! - **Host discrete log.** A slot commitment is an unblinded Pedersen vector
//!   commitment to a polynomial's coefficients over the Vesta host generators.
//!   It binds the coefficients unless someone knows a discrete-log relation
//!   among those generators.
//! - **Nested discrete log.** A bridge hash $B$ commits to the coordinates of a
//!   step's second slot commitment $O_1$ over the Pallas nested generators. The
//!   honest prover computes $B = x(O_1) \cdot G_i + y(O_1) \cdot G_j$. Ragu
//!   accepts other bridge hashes too. Every accepted bridge hash binds $O_1$
//!   unless someone knows a discrete-log relation among the nested generators.
//! - **Value discrete log.** A value commitment $[v]V + [\mathsf{rcv}]R$ binds
//!   $v$ unless someone knows $\log_V R$. It hides $v$ perfectly.
//!
//! Each element type stands for the following.
//!
//! - A `note::Commitment` is `poseidon::note_commitment`, which hashes the
//!   note's opening $(\mathsf{rcm}, \mathsf{pk}, v, \psi)$ under
//!   `Tachyon-CmDerive`. It binds the note. An output's padding tachygram is
//!   `poseidon::pad_tachygram`, which hashes the same opening under
//!   `Tachyon-CmOutPad`. It binds the note too, and its tag keeps every pad
//!   apart from every note commitment.
//! - A `PaymentKey` is `poseidon::payment_key`, which hashes the affine
//!   coordinates of `ak` and `nk` under `Tachyon-PkDerive`. It binds the
//!   owner's `(ak, nk)`. `NoteSeed` derives `pk` in-circuit. An output's `pk`
//!   is the recipient's, and it binds the pair the recipient derived it from.
//! - A `NoteMasterKey` is `poseidon::nf_master`, which hashes $\psi$ and `nk`
//!   under `Tachyon-NfMaster`. It binds both.
//! - The `Nullifier` of epoch $e$ is entry $e \bmod 4$ of
//!   `poseidon::nullifier_group`. That hash squeezes four elements from `mk`
//!   and the group start $e - (e \bmod 4)$ under `Tachyon-NfDerive`. The group
//!   start and the entry together give $e$. A nullifier binds `mk` and its
//!   epoch.
//! - An `Anchor` is one of two folds. A stamp fold is
//!   `poseidon::anchor_next_stamp`, which hashes the previous anchor, the epoch
//!   and the stamp's bridge hash $(x(B), y(B))$ under `Tachyon-AnchorSt`. A
//!   boundary digest is `poseidon::anchor_next_epoch`, which hashes the
//!   previous anchor and the epoch entered under `Tachyon-AnchorEp`. Each fold
//!   binds its inputs and, by its tag, which fold it is. By induction an anchor
//!   on the consensus chain binds the chain's history back to genesis. That
//!   history is every stamp's bridge hash and every epoch crossing. Some steps
//!   take an anchor as a free witness. Such an anchor stands for a pool state
//!   only when consensus accepts it or an anchor folded from it.
//! - A `TachygramSetBridge` is a bridge hash. It binds $O_1$, and $O_1$ binds
//!   its polynomial. A monic polynomial $\prod_i (X - t_i)$ determines its
//!   multiset of roots exactly, by unique factorization. A scaled polynomial
//!   determines the same roots. Equal bridge hashes give equal sets. Equal sets
//!   can give different bridge hashes, because a step's in-circuit bridge hash
//!   need not be the honest one and a QR bucket can hold a scaled polynomial
//!   (the book's "Scaled splits"). `Anchor::next_stamp` folds the honest bridge
//!   hash. An anchor folded in-circuit from another bridge hash lies off the
//!   chain consensus accepts.
//! - An `EvidenceTreeRoot` is a leaf or a node. A leaf is
//!   `poseidon::evidence_tree_leaf`, which hashes eight elements under
//!   `Tachyon-QrBucket`. They are a bucket's epoch, two anchors, discriminant,
//!   profile and the two coordinates of its contents bridge hash. A node is
//!   `poseidon::evidence_tree_node`, which hashes four subtree roots under
//!   `Tachyon-EvidNode`. Leaves and nodes differ in tag and width. A root binds
//!   its whole tree, including its shape and every bucket under it.
//! - A `value::Commitment` is $[v]V + [\mathsf{rcv}]R$ at a spend and $[-v]V +
//!   [\mathsf{rcv}]R$ at an output. $V$ and $R$ are the Orchard
//!   `z.cash:Orchard-cv` generators. The commitment binds $v$. Values in
//!   `0..=MAX_MONEY` are distinct in $\mathbb{F}_q$. The suffix of the header
//!   that carries the commitment gives its sign.
//! - A `QrProfile` stands for a path of `depth` sides. `QrProfile::descend`
//!   shifts each new side into the low bit of `bits`. The pair `(depth, bits)`
//!   is the path exactly.
//! - A `QrDiscriminant` is the free $R_0$ a network classifies from. It stands
//!   for itself.
//!
//! These bindings say what an element determines when it was derived as its
//! type describes. The producing steps establish that it was. Each `Header`
//! implementation states what its encoding binds and under which assumptions.

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

use ragu::{AcceleratedProver, Application, ApplicationBuilder, ProductionRank, pasta::Pasta};

use crate::pasta;

/// Eight payload elements for QR split/selection and bucket headers and one
/// suffix element.
pub const HEADER_SIZE: usize = 9;

/// The Tachyon Ragu application, with accelerated proving and reference
/// verification kernels.
pub type App<'app> = Application<'app, Pasta, ProductionRank, HEADER_SIZE, AcceleratedProver>;

/// Builds the Tachyon application with the baked setup.
///
/// Building runs the full setup, so a caller builds one application per
/// worker, keeps it on that worker and lends `&app` to each proof
/// operation.
///
/// # Errors
///
/// Returns an error if step registration or application finalization fails.
#[expect(clippy::large_stack_frames, reason = "builder chain; runs once")]
pub fn new_application() -> Result<Box<App<'static>>, ragu::Error> {
    ApplicationBuilder::<Pasta, ProductionRank, HEADER_SIZE, AcceleratedProver>::new()
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
