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
//! verifiers bind a PCD's data by recomputing the encoding natively. Each
//! `Data` component here takes elements of its own in a fixed order and number.
//! Integers (`EpochIndex`, a note's value, `QrProfile`'s `depth` and `bits`)
//! lie below $2^{64}$ and embed in $\mathbb{F}_p$ exactly. A point encodes as
//! its affine $(x, y)$; the identity has none, and `encode` rejects it.
//!
//! A header binds what its elements stand for when derived as their types
//! describe. The producing steps establish those derivations; each `Header`
//! implementation states what its encoding binds and under which assumptions.
//!
//! ## Assumptions
//!
//! - **Poseidon.** Each hash in `digest::poseidon` starts its sponge from its
//!   own 16-byte tag in the capacity and absorbs a fixed-length array of
//!   elements, with no length absorbed. Fixed width separates inputs under one
//!   tag; tags separate hashes. The assumption is that no one finds two
//!   distinct triples of tag, input and squeeze position with equal outputs.
//! - **Host discrete log.** A slot commitment is an unblinded Pedersen vector
//!   commitment to a polynomial's coefficients over the Vesta host generators;
//!   it binds the coefficients unless someone knows a discrete-log relation
//!   among those generators.
//! - **Nested discrete log.** A bridge hash $B$ commits to the coordinates of a
//!   step's second slot commitment $O_1$ over the Pallas nested generators
//!   (honestly $x(O_1) \cdot G_i + y(O_1) \cdot G_j$; Ragu accepts other bridge
//!   hashes too). Every accepted bridge hash binds $O_1$ unless someone knows a
//!   discrete-log relation among the nested generators.
//! - **Value discrete log.** Under the Orchard `z.cash:Orchard-cv` generators
//!   $\mathcal{V}$ and $\mathcal{R}$, $\[v\]\mathcal{V} +
//!   \[\mathsf{rcv}\]\mathcal{R}$ hides $v$ perfectly and binds $v$ unless
//!   someone knows $\log_{\mathcal{V}} \mathcal{R}$.
//!
//! ## Element bindings
//!
//! ### Plain values
//!
//! - **`QrProfile`**: a path of `depth` sides. `QrProfile::descend` shifts each
//!   new side into the low bit of `bits`, so `(depth, bits)` is the path
//!   exactly.
//! - **`QrDiscriminant`**: the free $R_0$ a network classifies from; stands for
//!   itself.
//!
//! ### Notes, keys and nullifiers (Poseidon)
//!
//! - **`PaymentKey`**: `poseidon::payment_key` (`Tachyon-PkDerive`) on affine
//!   `ak` and `nk` binds `(ak, nk)`. `NoteSeed` derives `pk` in-circuit; an
//!   output's `pk` is the recipient's and binds the pair the recipient derived
//!   it from.
//! - **`NoteMasterKey`**: `poseidon::nf_master` (`Tachyon-NfMaster`) on $(\psi,
//!   \mathsf{nk})$ binds both.
//! - **`note::Commitment` and output `pad`**: `poseidon::note_commitment`
//!   (`Tachyon-CmDerive`) and `poseidon::pad_tachygram` (`Tachyon-CmOutPad`) on
//!   $(\mathsf{rcm}, \mathsf{pk}, v, \psi)$ each bind the note, and their tags
//!   keep pads apart from note commitments.
//! - **`Nullifier`**: for epoch $e$, entry $e \bmod 4$ of the four elements
//!   `poseidon::nullifier_group` (`Tachyon-NfDerive`) squeezes from `mk` and
//!   $e-(e \bmod 4)$. Group start and entry index determine $e$, binding `mk`
//!   and $e$.
//!
//! ### Value commitments (value discrete log)
//!
//! - **`value::Commitment`**: $\[v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}$
//!   at a spend and $\[-v\]\mathcal{V} + \[\mathsf{rcv}\]\mathcal{R}$ at an
//!   output. Values in `0..=MAX_MONEY` are distinct in $\mathbb{F}_q$ and the
//!   header's `SUFFIX` gives the sign, binding $v$.
//!
//! ### Sets and evidence trees (Poseidon, host and nested discrete log)
//!
//! - **`TachygramSetBridge`**: a bridge hash binding $O_1$, which binds its
//!   polynomial. Unique factorization fixes the root multiset of $\prod_i (X -
//!   t_i)$, and nonzero scaling leaves the roots unchanged, so equal bridge
//!   hashes give equal sets. Equal sets can have different bridge hashes: an
//!   in-circuit bridge hash need not be the honest one, and a QR bucket can
//!   hold a scaled polynomial (the book's "Scaled splits").
//! - **`EvidenceTreeRoot`**: a leaf (`poseidon::evidence_tree_leaf`, hashing a
//!   bucket's epoch, two anchors, discriminant, profile and two contents
//!   bridge-hash coordinates, eight elements under `Tachyon-QrBucket`) or a
//!   node (`poseidon::evidence_tree_node`, hashing four subtree roots under
//!   `Tachyon-EvidNode`). Tag and width separate leaves from nodes, so a root
//!   binds the whole tree, its shape and every bucket under Poseidon, plus each
//!   bucket's contents under host and nested discrete log. Where a bucket's
//!   anchors lie on the consensus chain, it binds the stamp sets in their
//!   histories too.
//!
//! ### Anchor histories
//!
//! An `Anchor` is either a **stamp fold** (`poseidon::anchor_next_stamp`,
//! hashing `(anchor_prev, epoch, x(B), y(B))` under `Tachyon-AnchorSt`) or a
//! **boundary digest** (`poseidon::anchor_next_epoch`, hashing `(anchor_prev,
//! epoch)` under `Tachyon-AnchorEp`). Under Poseidon, each fold binds its
//! inputs and, by its tag, which fold it is. An anchor on the consensus chain
//! binds the history of stamp bridge hashes and epoch crossings back to genesis
//! (and, under host and nested discrete log, every stamp's set) by induction on
//! the fold count:
//!
//! - **Base.** Genesis is $\mathsf{Poseidon}_{\texttt{Tachyon-AnchorEp}}(0,
//!   0)$. Stamp folds have another tag; `Anchor::next_epoch` rejects epoch $0$,
//!   so boundary digests enter an epoch $\ge 1$ with input $\ne (0, 0)$.
//!   Reproducing genesis is a Poseidon collision.
//! - **Step.** Two non-empty histories reaching the same anchor have equal
//!   final outputs, hence under Poseidon the same tag, inputs and previous
//!   anchor; dropping the final fold leaves shorter histories at that previous
//!   anchor. Repeating this, neither history can hit genesis first, since the
//!   other would reach genesis via a fold, contradicting the base case; thus
//!   both have the same length and folds.
//!
//! `Anchor::next_stamp` folds the honest bridge hash; an anchor folded
//! in-circuit from another bridge hash lies off the consensus chain. Some steps
//! take an anchor as a free witness. Such an anchor stands for a pool state
//! only when consensus accepts it or an anchor folded from it.

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
