//! Evidence trees: one proof for a Poseidon Merkle root over a network's
//! sealed [`QrBucket`]s.
//!
//! [`EvidenceTreeLeafPair`] admits buckets two at a time,
//! [`EvidenceTreePairFuse`] and [`EvidenceTreeFuse`] assemble a node from
//! four subtrees, and [`EvidenceTreeCap`] raises a root to the depth a descent
//! needs. [`EvidenceTreeDescend`] walks a path, and [`EvidenceTreeOpen`]
//! replays the bucket a leaf holds.
//!
//! A tree starts at [`EVIDENCE_TREE_ARITY`] leaves. A builder short of that
//! repeats a bucket. A builder holding one bucket needs no tree at all: it
//! serves that bucket's own proof, which every consumer of a replayed bucket
//! takes unchanged.

extern crate alloc;

use alloc::{vec, vec::Vec};

use group::Curve as _;
use pasta_curves::{Ep, Eq, Fp, Fq};
use ragu::{Header, Index, Step, Suffix};

use super::qr::QrBucket;
use crate::{
    constants::EVIDENCE_TREE_ARITY,
    digest::poseidon,
    primitives::{
        Anchor, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, TachygramSetCommit,
    },
    ragu_constraint::enforce_zero,
};

/// A Poseidon Merkle root over one network's sealed buckets.
///
/// Every leaf under `root` is the [`poseidon::evidence_tree_leaf`] of a bucket
/// whose own `(epoch, anchor_start, anchor_next, discriminant)` are the four
/// this header carries. A one-leaf tree's root is that leaf's digest, and
/// [`EvidenceTreeDescend`] is what produces one.
///
/// The tree claims nothing about which buckets it holds. A tree holding one
/// bucket four times is as valid as a tree over a whole network, and a builder
/// that omits a bucket can only fail to answer for it. Each bucket's exclusion
/// claim already covers the whole epoch.
#[derive(Clone, Debug)]
pub struct EvidenceTree;

impl Header for EvidenceTree {
    /// `(epoch, anchor_start, anchor_next, discriminant, root)`
    type Data = (EpochIndex, Anchor, Anchor, QrDiscriminant, EvidenceTreeRoot);

    const SUFFIX: Suffix = Suffix::new(13);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_start, anchor_next, discriminant, root) = *data;
        (
            vec![
                Fp::from(epoch),
                Fp::from(anchor_start),
                Fp::from(anchor_next),
                Fp::from(discriminant),
                Fp::from(root),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Two sibling subtree roots of one network: half of a node.
///
/// A [`EVIDENCE_TREE_ARITY`]-child node reaches one hash through two steps,
/// since a [`Step`] takes at most two predecessor proofs. This header is a node
/// half-assembled: the left and right children of one side, under the four
/// network fields both already agree on.
#[derive(Clone, Debug)]
pub struct EvidenceTreePair;

impl Header for EvidenceTreePair {
    /// `(epoch, anchor_start, anchor_next, discriminant, first, second)`
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        EvidenceTreeRoot,
        EvidenceTreeRoot,
    );

    const SUFFIX: Suffix = Suffix::new(14);

    fn encode(data: &Self::Data) -> (Vec<Fp>, Vec<Fq>, Vec<Ep>, Vec<Eq>) {
        let (epoch, anchor_start, anchor_next, discriminant, first, second) = *data;
        (
            vec![
                Fp::from(epoch),
                Fp::from(anchor_start),
                Fp::from(anchor_next),
                Fp::from(discriminant),
                Fp::from(first),
                Fp::from(second),
            ],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

/// Admit two sealed [`QrBucket`]s as one half of a node.
///
/// Six permutations (two leaf digests), more than any other step in this
/// module. The two sponges absorb the same four network fields and share
/// nothing. A circuit that cannot afford both would split this into a step per
/// digest, at the cost of one more step per bucket: this step both admits a
/// bucket and consumes two proofs, which is what holds a tree over `n` buckets
/// to `n - 1` steps.
///
/// # Soundness
///
/// Each digest is derived from one threaded bucket header, and the four
/// equalities carry the network fields as [`EvidenceTreePairFuse`] does. The
/// emitted pair holds two sealed buckets as leaves and claims nothing more.
#[derive(Debug)]
pub struct EvidenceTreeLeafPair;

impl Step for EvidenceTreeLeafPair {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = EvidenceTreePair;
    type Right = QrBucket;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(32);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (): Self::Witness<'source>,
        (
            left_epoch,
            left_anchor_start,
            left_anchor_next,
            left_discriminant,
            left_profile,
            left_contents,
        ): <Self::Left as Header>::Data,
        (
            right_epoch,
            right_anchor_start,
            right_anchor_next,
            right_discriminant,
            right_profile,
            right_contents,
        ): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_epoch) - Fp::from(right_epoch),
            "EvidenceTreeLeafPair: inputs cover different epochs",
        )?;
        enforce_zero(
            Fp::from(left_anchor_start) - Fp::from(right_anchor_start),
            "EvidenceTreeLeafPair: inputs open at different anchors",
        )?;
        enforce_zero(
            Fp::from(left_anchor_next) - Fp::from(right_anchor_next),
            "EvidenceTreeLeafPair: inputs close at different anchors",
        )?;
        enforce_zero(
            Fp::from(left_discriminant) - Fp::from(right_discriminant),
            "EvidenceTreeLeafPair: inputs derive from different discriminants",
        )?;

        let first = EvidenceTreeRoot(poseidon::evidence_tree_leaf(
            Fp::from(left_epoch),
            Fp::from(left_anchor_start),
            Fp::from(left_anchor_next),
            Fp::from(left_discriminant),
            Fp::from(u64::from(left_profile.depth)),
            Fp::from(u64::from(left_profile.bits)),
            Eq::from(left_contents).to_affine(),
        ));
        let second = EvidenceTreeRoot(poseidon::evidence_tree_leaf(
            Fp::from(right_epoch),
            Fp::from(right_anchor_start),
            Fp::from(right_anchor_next),
            Fp::from(right_discriminant),
            Fp::from(u64::from(right_profile.depth)),
            Fp::from(u64::from(right_profile.bits)),
            Eq::from(right_contents).to_affine(),
        ));

        Ok((
            (
                left_epoch,
                left_anchor_start,
                left_anchor_next,
                left_discriminant,
                first,
                second,
            ),
            (),
        ))
    }
}

/// Pair two [`EvidenceTree`]s of one network as half a node.
///
/// No permutations.
///
/// # Soundness
///
/// Both roots are threaded, and the four equalities make the emitted header's
/// network fields true of every leaf beneath either input. The fields are
/// checked equal because a consumer reads the extent off the tree, so a tree
/// spanning more than its leaves do would let a bucket's exclusion cover folds
/// the bucket never held.
///
/// Nothing is hashed here. The pair asserts only that two subtrees belong to
/// one network; [`EvidenceTreeFuse`] is what turns four of them into a node.
#[derive(Debug)]
pub struct EvidenceTreePairFuse;

impl Step for EvidenceTreePairFuse {
    type Aux<'source> = ();
    type Left = EvidenceTree;
    type Output = EvidenceTreePair;
    type Right = EvidenceTree;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(27);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (): Self::Witness<'source>,
        (left_epoch, left_anchor_start, left_anchor_next, left_discriminant, left_root): <Self::Left as Header>::Data,
        (right_epoch, right_anchor_start, right_anchor_next, right_discriminant, right_root): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_epoch) - Fp::from(right_epoch),
            "EvidenceTreePairFuse: inputs cover different epochs",
        )?;
        enforce_zero(
            Fp::from(left_anchor_start) - Fp::from(right_anchor_start),
            "EvidenceTreePairFuse: inputs open at different anchors",
        )?;
        enforce_zero(
            Fp::from(left_anchor_next) - Fp::from(right_anchor_next),
            "EvidenceTreePairFuse: inputs close at different anchors",
        )?;
        enforce_zero(
            Fp::from(left_discriminant) - Fp::from(right_discriminant),
            "EvidenceTreePairFuse: inputs derive from different discriminants",
        )?;

        Ok((
            (
                left_epoch,
                left_anchor_start,
                left_anchor_next,
                left_discriminant,
                left_root,
                right_root,
            ),
            (),
        ))
    }
}

/// Hash two [`EvidenceTreePair`]s of one network into a node.
///
/// The children are ordered `(left.0, left.1, right.0, right.1)`, which is the
/// order [`EvidenceTreeDescend`] witnesses them in.
///
/// One permutation (the node).
///
/// # Soundness
///
/// All four roots are threaded, and the four equalities carry the network
/// fields as [`EvidenceTreePairFuse`] does. Every leaf beneath the emitted root
/// was beneath one of the four inputs, so the claim carries by induction.
#[derive(Debug)]
pub struct EvidenceTreeFuse;

impl Step for EvidenceTreeFuse {
    type Aux<'source> = ();
    type Left = EvidenceTreePair;
    type Output = EvidenceTree;
    type Right = EvidenceTreePair;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(28);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (): Self::Witness<'source>,
        (
            left_epoch,
            left_anchor_start,
            left_anchor_next,
            left_discriminant,
            left_first,
            left_second,
        ): <Self::Left as Header>::Data,
        (
            right_epoch,
            right_anchor_start,
            right_anchor_next,
            right_discriminant,
            right_first,
            right_second,
        ): <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(left_epoch) - Fp::from(right_epoch),
            "EvidenceTreeFuse: inputs cover different epochs",
        )?;
        enforce_zero(
            Fp::from(left_anchor_start) - Fp::from(right_anchor_start),
            "EvidenceTreeFuse: inputs open at different anchors",
        )?;
        enforce_zero(
            Fp::from(left_anchor_next) - Fp::from(right_anchor_next),
            "EvidenceTreeFuse: inputs close at different anchors",
        )?;
        enforce_zero(
            Fp::from(left_discriminant) - Fp::from(right_discriminant),
            "EvidenceTreeFuse: inputs derive from different discriminants",
        )?;

        let root = EvidenceTreeRoot(poseidon::evidence_tree_node([
            Fp::from(left_first),
            Fp::from(left_second),
            Fp::from(right_first),
            Fp::from(right_second),
        ]));

        Ok((
            (
                left_epoch,
                left_anchor_start,
                left_anchor_next,
                left_discriminant,
                root,
            ),
            (),
        ))
    }
}

/// Raise a [`EvidenceTree`] one level by making its root the only child of a
/// new root.
///
/// [`EvidenceTreeDescend`] walks [`EvidenceTreeDescend::LEVELS`] levels at a
/// time. A builder caps a tree at most `LEVELS - 1` times, until its depth is a
/// multiple of that.
///
/// One permutation (the node).
///
/// # Soundness
///
/// The root is threaded and repeated into every child slot, so the input tree
/// is the only subtree beneath the emitted root and raising a tree cannot admit
/// a leaf. A descent through such a node selects the same child whichever side
/// bits it reads.
#[derive(Debug)]
pub struct EvidenceTreeCap;

impl Step for EvidenceTreeCap {
    type Aux<'source> = ();
    type Left = EvidenceTree;
    type Output = EvidenceTree;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(29);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (): Self::Witness<'source>,
        (epoch, anchor_start, anchor_next, discriminant, root): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        let raised = EvidenceTreeRoot(poseidon::evidence_tree_node(
            [Fp::from(root); EVIDENCE_TREE_ARITY],
        ));

        Ok(((epoch, anchor_start, anchor_next, discriminant, raised), ()))
    }
}

/// Walk [`LEVELS`](Self::LEVELS) levels of a Merkle path, emitting the subtree
/// the path reaches.
///
/// Each level is a node's children, ordered as the node hashes them, and two
/// side bits, outer first: the outer bit selects a half and the inner bit
/// selects within it.
///
/// Four permutations (one node per level).
///
/// # Soundness
///
/// `node` starts threaded, each level's children are pinned to it by the node
/// hash, and the emitted root is one of the four children of a node reached
/// that way. Every leaf beneath a subtree of a valid tree is a leaf of that
/// tree, so the claim survives the descent. A leaf digest absorbs nine
/// elements and a node four, so a path cannot stop one level short and present
/// a node as a bucket.
#[derive(Debug)]
pub struct EvidenceTreeDescend;

impl EvidenceTreeDescend {
    /// The levels one descent covers.
    ///
    /// A path of `depth` levels takes `⌈depth / LEVELS⌉` descents, so a
    /// builder pads its tree to a multiple of this. A profile addresses at
    /// most $\mathsf{MAX\_DEPTH} / 2$ quaternary levels, which is a multiple of
    /// `LEVELS`, so the deepest reachable tree needs no padding.
    pub const LEVELS: usize = 4;
}

const _: () = assert!(
    QrProfile::MAX_DEPTH.is_multiple_of(2 * EvidenceTreeDescend::LEVELS),
    "a descent's levels must divide the quaternary levels a profile can address"
);

impl Step for EvidenceTreeDescend {
    type Aux<'source> = ();
    type Left = EvidenceTree;
    type Output = EvidenceTree;
    type Right = ();
    /// `(path)`
    type Witness<'source> = ([([bool; 2], [EvidenceTreeRoot; EVIDENCE_TREE_ARITY]); Self::LEVELS],);

    const INDEX: Index = Index::new(30);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (path,): Self::Witness<'source>,
        (epoch, anchor_start, anchor_next, discriminant, root): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        // TODO: a real circuit must constrain each side bit to a boolean. The
        // selection below is exact for boolean bits and is the bilinear surface
        // through the four children otherwise, so free field elements would
        // reach values that are no child of the node.
        let mut node = Fp::from(root);
        for ([outer, inner], children) in path {
            let [first, second, third, fourth] = children.map(Fp::from);
            enforce_zero(
                node - poseidon::evidence_tree_node([first, second, third, fourth]),
                "EvidenceTreeDescend: children do not hash to the node",
            )?;

            let outer_side = Fp::from(u64::from(outer));
            let inner_side = Fp::from(u64::from(inner));
            let lower = first + inner_side * (second - first);
            let upper = third + inner_side * (fourth - third);
            node = lower + outer_side * (upper - lower);
        }

        Ok((
            (
                epoch,
                anchor_start,
                anchor_next,
                discriminant,
                EvidenceTreeRoot(node),
            ),
            (),
        ))
    }
}

/// Replay the [`QrBucket`] a one-leaf [`EvidenceTree`] holds.
///
/// Three permutations (the leaf digest).
///
/// # Soundness
///
/// The witnessed profile and contents commitment are pinned jointly to `root`
/// by the leaf digest. `root` is a leaf digest and not a node: a leaf absorbs
/// nine elements and a node four, so the two digests never coincide, and a
/// descent stopped short leaves a node no preimage opens. Preimage resistance
/// then makes the emitted header one [`QrBucketSeal`](super::qr::QrBucketSeal)
/// emitted, so this second producer of [`QrBucket`] establishes nothing the
/// seal did not.
///
/// Only [`EvidenceTreeDescend`] emits a tree whose root is a leaf digest, so
/// every open follows a descent.
///
/// Binding the profile stops this forgery: a real bucket's
/// contents presented under the tested value's own profile would pass
/// [`QrUnspentInit`](super::qr::QrUnspentInit)'s fold and open nonzero, proving
/// exclusion for a value published in a different bucket.
#[derive(Debug)]
pub struct EvidenceTreeOpen;

impl Step for EvidenceTreeOpen {
    type Aux<'source> = ();
    type Left = EvidenceTree;
    type Output = QrBucket;
    type Right = ();
    /// `(profile, contents)`
    type Witness<'source> = (QrProfile, TachygramSetCommit);

    const INDEX: Index = Index::new(31);

    fn witness<'source>(
        &self,
        _ctx: &mut ragu::StepCtx<'_>,
        (profile, contents): Self::Witness<'source>,
        (epoch, anchor_start, anchor_next, discriminant, root): <Self::Left as Header>::Data,
        _right: <Self::Right as Header>::Data,
    ) -> ragu_core::Result<(<Self::Output as Header>::Data, Self::Aux<'source>)> {
        enforce_zero(
            Fp::from(root)
                - poseidon::evidence_tree_leaf(
                    Fp::from(epoch),
                    Fp::from(anchor_start),
                    Fp::from(anchor_next),
                    Fp::from(discriminant),
                    Fp::from(u64::from(profile.depth)),
                    Fp::from(u64::from(profile.bits)),
                    Eq::from(contents).to_affine(),
                ),
            "EvidenceTreeOpen: witnessed bucket is not the tree's leaf",
        )?;

        Ok((
            (
                epoch,
                anchor_start,
                anchor_next,
                discriminant,
                profile,
                contents,
            ),
            (),
        ))
    }
}
