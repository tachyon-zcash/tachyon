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

use alloc::vec::Vec;

use ragu::{
    header::{Header, Suffix},
    step::{Encoded, HeaderInput, Index, Oracles, Step},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::Pasta,
};
use ragu_primitives::{Element, allocator::Allocator, io::Write};
use udon::{curve::Projective as _, field::Field as _};

use super::qr::QrBucket;
use crate::{
    constants::EVIDENCE_TREE_ARITY,
    digest::poseidon,
    pasta::{Eq, Fp},
    primitives::{
        Anchor, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, TachygramSetPoly,
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

/// `EvidenceTree` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct EvidenceTreeOutput<'dr, D: Driver<'dr>> {
    /// `epoch`.
    pub epoch: Element<'dr, D>,
    /// `anchor_start`.
    pub anchor_start: Element<'dr, D>,
    /// `anchor_next`.
    pub anchor_next: Element<'dr, D>,
    /// `discriminant`.
    pub discriminant: Element<'dr, D>,
    /// `root`.
    pub root: Element<'dr, D>,
}

impl Header<Fp> for EvidenceTree {
    /// `(epoch, anchor_start, anchor_next, discriminant, root)`
    type Data = (EpochIndex, Anchor, Anchor, QrDiscriminant, EvidenceTreeRoot);
    type Output = Kind![Fp; EvidenceTreeOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(EvidenceTreeOutput {
            epoch: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?,
            discriminant: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.3)),
            )?,
            root: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.4)),
            )?,
        })
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

/// `EvidenceTreePair` gadget.
#[derive(Gadget, Write)]
#[expect(
    missing_debug_implementations,
    reason = "gadgets do not implement Debug"
)]
pub struct EvidenceTreePairOutput<'dr, D: Driver<'dr>> {
    /// `epoch`.
    pub epoch: Element<'dr, D>,
    /// `anchor_start`.
    pub anchor_start: Element<'dr, D>,
    /// `anchor_next`.
    pub anchor_next: Element<'dr, D>,
    /// `discriminant`.
    pub discriminant: Element<'dr, D>,
    /// `first`.
    pub first: Element<'dr, D>,
    /// `second`.
    pub second: Element<'dr, D>,
}

impl Header<Fp> for EvidenceTreePair {
    /// `(epoch, anchor_start, anchor_next, discriminant, first, second)`
    type Data = (
        EpochIndex,
        Anchor,
        Anchor,
        QrDiscriminant,
        EvidenceTreeRoot,
        EvidenceTreeRoot,
    );
    type Output = Kind![Fp; EvidenceTreePairOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(13);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu_core::Result<Bound<'dr, D, Self::Output>> {
        Ok(EvidenceTreePairOutput {
            epoch: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.0)),
            )?,
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.1)),
            )?,
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.2)),
            )?,
            discriminant: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.3)),
            )?,
            first: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.4)),
            )?,
            second: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|fields| Fp::from(fields.5)),
            )?,
        })
    }
}

/// Admit two sealed [`QrBucket`]s as one half of a node.
///
/// Four permutations (two leaf digests). The two sponges absorb the same four
/// network fields and share nothing. This step both admits a bucket and
/// consumes two proofs, which is what holds a tree over `n` buckets to `n - 1`
/// steps.
///
/// # Soundness
///
/// Each digest is derived from one threaded bucket header, and the four
/// equalities carry the network fields as [`EvidenceTreePairFuse`] does. The
/// emitted pair holds two sealed buckets as leaves and claims nothing more.
#[derive(Debug)]
pub struct EvidenceTreeLeafPair;

impl Step<Pasta> for EvidenceTreeLeafPair {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = EvidenceTreePair;
    type Right = QrBucket;
    /// `(left_contents, right_contents)`
    type Witness<'source> = (TachygramSetPoly, TachygramSetPoly);

    const INDEX: Index = Index::new(30);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let (left_contents, right_contents) = witness.take();
            let (left_epoch, left_anchor_start, left_anchor_next, left_discriminant, left_profile) =
                left.take();
            let (
                right_epoch,
                right_anchor_start,
                right_anchor_next,
                right_discriminant,
                right_profile,
            ) = right.take();
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
                Eq::from(left_contents.commit()).to_affine(),
            ));
            let second = EvidenceTreeRoot(poseidon::evidence_tree_leaf(
                Fp::from(right_epoch),
                Fp::from(right_anchor_start),
                Fp::from(right_anchor_next),
                Fp::from(right_discriminant),
                Fp::from(u64::from(right_profile.depth)),
                Fp::from(u64::from(right_profile.bits)),
                Eq::from(right_contents.commit()).to_affine(),
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
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
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

impl Step<Pasta> for EvidenceTreePairFuse {
    type Aux<'source> = ();
    type Left = EvidenceTree;
    type Output = EvidenceTreePair;
    type Right = EvidenceTree;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(25);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let () = witness.take();
            let (left_epoch, left_anchor_start, left_anchor_next, left_discriminant, left_root) =
                left.take();
            let (
                right_epoch,
                right_anchor_start,
                right_anchor_next,
                right_discriminant,
                right_root,
            ) = right.take();
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
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
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

impl Step<Pasta> for EvidenceTreeFuse {
    type Aux<'source> = ();
    type Left = EvidenceTreePair;
    type Output = EvidenceTree;
    type Right = EvidenceTreePair;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(26);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let () = witness.take();
            let (
                left_epoch,
                left_anchor_start,
                left_anchor_next,
                left_discriminant,
                left_first,
                left_second,
            ) = left.take();
            let (
                right_epoch,
                right_anchor_start,
                right_anchor_next,
                right_discriminant,
                right_first,
                right_second,
            ) = right.take();
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
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
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

impl Step<Pasta> for EvidenceTreeCap {
    type Aux<'source> = ();
    type Left = EvidenceTree;
    type Output = EvidenceTree;
    type Right = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(27);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let () = witness.take();
            let (epoch, anchor_start, anchor_next, discriminant, root) = left.take();
            let () = right.take();
            let raised = EvidenceTreeRoot(poseidon::evidence_tree_node(
                [Fp::from(root); EVIDENCE_TREE_ARITY],
            ));

            Ok(((epoch, anchor_start, anchor_next, discriminant, raised), ()))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
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
/// tree, so the claim survives the descent. Leaf and node digests use different
/// domains, `Tachyon-QrBucket` and `Tachyon-EvidNode`, so a path cannot stop
/// one level short and present a node as a bucket.
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

impl Step<Pasta> for EvidenceTreeDescend {
    type Aux<'source> = ();
    type Left = EvidenceTree;
    type Output = EvidenceTree;
    type Right = ();
    /// `(path)`
    type Witness<'source> = ([([bool; 2], [EvidenceTreeRoot; EVIDENCE_TREE_ARITY]); Self::LEVELS],);

    const INDEX: Index = Index::new(28);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let (path,) = witness.take();
            let (epoch, anchor_start, anchor_next, discriminant, root) = left.take();
            let () = right.take();
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
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Replay the [`QrBucket`] a one-leaf [`EvidenceTree`] holds.
///
/// Two permutations (the leaf digest).
///
/// # Soundness
///
/// The witnessed profile and contents commitment are pinned jointly to `root`
/// by the leaf digest. `root` is a leaf digest and not a node: leaf and node
/// digests use different domains, `Tachyon-QrBucket` and `Tachyon-EvidNode`,
/// and a descent stopped short leaves a node no preimage opens. Preimage
/// resistance then makes the emitted header one
/// [`QrBucketSeal`](super::qr::QrBucketSeal) emitted, so this second producer
/// of [`QrBucket`] establishes nothing the seal did not.
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

impl Step<Pasta> for EvidenceTreeOpen {
    type Aux<'source> = ();
    type Left = EvidenceTree;
    type Output = QrBucket;
    type Right = ();
    /// `(profile, contents)`
    type Witness<'source> = (QrProfile, TachygramSetPoly);

    const INDEX: Index = Index::new(29);

    fn polynomials(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu_core::Result<[Vec<Fp>; 2]> {
        Ok([
            witness.1.as_ref().iter_coeffs().collect(),
            alloc::vec![Fp::ONE],
        ])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        DriverValue<D, <Self::Output as Header<Fp>>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded = Encoded::<D, Self::Left, HEADER_SIZE>::new(dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let output = D::try_just(|| {
            let (profile, contents_poly) = witness.take();
            let contents = contents_poly.commit();
            let (epoch, anchor_start, anchor_next, discriminant, root) = left.take();
            let () = right.take();
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
                (epoch, anchor_start, anchor_next, discriminant, profile),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}
