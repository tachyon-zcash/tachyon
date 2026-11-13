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
use core::array;

use ragu::{
    header::{Header, Suffix},
    step::{Encoded, HeaderInput, Index, Oracles, Slot, Step},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    maybe::Maybe as _,
    pasta::Pasta,
};
use ragu_primitives::{Boolean, Element, GadgetExt as _, allocator::Allocator, io::Write};
use udon::curve::Affine as _;

use super::qr::QrBucket;
use crate::{
    constants::EVIDENCE_TREE_ARITY,
    digest::poseidon,
    pasta::{EpAffine, Fp},
    primitives::{
        Anchor, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, TachygramSetBridge,
        TachygramSetPoly,
    },
    ragu_constraint::enforce_zero,
    relations::enforce::enforce_poly_equal,
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

#[derive(Gadget, Write)]
pub struct EvidenceTreeOutput<'dr, D: Driver<'dr>> {
    pub epoch: Element<'dr, D>,
    pub anchor_start: Element<'dr, D>,
    pub anchor_next: Element<'dr, D>,
    pub discriminant: Element<'dr, D>,
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

#[derive(Gadget, Write)]
pub struct EvidenceTreePairOutput<'dr, D: Driver<'dr>> {
    pub epoch: Element<'dr, D>,
    pub anchor_start: Element<'dr, D>,
    pub anchor_next: Element<'dr, D>,
    pub discriminant: Element<'dr, D>,
    pub first: Element<'dr, D>,
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
/// Each digest uses the contents hash certified by
/// [`QrBucketSeal`](super::qr::QrBucketSeal) or [`EvidenceTreeOpen`]. The four
/// equalities carry the network fields as [`EvidenceTreePairFuse`] does.
/// The emitted pair holds two sealed buckets as leaves and claims nothing more.
#[derive(Debug)]
pub struct EvidenceTreeLeafPair;

impl Step<Pasta> for EvidenceTreeLeafPair {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = EvidenceTreePair;
    type Right = QrBucket;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(30);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        _oracles: &mut Oracles<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
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
        let bucket = left_encoded.as_gadget();
        let first = poseidon::circuit::evidence_tree_leaf(
            dr,
            &bucket.epoch,
            &bucket.anchor_start,
            &bucket.anchor_next,
            &bucket.discriminant,
            (&bucket.depth, &bucket.bits),
            &bucket.contents_hash,
        )?;
        let right_bucket = right_encoded.as_gadget();
        let second = poseidon::circuit::evidence_tree_leaf(
            dr,
            &right_bucket.epoch,
            &right_bucket.anchor_start,
            &right_bucket.anchor_next,
            &right_bucket.discriminant,
            (&right_bucket.depth, &right_bucket.bits),
            &right_bucket.contents_hash,
        )?;
        let output = D::try_just(|| {
            let (left_epoch, left_anchor_start, left_anchor_next, left_discriminant, ..) =
                left.take();
            let (right_epoch, right_anchor_start, right_anchor_next, right_discriminant, ..) =
                right.take();
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

            Ok((
                (
                    left_epoch,
                    left_anchor_start,
                    left_anchor_next,
                    left_discriminant,
                    EvidenceTreeRoot(*first.value().take()),
                    EvidenceTreeRoot(*second.value().take()),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        encoded.as_gadget().first.enforce_equal(dr, &first)?;
        encoded.as_gadget().second.enforce_equal(dr, &second)?;
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
        let left_pair = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let right_pair = right_encoded.as_gadget();
        let root = poseidon::circuit::evidence_tree_node(
            dr,
            &[
                left_pair.first.clone(),
                left_pair.second.clone(),
                right_pair.first.clone(),
                right_pair.second.clone(),
            ],
        )?;
        let output = D::try_just(|| {
            let () = witness.take();
            let (left_epoch, left_anchor_start, left_anchor_next, left_discriminant, ..) =
                left.take();
            let (right_epoch, right_anchor_start, right_anchor_next, right_discriminant, ..) =
                right.take();
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

            Ok((
                (
                    left_epoch,
                    left_anchor_start,
                    left_anchor_next,
                    left_discriminant,
                    EvidenceTreeRoot(*root.value().take()),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        encoded.as_gadget().root.enforce_equal(dr, &root)?;
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
        let raised = poseidon::circuit::evidence_tree_node(
            dr,
            &array::from_fn(|_| left_encoded.as_gadget().root.clone()),
        )?;
        let output = D::try_just(|| {
            let () = witness.take();
            let (epoch, anchor_start, anchor_next, discriminant, _) = left.take();
            let () = right.take();
            Ok((
                (
                    epoch,
                    anchor_start,
                    anchor_next,
                    discriminant,
                    EvidenceTreeRoot(*raised.value().take()),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        encoded.as_gadget().root.enforce_equal(dr, &raised)?;
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

    #[expect(
        clippy::indexing_slicing,
        reason = "four fixed path levels with four children per level"
    )]
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
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let mut node = left_encoded.as_gadget().root.clone();
        for level in 0..Self::LEVELS {
            let outer =
                Boolean::alloc(dr, &mut (), witness.as_ref().map(|path| path.0[level].0[0]))?;
            let inner =
                Boolean::alloc(dr, &mut (), witness.as_ref().map(|path| path.0[level].0[1]))?;
            let allocated = array::from_fn::<_, EVIDENCE_TREE_ARITY, _>(|child| {
                Element::alloc(
                    dr,
                    &mut (),
                    witness
                        .as_ref()
                        .map(|path| Fp::from(path.0[level].1[child])),
                )
            });
            let children = {
                let [first, second, third, fourth] = allocated;
                [first?, second?, third?, fourth?]
            };
            let hash = poseidon::circuit::evidence_tree_node(dr, &children)?;
            node.enforce_equal(dr, &hash).map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "EvidenceTreeDescend: children do not hash to the node".into(),
                )
            })?;
            let [first, second, third, fourth] = children;
            let lower = inner.conditional_select(dr, &first, &second)?;
            let upper = inner.conditional_select(dr, &third, &fourth)?;
            node = outer.conditional_select(dr, &lower, &upper)?;
        }
        let output = D::just(|| {
            let (epoch, anchor_start, anchor_next, discriminant, _) = left.take();
            (
                (
                    epoch,
                    anchor_start,
                    anchor_next,
                    discriminant,
                    EvidenceTreeRoot(*node.value().take()),
                ),
                (),
            )
        });
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        encoded.as_gadget().root.enforce_equal(dr, &node)?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}

/// Replay the [`QrBucket`] a one-leaf [`EvidenceTree`] holds.
///
/// Two permutations (the leaf digest).
/// O0/O1 hold the contents and open once each. O1's bridge hash enters the
/// leaf.
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
            witness.1.as_ref().iter_coeffs().collect(),
        ])
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D>,
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
        enforce_poly_equal(dr, oracles, Slot::output(0), Slot::output(1))?;
        let depth = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|data| Fp::from(u64::from(data.0.depth))),
        )?;
        let bits = Element::alloc(
            dr,
            &mut (),
            witness
                .as_ref()
                .map(|data| Fp::from(u64::from(data.0.bits))),
        )?;
        let tree = left_encoded.as_gadget();
        let leaf = poseidon::circuit::evidence_tree_leaf(
            dr,
            &tree.epoch,
            &tree.anchor_start,
            &tree.anchor_next,
            &tree.discriminant,
            (&depth, &bits),
            oracles.bridge_hash(),
        )?;
        leaf.enforce_equal(dr, &tree.root).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "EvidenceTreeOpen: witnessed bucket is not the tree's leaf".into(),
            )
        })?;
        let [hash_x, hash_y] = oracles.bridge_hash().each_ref().map(Element::value);
        let output = D::try_just(|| {
            let (profile, _) = witness.take();
            let contents_hash =
                EpAffine::from_xy(*hash_x.take(), *hash_y.take()).ok_or_else(|| {
                    ragu_core::Error::InvalidWitness(
                        "EvidenceTreeOpen: bridge hash is not on the curve".into(),
                    )
                })?;
            if contents_hash.is_identity() {
                return Err(ragu_core::Error::InvalidWitness(
                    "EvidenceTreeOpen: bridge hash is the identity".into(),
                ));
            }
            let (epoch, anchor_start, anchor_next, discriminant, _) = left.take();
            let () = right.take();

            Ok((
                (
                    epoch,
                    anchor_start,
                    anchor_next,
                    discriminant,
                    profile,
                    TachygramSetBridge::from(contents_hash),
                ),
                (),
            ))
        })?;
        let (data, aux) = output.cast();
        let encoded = Encoded::<D, Self::Output, HEADER_SIZE>::new(dr, &mut (), data.clone())?;
        for (output_hash, oracle_hash) in encoded
            .as_gadget()
            .contents_hash
            .iter()
            .zip(oracles.bridge_hash())
        {
            output_hash.enforce_equal(dr, oracle_hash)?;
        }
        encoded.as_gadget().depth.enforce_equal(dr, &depth)?;
        encoded.as_gadget().bits.enforce_equal(dr, &bits)?;
        Ok(((left_encoded, right_encoded, encoded), data, aux))
    }
}
