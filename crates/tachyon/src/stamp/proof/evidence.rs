//! Evidence trees: one proof for a Poseidon Merkle root over a network's
//! sealed [`QrBucket`]s.
//!
//! Pair and fuse steps assemble [`EVIDENCE_TREE_ARITY`]-child nodes; capping
//! pads the depth for descent and replay. A tree needs at least four leaves,
//! so builders may repeat buckets. With just one bucket they can serve its
//! proof directly to any consumer of a replayed bucket.

use core::array;

use ragu::{
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget, Kind},
    header::{Header, Padding, Suffix},
    maybe::Maybe as _,
    pasta::Pasta,
    primitives::{Boolean, Element, GadgetExt as _, allocator::Allocator, io::Write},
    step::{Encoded, HeaderInput, Index, Oracles, Prepared, Step},
    udon::curve::Affine as _,
};

use super::qr::{QrBucket, QrBucketOutput};
use crate::{
    constants::EVIDENCE_TREE_ARITY,
    digest::poseidon,
    gadgets,
    pasta::{EpAffine, Fp},
    primitives::{
        Anchor, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, TachygramSetBridge,
        TachygramSetPoly,
    },
};

/// A Poseidon Merkle root over one network's sealed buckets.
///
/// A one-leaf tree's root is that leaf's digest, produced when
/// [`EvidenceTreeDescend`] reaches a leaf rather than an internal subtree.
///
/// # Injectivity
///
/// [`EvidenceTreeFuse`], [`EvidenceTreeCap`] and [`EvidenceTreeDescend`] output
/// this header. Every verified `EvidenceTree` asserts that `root` is *valid*
/// for its four network fields `(epoch, anchor_start, anchor_next,
/// discriminant)`, saying nothing about bucket selection, count or placement.
/// Each bucket's assertion stands independently of the rest of the tree.
///
/// Two rules define the least set of valid elements for given network fields.
///
/// - The [leaf digest](poseidon::evidence_tree_leaf) of the eight header
///   elements of a verified [`QrBucket`] matching those network fields is
///   valid.
/// - The [node digest](poseidon::evidence_tree_node) of four elements valid for
///   those network fields is valid.
///
/// No valid element is known as both a leaf digest and a node digest, and each
/// [determines what it absorbed](EvidenceTreeRoot#injectivity). Because
/// [`EvidenceTreeOpen`] reproduces the header and contents of the bucket behind
/// a leaf, induction over the step tree traces every leaf behind a valid
/// element to a header emitted by [`QrBucketSeal`](super::qr::QrBucketSeal).
#[derive(Clone, Debug)]
pub struct EvidenceTree;

#[derive(Gadget, Write)]
pub struct EvidenceTreeOutput<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub epoch: gadgets::epoch::EpochIndex<'dr, D>,
    pub anchor_start: Element<'dr, D>,
    pub anchor_next: Element<'dr, D>,
    pub discriminant: Element<'dr, D>,
    pub root: Element<'dr, D>,
}

impl Header<Fp> for EvidenceTree {
    /// `(epoch, anchor_start, anchor_next, discriminant, root)`
    type Data = (EpochIndex, Anchor, Anchor, QrDiscriminant, EvidenceTreeRoot);
    type OnlinePolyCommit = (Padding, Padding);
    type Output = Kind![Fp; EvidenceTreeOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(12);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(EvidenceTreeOutput {
            epoch: gadgets::epoch::EpochIndex::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(epoch, ..)| epoch),
            )?,
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(_, anchor_start, ..)| Fp::from(anchor_start)),
            )?,
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(_, _, anchor_next, ..)| Fp::from(anchor_next)),
            )?,
            discriminant: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(.., discriminant, _)| Fp::from(discriminant)),
            )?,
            root: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(.., root)| Fp::from(root)),
            )?,
        })
    }
}

/// Two sibling subtree roots of one network: half of a node.
///
/// A [`Step`] takes at most two inputs, so one four-way node needs two pairs.
///
/// # Injectivity
///
/// [`EvidenceTreeLeafPair`] and [`EvidenceTreePairFuse`] output this header.
/// Every verified `EvidenceTreePair` asserts that `first` and `second` are each
/// [valid](EvidenceTree#injectivity) for its network fields, without relating
/// the two.
#[derive(Clone, Debug)]
pub struct EvidenceTreePair;

#[derive(Gadget, Write)]
pub struct EvidenceTreePairOutput<'dr, D: Driver<'dr>> {
    #[ragu(gadget)]
    pub epoch: gadgets::epoch::EpochIndex<'dr, D>,
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
    type OnlinePolyCommit = (Padding, Padding);
    type Output = Kind![Fp; EvidenceTreePairOutput<'_, _>];

    const SUFFIX: Suffix = Suffix::new(13);

    fn encode<'dr, D: Driver<'dr, F = Fp>, A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        witness: DriverValue<D, Self::Data>,
    ) -> ragu::Result<Bound<'dr, D, Self::Output>> {
        Ok(EvidenceTreePairOutput {
            epoch: gadgets::epoch::EpochIndex::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(epoch, ..)| epoch),
            )?,
            anchor_start: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(_, anchor_start, ..)| Fp::from(anchor_start)),
            )?,
            anchor_next: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(_, _, anchor_next, ..)| Fp::from(anchor_next)),
            )?,
            discriminant: Element::alloc(
                dr,
                allocator,
                witness
                    .as_ref()
                    .map(|&(_, _, _, discriminant, ..)| Fp::from(discriminant)),
            )?,
            first: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(.., first, _)| Fp::from(first)),
            )?,
            second: Element::alloc(
                dr,
                allocator,
                witness.as_ref().map(|&(.., second)| Fp::from(second)),
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
/// The circuit equates and copies the network fields. Hashing each bucket's
/// eight elements in header order gives two valid leaves for that network.
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
        _oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let left_bucket = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let right_bucket = right_encoded.as_gadget();
        for (left_element, right_element) in [
            (&*left_bucket.epoch, &*right_bucket.epoch),
            (&left_bucket.anchor_start, &right_bucket.anchor_start),
            (&left_bucket.anchor_next, &right_bucket.anchor_next),
            (&left_bucket.discriminant, &right_bucket.discriminant),
        ] {
            left_element.enforce_equal(dr, right_element)?;
        }
        let first = poseidon::circuit::evidence_tree_leaf(
            dr,
            &left_bucket.epoch,
            &left_bucket.anchor_start,
            &left_bucket.anchor_next,
            &left_bucket.discriminant,
            (&left_bucket.profile.depth, &left_bucket.profile.bits),
            &left_bucket.contents_hash,
        )?;
        let second = poseidon::circuit::evidence_tree_leaf(
            dr,
            &right_bucket.epoch,
            &right_bucket.anchor_start,
            &right_bucket.anchor_next,
            &right_bucket.discriminant,
            (&right_bucket.profile.depth, &right_bucket.profile.bits),
            &right_bucket.contents_hash,
        )?;
        let output = D::just(|| {
            let (epoch, anchor_start, anchor_next, discriminant, ..) = left.take();
            (
                epoch,
                anchor_start,
                anchor_next,
                discriminant,
                EvidenceTreeRoot(*first.value().take()),
                EvidenceTreeRoot(*second.value().take()),
            )
        });
        let fields = EvidenceTreePairOutput {
            epoch: left_bucket.epoch.clone(),
            anchor_start: left_bucket.anchor_start.clone(),
            anchor_next: left_bucket.anchor_next.clone(),
            discriminant: left_bucket.discriminant.clone(),
            first,
            second,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}

/// Pair two [`EvidenceTree`]s of one network as half a node.
///
/// No permutations.
///
/// # Soundness
///
/// Matching and copying the network fields preserves the validity of both
/// roots, copied as `first` and `second`.
/// [`EvidenceTreeOpen`] binds a replayed bucket to those network fields by
/// hashing them into its leaf digest and checking that digest against the root.
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
        _oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let left_tree = left_encoded.as_gadget();
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right.clone())?;
        let right_tree = right_encoded.as_gadget();
        for (left_element, right_element) in [
            (&*left_tree.epoch, &*right_tree.epoch),
            (&left_tree.anchor_start, &right_tree.anchor_start),
            (&left_tree.anchor_next, &right_tree.anchor_next),
            (&left_tree.discriminant, &right_tree.discriminant),
        ] {
            left_element.enforce_equal(dr, right_element)?;
        }
        let output = D::just(|| {
            let (epoch, anchor_start, anchor_next, discriminant, root) = left.take();
            let (.., right_root) = right.take();
            (
                epoch,
                anchor_start,
                anchor_next,
                discriminant,
                root,
                right_root,
            )
        });
        let fields = EvidenceTreePairOutput {
            epoch: left_tree.epoch.clone(),
            anchor_start: left_tree.anchor_start.clone(),
            anchor_next: left_tree.anchor_next.clone(),
            discriminant: left_tree.discriminant.clone(),
            first: left_tree.root.clone(),
            second: right_tree.root.clone(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}

/// Hash two [`EvidenceTreePair`]s of one network into a node.
///
/// One permutation (the node).
///
/// # Soundness
///
/// Matching and copying the network fields gives four valid roots for one
/// network. Their node digest in `(left.0, left.1, right.0, right.1)` order
/// is valid by [`EvidenceTree`]'s node rule and matches descent order.
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
        _oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        for (left_element, right_element) in [
            (&*left_pair.epoch, &*right_pair.epoch),
            (&left_pair.anchor_start, &right_pair.anchor_start),
            (&left_pair.anchor_next, &right_pair.anchor_next),
            (&left_pair.discriminant, &right_pair.discriminant),
        ] {
            left_element.enforce_equal(dr, right_element)?;
        }
        let root = poseidon::circuit::evidence_tree_node(
            dr,
            &[
                left_pair.first.clone(),
                left_pair.second.clone(),
                right_pair.first.clone(),
                right_pair.second.clone(),
            ],
        )?;
        let output = D::just(|| {
            let (epoch, anchor_start, anchor_next, discriminant, ..) = left.take();
            (
                epoch,
                anchor_start,
                anchor_next,
                discriminant,
                EvidenceTreeRoot(*root.value().take()),
            )
        });
        let fields = EvidenceTreeOutput {
            epoch: left_pair.epoch.clone(),
            anchor_start: left_pair.anchor_start.clone(),
            anchor_next: left_pair.anchor_next.clone(),
            discriminant: left_pair.discriminant.clone(),
            root,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}

/// Raise an [`EvidenceTree`] one level.
///
/// [`EvidenceTreeDescend`] walks [`EvidenceTreeDescend::LEVELS`] levels at a
/// time. At most `LEVELS - 1` caps make the depth a multiple of `LEVELS`.
///
/// One permutation (the node).
///
/// # Soundness
///
/// Copying the network fields and hashing the input's `root` across all four
/// node-digest positions makes `root` valid under the second rule of
/// [`EvidenceTree`].
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
        _oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let tree = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let children = array::from_fn::<_, EVIDENCE_TREE_ARITY, _>(|_| tree.root.clone());
        let raised = poseidon::circuit::evidence_tree_node(dr, &children)?;
        let output = D::just(|| {
            let (epoch, anchor_start, anchor_next, discriminant, _) = left.take();
            (
                epoch,
                anchor_start,
                anchor_next,
                discriminant,
                EvidenceTreeRoot(*raised.value().take()),
            )
        });
        let fields = EvidenceTreeOutput {
            epoch: tree.epoch.clone(),
            anchor_start: tree.anchor_start.clone(),
            anchor_next: tree.anchor_next.clone(),
            discriminant: tree.discriminant.clone(),
            root: raised,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}

/// Walk [`LEVELS`](Self::LEVELS) levels of a Merkle path, emitting the subtree
/// the path reaches.
///
/// Four permutations (one node per level).
///
/// # Soundness
///
/// At each level, four witnessed roots must hash to the current root. A valid
/// node digest cannot also open as a leaf and determines four valid roots for
/// the same network. Either choice of half and either position within it
/// therefore preserve validity. The prover chooses both bits freely; the
/// output keeps the network fields, and no step depends on the path taken.
#[derive(Debug)]
pub struct EvidenceTreeDescend;

impl EvidenceTreeDescend {
    /// The levels one descent covers.
    ///
    /// A path of `depth` levels takes `⌈depth / LEVELS⌉` descents, so a
    /// builder pads its tree to a multiple of this. A profile addresses at
    /// most `MAX_DEPTH / 2` quaternary levels, which is a multiple of
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
        _oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let tree = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let mut node = tree.root.clone();
        for level in 0..Self::LEVELS {
            let outer = Boolean::alloc(
                dr,
                &mut (),
                witness.as_ref().map(|&(path,)| {
                    let ([outer, _], _) = path[level];
                    outer
                }),
            )?;
            let inner = Boolean::alloc(
                dr,
                &mut (),
                witness.as_ref().map(|&(path,)| {
                    let ([_, inner], _) = path[level];
                    inner
                }),
            )?;
            let allocated = array::from_fn::<_, EVIDENCE_TREE_ARITY, _>(|child| {
                Element::alloc(
                    dr,
                    &mut (),
                    witness.as_ref().map(|&(path,)| {
                        let (_, children) = path[level];
                        Fp::from(children[child])
                    }),
                )
            });
            let children = {
                let [first, second, third, fourth] = allocated;
                [first?, second?, third?, fourth?]
            };
            let hash = poseidon::circuit::evidence_tree_node(dr, &children)?;
            node.enforce_equal(dr, &hash)?;
            let [first, second, third, fourth] = children;
            let lower = inner.conditional_select(dr, &first, &second)?;
            let upper = inner.conditional_select(dr, &third, &fourth)?;
            node = outer.conditional_select(dr, &lower, &upper)?;
        }
        let output = D::just(|| {
            let (epoch, anchor_start, anchor_next, discriminant, _) = left.take();
            (
                epoch,
                anchor_start,
                anchor_next,
                discriminant,
                EvidenceTreeRoot(*node.value().take()),
            )
        });
        let fields = EvidenceTreeOutput {
            epoch: tree.epoch.clone(),
            anchor_start: tree.anchor_start.clone(),
            anchor_next: tree.anchor_next.clone(),
            discriminant: tree.discriminant.clone(),
            root: node,
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}

/// Replay the [`QrBucket`] a one-leaf [`EvidenceTree`] holds.
///
/// Two permutations (the leaf digest).
/// The [`TachygramSetPoly`] holds the contents and opens once. Its bridge hash
/// enters the leaf.
///
/// # Soundness
///
/// Copying the input's network fields, allocating two unconstrained profile
/// wires, and reading `contents_hash` as the bridge hash of the prover's
/// committed contents $C$ in the last output slot, the circuit equates `root`
/// with the leaf digest of those eight elements.
///
/// Because `root` is valid and cannot also be known as a node digest, the first
/// rule of [`EvidenceTree`] makes it the leaf digest of a verified
/// [`QrBucket`]. Leaf-digest injectivity matches the output header and profile
/// path to that bucket's, and because `contents_hash` serves as a bridge hash
/// for both accumulators and [determines its polynomial](TachygramSetBridge),
/// $C$ equals that bucket's contents and inherits its assertion.
///
/// Although the bridge hash is not fixed before $\zeta$ and no identity is
/// checked at $\zeta$, an unconstrained opening at $\zeta$ binds the output
/// slot to $C$.
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

    fn prepare(
        &self,
        witness: &Self::Witness<'_>,
        _: HeaderInput<'_, Fp, Self::Left>,
        _: HeaderInput<'_, Fp, Self::Right>,
    ) -> ragu::Result<Prepared<Fp, Self::Output>> {
        let contents = &witness.1;
        Ok(TachygramSetPoly::SLOT.poly(Prepared::new(), contents))
    }

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        dr: &mut D,
        oracles: &mut Oracles<'_, 'dr, D, Pasta, Self>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header<Fp>>::Data>,
        right: DriverValue<D, <Self::Right as Header<Fp>>::Data>,
    ) -> ragu::Result<(
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
        let tree = left_encoded.as_gadget();
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(dr, &mut (), right)?;
        let fields = QrBucketOutput {
            epoch: tree.epoch.clone(),
            anchor_start: tree.anchor_start.clone(),
            anchor_next: tree.anchor_next.clone(),
            discriminant: tree.discriminant.clone(),
            profile: gadgets::qr::QrProfile::alloc(
                dr,
                &mut (),
                witness.as_ref().map(|&(profile, _)| profile),
            )?,
            contents_hash: [
                oracles.bridge_hash().x().clone(),
                oracles.bridge_hash().y().clone(),
            ],
        };
        let zeta = oracles.zeta().clone();
        oracles.output(TachygramSetPoly::SLOT).open(dr, &zeta)?;
        let leaf = poseidon::circuit::evidence_tree_leaf(
            dr,
            &fields.epoch,
            &fields.anchor_start,
            &fields.anchor_next,
            &fields.discriminant,
            (&fields.profile.depth, &fields.profile.bits),
            &fields.contents_hash,
        )?;
        tree.root.enforce_equal(dr, &leaf)?;
        let [hash_x, hash_y] = fields.contents_hash.each_ref().map(Element::value);
        let output = D::just(|| {
            let (profile, _) = witness.take();
            let (epoch, anchor_start, anchor_next, discriminant, _) = left.take();
            #[expect(
                clippy::expect_used,
                reason = "the oracle supplies commitment coordinates"
            )]
            let contents_hash = EpAffine::from_xy(*hash_x.take(), *hash_y.take())
                .expect("the bridge hash commitment is a curve point");
            (
                epoch,
                anchor_start,
                anchor_next,
                discriminant,
                profile,
                TachygramSetBridge::from(contents_hash),
            )
        });
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            output,
            D::unit(),
        ))
    }
}
