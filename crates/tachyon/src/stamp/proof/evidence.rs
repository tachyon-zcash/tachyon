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
use core::array;

use ragu::{
    Encoded, Header, Index, Step, StepCtx,
    pasta::{Eq, Fp},
};
use ragu_core::{
    drivers::{Driver, DriverValue},
    gadgets::Bound,
    maybe::Maybe as _,
};
use ragu_primitives::{Boolean, Element, GadgetExt as _};
use udon::curve::Projective as _;

use super::qr::QrBucket;
pub use crate::stamp::headers::evidence::{EvidenceTree, EvidenceTreePair};
use crate::{
    constants::EVIDENCE_TREE_ARITY,
    digest::poseidon,
    primitives::{EvidenceTreeRoot, QrProfile, TachygramSetCommit},
    relations::enforce::enforce_equal_fields,
};

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

impl Step for EvidenceTreeLeafPair {
    type Aux<'source> = ();
    type Left = QrBucket;
    type Output = EvidenceTreePair;
    type Right = QrBucket;
    type Shared = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(30);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let left_fields = [
            left_encoded.as_gadget().epoch.element.clone(),
            left_encoded.as_gadget().anchor_start.element.clone(),
            left_encoded.as_gadget().anchor_next.element.clone(),
            left_encoded.as_gadget().discriminant.element.clone(),
        ];
        let right_fields = [
            right_encoded.as_gadget().epoch.element.clone(),
            right_encoded.as_gadget().anchor_start.element.clone(),
            right_encoded.as_gadget().anchor_next.element.clone(),
            right_encoded.as_gadget().discriminant.element.clone(),
        ];
        enforce_equal_fields(
            ctx.dr,
            &left_fields,
            &right_fields,
            [
                "EvidenceTreeLeafPair: inputs cover different epochs",
                "EvidenceTreeLeafPair: inputs open at different anchors",
                "EvidenceTreeLeafPair: inputs close at different anchors",
                "EvidenceTreeLeafPair: inputs derive from different discriminants",
            ],
        )?;
        let first = left_encoded
            .as_gadget()
            .evidence_leaf(ctx.dr)
            .map(|root| root.element)?;
        let second = right_encoded
            .as_gadget()
            .evidence_leaf(ctx.dr)
            .map(|root| root.element)?;
        let output = D::just(|| {
            let (epoch, start, end, discriminant, ..) = left.take();
            (
                epoch,
                start,
                end,
                discriminant,
                EvidenceTreeRoot(*first.value().take()),
                EvidenceTreeRoot(*second.value().take()),
            )
        });
        let fields = crate::stamp::headers::evidence::EvidenceTreePairOutput {
            epoch: (left_fields[0].clone()).into(),
            anchor_start: (left_fields[1].clone()).into(),
            anchor_next: (left_fields[2].clone()).into(),
            discriminant: (left_fields[3].clone()).into(),
            first: (first).into(),
            second: (second).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
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
    type Shared = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(25);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let left_fields = [
            left_encoded.as_gadget().epoch.element.clone(),
            left_encoded.as_gadget().anchor_start.element.clone(),
            left_encoded.as_gadget().anchor_next.element.clone(),
            left_encoded.as_gadget().discriminant.element.clone(),
        ];
        let right_fields = [
            right_encoded.as_gadget().epoch.element.clone(),
            right_encoded.as_gadget().anchor_start.element.clone(),
            right_encoded.as_gadget().anchor_next.element.clone(),
            right_encoded.as_gadget().discriminant.element.clone(),
        ];
        enforce_equal_fields(
            ctx.dr,
            &left_fields,
            &right_fields,
            [
                "EvidenceTreePairFuse: inputs cover different epochs",
                "EvidenceTreePairFuse: inputs open at different anchors",
                "EvidenceTreePairFuse: inputs close at different anchors",
                "EvidenceTreePairFuse: inputs derive from different discriminants",
            ],
        )?;
        let output = D::just(|| {
            let (epoch, start, end, discriminant, root) = left.take();
            (epoch, start, end, discriminant, root, right.take().4)
        });
        let fields = crate::stamp::headers::evidence::EvidenceTreePairOutput {
            epoch: (left_fields[0].clone()).into(),
            anchor_start: (left_fields[1].clone()).into(),
            anchor_next: (left_fields[2].clone()).into(),
            discriminant: (left_fields[3].clone()).into(),
            first: (left_encoded.as_gadget().root.element.clone()).into(),
            second: (right_encoded.as_gadget().root.element.clone()).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
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
    type Shared = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(26);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded =
            Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right.clone())?;
        let left_fields = [
            left_encoded.as_gadget().epoch.element.clone(),
            left_encoded.as_gadget().anchor_start.element.clone(),
            left_encoded.as_gadget().anchor_next.element.clone(),
            left_encoded.as_gadget().discriminant.element.clone(),
        ];
        let right_fields = [
            right_encoded.as_gadget().epoch.element.clone(),
            right_encoded.as_gadget().anchor_start.element.clone(),
            right_encoded.as_gadget().anchor_next.element.clone(),
            right_encoded.as_gadget().discriminant.element.clone(),
        ];
        enforce_equal_fields(
            ctx.dr,
            &left_fields,
            &right_fields,
            [
                "EvidenceTreeFuse: inputs cover different epochs",
                "EvidenceTreeFuse: inputs open at different anchors",
                "EvidenceTreeFuse: inputs close at different anchors",
                "EvidenceTreeFuse: inputs derive from different discriminants",
            ],
        )?;
        let children = [
            left_encoded.as_gadget().first.element.clone(),
            left_encoded.as_gadget().second.element.clone(),
            right_encoded.as_gadget().first.element.clone(),
            right_encoded.as_gadget().second.element.clone(),
        ];
        let root = poseidon::evidence_tree_node_circuit(ctx.dr, &children)?;
        let output = D::just(|| {
            let (epoch, start, end, discriminant, ..) = left.take();
            (
                epoch,
                start,
                end,
                discriminant,
                EvidenceTreeRoot(*root.value().take()),
            )
        });
        let fields = crate::stamp::headers::evidence::EvidenceTreeOutput {
            epoch: (left_fields[0].clone()).into(),
            anchor_start: (left_fields[1].clone()).into(),
            anchor_next: (left_fields[2].clone()).into(),
            discriminant: (left_fields[3].clone()).into(),
            root: (root).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
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
    type Shared = ();
    type Witness<'source> = ();

    const INDEX: Index = Index::new(27);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        _witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
        let root = left_encoded.as_gadget().root.element.clone();
        let children = array::from_fn::<_, EVIDENCE_TREE_ARITY, _>(|_| root.clone());
        let raised = poseidon::evidence_tree_node_circuit(ctx.dr, &children)?;
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
        let fields = crate::stamp::headers::evidence::EvidenceTreeOutput {
            epoch: (left_encoded.as_gadget().epoch.element.clone()).into(),
            anchor_start: (left_encoded.as_gadget().anchor_start.element.clone()).into(),
            anchor_next: (left_encoded.as_gadget().anchor_next.element.clone()).into(),
            discriminant: (left_encoded.as_gadget().discriminant.element.clone()).into(),
            root: (raised).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
        ))
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

impl Step for EvidenceTreeDescend {
    type Aux<'source> = ();
    type Left = EvidenceTree;
    type Output = EvidenceTree;
    type Right = ();
    type Shared = ();
    /// `(path)`
    type Witness<'source> = ([([bool; 2], [EvidenceTreeRoot; EVIDENCE_TREE_ARITY]); Self::LEVELS],);

    const INDEX: Index = Index::new(28);

    #[expect(
        clippy::indexing_slicing,
        reason = "four fixed path levels with four children per level"
    )]
    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
        let mut node = left_encoded.as_gadget().root.element.clone();
        for level in 0..Self::LEVELS {
            let outer = Boolean::alloc(
                ctx.dr,
                &mut (),
                witness.as_ref().map(|path| path.0[level].0[0]),
            )?;
            let inner = Boolean::alloc(
                ctx.dr,
                &mut (),
                witness.as_ref().map(|path| path.0[level].0[1]),
            )?;
            let children = [
                Element::alloc(
                    ctx.dr,
                    &mut (),
                    witness.as_ref().map(|path| Fp::from(path.0[level].1[0])),
                )?,
                Element::alloc(
                    ctx.dr,
                    &mut (),
                    witness.as_ref().map(|path| Fp::from(path.0[level].1[1])),
                )?,
                Element::alloc(
                    ctx.dr,
                    &mut (),
                    witness.as_ref().map(|path| Fp::from(path.0[level].1[2])),
                )?,
                Element::alloc(
                    ctx.dr,
                    &mut (),
                    witness.as_ref().map(|path| Fp::from(path.0[level].1[3])),
                )?,
            ];
            let hash = poseidon::evidence_tree_node_circuit(ctx.dr, &children)?;
            node.enforce_equal(ctx.dr, &hash).map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "EvidenceTreeDescend: children do not hash to the node".into(),
                )
            })?;
            let [first, second, third, fourth] = children;
            let lower = inner.conditional_select(ctx.dr, &first, &second)?;
            let upper = inner.conditional_select(ctx.dr, &third, &fourth)?;
            node = outer.conditional_select(ctx.dr, &lower, &upper)?;
        }
        let output = D::just(|| {
            let (epoch, start, end, discriminant, _) = left.take();
            (
                epoch,
                start,
                end,
                discriminant,
                EvidenceTreeRoot(*node.value().take()),
            )
        });
        let fields = crate::stamp::headers::evidence::EvidenceTreeOutput {
            epoch: (left_encoded.as_gadget().epoch.element.clone()).into(),
            anchor_start: (left_encoded.as_gadget().anchor_start.element.clone()).into(),
            anchor_next: (left_encoded.as_gadget().anchor_next.element.clone()).into(),
            discriminant: (left_encoded.as_gadget().discriminant.element.clone()).into(),
            root: (node).into(),
        };
        Ok((
            (left_encoded, right_encoded, Encoded::from_gadget(fields)),
            (),
            output,
            D::unit(),
        ))
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

impl Step for EvidenceTreeOpen {
    type Aux<'source> = ();
    type Left = EvidenceTree;
    type Output = QrBucket;
    type Right = ();
    type Shared = ();
    /// `(profile, contents)`
    type Witness<'source> = (QrProfile, TachygramSetCommit);

    const INDEX: Index = Index::new(29);

    fn witness<'dr, 'source: 'dr, D: Driver<'dr, F = Fp>, const HEADER_SIZE: usize>(
        &self,
        ctx: &mut StepCtx<'_, 'dr, D>,
        witness: DriverValue<D, Self::Witness<'source>>,
        left: DriverValue<D, <Self::Left as Header>::Data>,
        right: DriverValue<D, <Self::Right as Header>::Data>,
    ) -> ragu_core::Result<(
        (
            Encoded<'dr, D, Self::Left, HEADER_SIZE>,
            Encoded<'dr, D, Self::Right, HEADER_SIZE>,
            Encoded<'dr, D, Self::Output, HEADER_SIZE>,
        ),
        Bound<'dr, D, Self::Shared>,
        DriverValue<D, <Self::Output as Header>::Data>,
        DriverValue<D, Self::Aux<'source>>,
    )>
    where
        Self: 'dr,
    {
        let left_encoded =
            Encoded::<D, Self::Left, HEADER_SIZE>::new(ctx.dr, &mut (), left.clone())?;
        let right_encoded = Encoded::<D, Self::Right, HEADER_SIZE>::new(ctx.dr, &mut (), right)?;
        let profile = [
            Element::alloc(
                ctx.dr,
                &mut (),
                witness
                    .as_ref()
                    .map(|data| Fp::from(u64::from(data.0.depth))),
            )?,
            Element::alloc(
                ctx.dr,
                &mut (),
                witness
                    .as_ref()
                    .map(|data| Fp::from(u64::from(data.0.bits))),
            )?,
        ];
        let contents = crate::gadgets::commitment::HostCommitment::alloc(
            ctx.dr,
            &mut (),
            witness.as_ref().map(|data| Eq::from(data.1).to_affine()),
        )
        .map(|encoding| encoding.limbs)?;
        let output = D::just(|| {
            let (carrier_profile, carrier_contents) = witness.take();
            let (epoch, anchor_start, anchor_next, discriminant, _) = left.clone().take();
            (
                epoch,
                anchor_start,
                anchor_next,
                discriminant,
                carrier_profile,
                carrier_contents,
            )
        });
        let expected = left_encoded.as_gadget().root.element.clone();
        let fields = [
            left_encoded.as_gadget().epoch.element.clone(),
            left_encoded.as_gadget().anchor_start.element.clone(),
            left_encoded.as_gadget().anchor_next.element.clone(),
            left_encoded.as_gadget().discriminant.element.clone(),
        ];
        let output_fields = crate::stamp::headers::qr::QrBucketOutput {
            epoch: (fields[0].clone()).into(),
            anchor_start: (fields[1].clone()).into(),
            anchor_next: (fields[2].clone()).into(),
            discriminant: (fields[3].clone()).into(),
            profile: crate::gadgets::profile::QrProfileGadget {
                depth: profile[0].clone(),
                bits: profile[1].clone(),
            },
            contents: (crate::gadgets::commitment::HostCommitment { limbs: contents }).into(),
        };
        let computed = output_fields
            .evidence_leaf(ctx.dr)
            .map(|root| root.element)?;
        expected.enforce_equal(ctx.dr, &computed).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "EvidenceTreeOpen: witnessed bucket is not the tree's leaf".into(),
            )
        })?;

        Ok((
            (
                left_encoded,
                right_encoded,
                Encoded::from_gadget(output_fields),
            ),
            (),
            output,
            D::unit(),
        ))
    }
}

#[cfg(test)]
mod tests {
    fn network_fields<'dr, D: Driver<'dr, F = Fp>>(
        dr: &mut D,
        fields: [DriverValue<D, Fp>; 4],
    ) -> ragu_core::Result<[Element<'dr, D>; 4]> {
        let [epoch, start, end, discriminant] = fields;
        Ok([
            Element::alloc(dr, &mut (), epoch)?,
            Element::alloc(dr, &mut (), start)?,
            Element::alloc(dr, &mut (), end)?,
            Element::alloc(dr, &mut (), discriminant)?,
        ])
    }

    use ragu_primitives::Simulator;
    use udon::field::Field as _;

    use super::*;

    /// Valid published buckets correlate their epoch and anchor digests. Raw
    /// allocation-boundary assignments isolate each equality without
    /// fabricating a recursively authenticated child under altered native
    /// header data.
    #[test]
    fn network_comparison_rejects_each_independent_field_mismatch() {
        let expected = [Fp::from(5), Fp::from(7), Fp::from(11), Fp::from(13)];
        for changed in 0..=4 {
            let mut candidate = expected;
            if changed < 4 {
                candidate[changed] += Fp::ONE;
            }
            let result = Simulator::<Fp>::simulate((expected, candidate), |driver, assignment| {
                let left = network_fields(
                    driver,
                    array::from_fn(|index| assignment.as_ref().map(|values| values.0[index])),
                )?;
                let right = network_fields(
                    driver,
                    array::from_fn(|index| assignment.as_ref().map(|values| values.1[index])),
                )?;
                enforce_equal_fields(
                    driver,
                    &left,
                    &right,
                    ["epoch", "start", "end", "discriminant"],
                )
            });
            if changed == 4 {
                result.expect("equal network fields");
            } else {
                assert!(result.is_err(), "field {changed} must be constrained");
            }
        }
    }
}
