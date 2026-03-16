//! Note keys and GGM tree PRF for nullifier derivation.
//!
//! A binary-tree pseudorandom function instantiated from Poseidon.
//! Each step hashes the current node with a bit (0 = left, 1 = right).
//! Traversal is MSB-first so that left subtrees cover lower-numbered
//! leaves, enabling contiguous-range prefix delegation.

use alloc::vec::Vec;
use core::num::NonZeroU8;

use ff::PrimeField as _;
// TODO(#39): replace halo2_poseidon with Ragu Poseidon params
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use crate::{
    constants::{NOTE_NULLIFIER_DOMAIN, NOTE_PREFIX_DOMAIN},
    note::Nullifier,
    primitives::Epoch,
};

/// GGM tree depth — 32-bit epochs cover ~4 billion values.
const MAX_TREE_DEPTH: u8 = 32;

/// A GGM tree node parameterized by its depth type.
///
/// - `NoteKey<Master>` is a root node (depth 0, ZST overhead).
/// - `NoteKey<Prefix>` is a delegate node covering a specific subtree.
/// - `NoteKey<Leaf>` is a fully-evaluated leaf (single epoch).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteKey<D> {
    /// The value of the node.
    pub inner: Fp,
    /// The depth marker.
    pub prefix: D,
}

/// Marker for a master (root, depth 0) note key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Master;

/// A GGM subtree identified by its depth and node index.
///
/// At depth `d` there are `2^d` nodes. Node `i` covers the contiguous epoch
/// range `[i * 2^(32-d) ..= (i+1) * 2^(32-d) - 1]`. The index encodes the
/// `d`-bit path from root (MSB-first).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prefix {
    depth: NonZeroU8,
    index: u32,
}

/// Errors from constructing a [`Prefix`].
#[derive(Debug, Eq, PartialEq)]
pub enum PrefixError {
    /// Depth is zero or exceeds the maximum tree depth.
    DepthOutOfRange,
    /// Index is too large for the given depth.
    IndexOutOfRange,
}

impl Prefix {
    /// Create a new prefix identifying the specified node.
    pub const fn new(depth: NonZeroU8, index: u32) -> Result<Self, PrefixError> {
        if depth.get() >= MAX_TREE_DEPTH {
            return Err(PrefixError::DepthOutOfRange);
        }

        let height = MAX_TREE_DEPTH - depth.get();
        if index > (u32::MAX >> height) {
            return Err(PrefixError::IndexOutOfRange);
        }

        Ok(Self { depth, index })
    }

    /// The node index at this depth.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.index
    }

    /// First leaf index in the covered range.
    #[must_use]
    pub const fn first(self) -> u32 {
        let height = MAX_TREE_DEPTH - self.depth.get();
        self.index << height
    }

    /// Last leaf index in the covered range (inclusive).
    #[must_use]
    pub const fn last(self) -> u32 {
        self.first() | (u32::MAX >> self.depth.get())
    }

    /// Decompose the epoch range `[start..end)` into the minimal set of dyadic
    /// intervals.
    #[must_use]
    pub fn tight(start: u32, end: u32) -> Vec<Self> {
        let mut pos = start;
        let mut result = Vec::new();
        while pos < end {
            let sub_height = {
                let fits = (end - pos).ilog2();
                let aligned = pos.trailing_zeros();
                #[expect(clippy::expect_used, reason = "betwen 1 and 31")]
                u8::try_from(aligned.min(fits)).expect("small number")
            };

            #[expect(clippy::expect_used, reason = "valid depth")]
            let sub_depth = NonZeroU8::new(MAX_TREE_DEPTH - sub_height).expect("valid depth");

            #[expect(clippy::expect_used, reason = "index calculation")]
            result
                .push(Self::new(sub_depth, pos >> sub_height).expect("valid index at valid depth"));

            let span_width = 1u32 << sub_height;
            pos += span_width;
        }
        result
    }
}

/// A fully-evaluated GGM leaf — covers exactly one epoch.
///
/// At depth 32 (= `MAX_TREE_DEPTH`) there is no remaining tree to walk.
/// The inner value is the PRF output for a single epoch, ready to be
/// hashed into a nullifier without any in-circuit tree traversal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leaf {
    epoch: u32,
}

impl Leaf {
    /// The epoch this leaf covers.
    #[must_use]
    pub const fn epoch(self) -> u32 {
        self.epoch
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Master {}
    impl Sealed for super::Prefix {}
    impl Sealed for super::Leaf {}
}

/// Sealed trait for GGM tree depth markers ([`Master`], [`Prefix`], [`Leaf`]).
pub trait GGMTreeDepth: Copy + sealed::Sealed {
    /// The number of levels already descended from the root.
    fn depth(self) -> u8;
}

impl GGMTreeDepth for Master {
    fn depth(self) -> u8 {
        u8::MIN
    }
}

impl GGMTreeDepth for Prefix {
    fn depth(self) -> u8 {
        self.depth.get()
    }
}

impl GGMTreeDepth for Leaf {
    fn depth(self) -> u8 {
        MAX_TREE_DEPTH
    }
}

impl<D: GGMTreeDepth> NoteKey<D> {
    /// The number of levels already descended.
    pub fn depth(self) -> u8 {
        self.prefix.depth()
    }

    /// Evaluate the GGM PRF at the given epoch, walking the remaining bits
    /// MSB-first.
    pub(in crate::keys) fn evaluate(&self, leaf: u32) -> Fp {
        walk(self.inner, leaf, MAX_TREE_DEPTH - self.prefix.depth())
    }
}

impl NoteKey<Master> {
    /// Evaluate the GGM tree to a leaf for a specific epoch.
    ///
    /// The returned `NoteKey<Leaf>` holds the fully-evaluated PRF value
    /// — no further tree walking is needed to derive the nullifier.
    #[must_use]
    pub fn derive_leaf(&self, flavor: Epoch) -> NoteKey<Leaf> {
        NoteKey {
            inner: self.evaluate(u32::from(flavor)),
            prefix: Leaf {
                epoch: u32::from(flavor),
            },
        }
    }

    /// Derive a nullifier for epoch `flavor`: $\mathsf{nf} =
    /// F_{\mathsf{mk}}(\text{flavor})$.
    #[must_use]
    pub fn derive_nullifier(&self, flavor: Epoch) -> Nullifier {
        self.derive_leaf(flavor).derive_nullifier()
    }

    /// Derive epoch-restricted prefix keys for OSS delegation.
    ///
    /// Each returned key can evaluate the PRF only for epochs within
    /// the subtree identified by its prefix.
    pub fn derive_note_delegates(
        &self,
        prefixes: impl IntoIterator<Item = Prefix>,
    ) -> Vec<NoteKey<Prefix>> {
        prefixes
            .into_iter()
            .map(|prefix| {
                NoteKey {
                    inner: walk(self.inner, prefix.index, prefix.depth()),
                    prefix,
                }
            })
            .collect()
    }
}

impl NoteKey<Prefix> {
    /// Evaluate the GGM tree to a leaf for a specific epoch, returning
    /// `None` if the epoch is outside this prefix's authorized range.
    #[must_use]
    pub fn derive_leaf(&self, flavor: Epoch) -> Option<NoteKey<Leaf>> {
        let epoch = u32::from(flavor);
        if epoch < self.prefix.first() || epoch > self.prefix.last() {
            return None;
        }
        Some(NoteKey {
            inner: self.evaluate(epoch),
            prefix: Leaf { epoch },
        })
    }

    /// Derive a nullifier for epoch `flavor`, returning `None` if the
    /// epoch is outside this prefix's authorized range.
    #[must_use]
    pub fn derive_nullifier(&self, flavor: Epoch) -> Option<Nullifier> {
        self.derive_leaf(flavor).map(|leaf| leaf.derive_nullifier())
    }
}

impl NoteKey<Leaf> {
    /// Derive the nullifier from a fully-evaluated leaf.
    ///
    /// `nf = Poseidon(Tachyon-NoteNull, leaf, epoch)`
    ///
    /// This is a single hash — no tree walking. The `Tachyon-NoteNull`
    /// domain is distinct from the `Tachyon-NotePref` domain used for
    /// GGM tree steps.
    #[must_use]
    pub fn derive_nullifier(&self) -> Nullifier {
        #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
        let personalization = Fp::from_u128(u128::from_le_bytes(*NOTE_NULLIFIER_DOMAIN));
        let epoch = Fp::from(u64::from(self.prefix.epoch));
        Nullifier::from(
            Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
                personalization,
                self.inner,
                epoch,
            ]),
        )
    }
}

/// One GGM tree step: `Poseidon(tag, node, bit)`.
///
/// Uses `Tachyon-NotePref` domain — distinct from the final
/// leaf-to-nullifier derivation which uses `Tachyon-NoteNull`.
fn step(node: Fp, bit: Fp) -> Fp {
    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    let personalization = Fp::from_u128(u128::from_le_bytes(*NOTE_PREFIX_DOMAIN));
    Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([personalization, node, bit])
}

/// Recursive GGM walk: consume the top bit of `leaf` at each level,
/// MSB-first, for `remaining` levels.
fn walk(node: Fp, leaf: u32, remaining: u8) -> Fp {
    match remaining.checked_sub(1) {
        | None => node,
        | Some(next) => {
            let bit = (leaf >> next) & 0b0001;
            walk(step(node, Fp::from(u64::from(bit))), leaf, next)
        },
    }
}

impl TryFrom<[u8; 32]> for NoteKey<Master> {
    type Error = NoteKeyError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        let inner = Fp::from_repr(bytes)
            .into_option()
            .ok_or(NoteKeyError::InvalidRepr)?;
        Ok(Self {
            inner,
            prefix: Master,
        })
    }
}

impl From<NoteKey<Master>> for [u8; 32] {
    fn from(key: NoteKey<Master>) -> [u8; 32] {
        key.inner.to_repr()
    }
}

impl TryFrom<[u8; 37]> for NoteKey<Prefix> {
    type Error = NoteKeyError;

    fn try_from(bytes: [u8; 37]) -> Result<Self, Self::Error> {
        // [repr(32) | depth(1) | index_le(4)]
        let fp_bytes: &[u8; 32] = bytes.first_chunk().ok_or(NoteKeyError::Truncated)?;
        let inner = Fp::from_repr(*fp_bytes)
            .into_option()
            .ok_or(NoteKeyError::InvalidRepr)?;
        let tail: &[u8; 5] = bytes.last_chunk().ok_or(NoteKeyError::Truncated)?;
        let (&depth_byte, index_slice) = tail.split_first().ok_or(NoteKeyError::Truncated)?;
        let depth = NonZeroU8::new(depth_byte).ok_or(NoteKeyError::ZeroPrefix)?;
        let index_bytes: &[u8; 4] = index_slice.first_chunk().ok_or(NoteKeyError::Truncated)?;
        #[expect(clippy::little_endian_bytes, reason = "deserialization")]
        let index = u32::from_le_bytes(*index_bytes);
        let prefix = Prefix::new(depth, index).map_err(NoteKeyError::InvalidPrefix)?;
        Ok(Self { inner, prefix })
    }
}

impl From<NoteKey<Prefix>> for [u8; 37] {
    fn from(key: NoteKey<Prefix>) -> [u8; 37] {
        // [repr(32) | depth(1) | index_le(4)]
        #[expect(clippy::expect_used, reason = "length is statically known")]
        [
            key.inner.to_repr().as_slice(),
            &[key.prefix.depth()],
            #[expect(clippy::little_endian_bytes, reason = "serialization")]
            &key.prefix.index().to_le_bytes(),
        ]
        .concat()
        .try_into()
        .expect("32 + 1 + 4 = 37")
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for NoteKey<Prefix> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes: [u8; 37] = (*self).into();
        serializer.serialize_bytes(&bytes)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for NoteKey<Prefix> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use core::fmt;

        use serde::de;

        struct NoteKeyVisitor;

        impl de::Visitor<'_> for NoteKeyVisitor {
            type Value = NoteKey<Prefix>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("37 bytes encoding a NoteKey<Prefix>")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if v.len() != 37 {
                    return Err(E::invalid_length(v.len(), &self));
                }
                let mut bytes = [0u8; 37];
                bytes.copy_from_slice(v);
                NoteKey::<Prefix>::try_from(bytes)
                    .map_err(|_err| de::Error::custom("invalid NoteKey<Prefix>"))
            }
        }

        deserializer.deserialize_bytes(NoteKeyVisitor)
    }
}

#[derive(Debug)]
/// Errors that can occur when deserializing a NoteKey.
pub enum NoteKeyError {
    /// The input bytes are truncated.
    Truncated,
    /// The input bytes are not a valid representation of an Fp.
    InvalidRepr,
    /// The prefix depth is zero.
    ZeroPrefix,
    /// The prefix construction failed.
    InvalidPrefix(PrefixError),
}

#[cfg(test)]
mod tests {
    use core::num::NonZeroU8;

    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    #[test]
    fn distinct_leaves() {
        let mut rng = StdRng::seed_from_u64(0);
        let key = NoteKey::<Master>::try_from(Fp::random(&mut rng).to_repr()).unwrap();

        assert_ne!(key.evaluate(0), key.evaluate(1));
    }

    #[test]
    fn distinct_keys() {
        let mut rng = StdRng::seed_from_u64(0);
        let key1 = NoteKey::<Master>::try_from(Fp::random(&mut rng).to_repr()).unwrap();
        let key2 = NoteKey::<Master>::try_from(Fp::random(&mut rng).to_repr()).unwrap();

        assert_ne!(key1.evaluate(42), key2.evaluate(42));
    }

    /// Prefix key at each depth (index 0) produces the same nullifier
    /// as the root key for leaf 0.
    #[test]
    fn prefix_index_zero_matches_root() {
        let mut rng = StdRng::seed_from_u64(0);
        let root = NoteKey::<Master>::try_from(Fp::random(&mut rng).to_repr()).unwrap();
        let prefixes: Vec<_> = [6u8, 14, 20, 26]
            .into_iter()
            .map(|depth| Prefix::new(NonZeroU8::new(depth).unwrap(), 0).unwrap())
            .collect();
        for delegate in root.derive_note_delegates(prefixes) {
            assert_eq!(
                delegate.evaluate(0),
                root.evaluate(0),
                "mismatch at depth {:?}",
                delegate.depth()
            );
        }
    }

    #[test]
    fn prefix_new_rejects_invalid() {
        // depth=0 is prevented by NonZeroU8 parameter type
        // depth > TREE_DEPTH is invalid
        assert_eq!(
            Prefix::new(NonZeroU8::new(33u8).unwrap(), 0).unwrap_err(),
            PrefixError::DepthOutOfRange
        );
        // index >= 2^depth is invalid
        assert_eq!(
            Prefix::new(NonZeroU8::new(1u8).unwrap(), 2).unwrap_err(),
            PrefixError::IndexOutOfRange
        );
        assert_eq!(
            Prefix::new(NonZeroU8::new(2u8).unwrap(), 4).unwrap_err(),
            PrefixError::IndexOutOfRange
        );
        // depth == MAX_TREE_DEPTH (single leaf) is not delegable.
        assert_eq!(
            Prefix::new(NonZeroU8::new(32u8).unwrap(), 0).unwrap_err(),
            PrefixError::DepthOutOfRange
        );
        // Rightmost valid nodes at each depth.
        assert_eq!(
            Prefix::new(NonZeroU8::new(1u8).unwrap(), 1).unwrap(),
            Prefix {
                depth: NonZeroU8::new(1u8).unwrap(),
                index: 1
            }
        );
        assert_eq!(
            Prefix::new(NonZeroU8::new(2u8).unwrap(), 3).unwrap(),
            Prefix {
                depth: NonZeroU8::new(2u8).unwrap(),
                index: 3
            }
        );
        assert_eq!(
            Prefix::new(NonZeroU8::new(31u8).unwrap(), u32::MAX >> 1).unwrap(),
            Prefix {
                depth: NonZeroU8::new(31u8).unwrap(),
                index: u32::MAX >> 1
            }
        );
    }

    #[test]
    fn prefix_epoch_range() {
        let minute = Prefix::new(NonZeroU8::new(26u8).unwrap(), 1).unwrap();
        assert_eq!(minute.first(), 64);
        assert_eq!(minute.last(), 127);

        let half = Prefix::new(NonZeroU8::new(1u8).unwrap(), 0).unwrap();
        assert_eq!(half.first(), 0);
        assert_eq!(half.last(), 0b0111_1111_1111_1111_1111_1111_1111_1111);

        // Rightmost subtree at depth 1 covers [2^31 ..= u32::MAX].
        let upper_half = Prefix::new(NonZeroU8::new(1u8).unwrap(), 1).unwrap();
        assert_eq!(
            upper_half.first(),
            0b1000_0000_0000_0000_0000_0000_0000_0000
        );
        assert_eq!(upper_half.last(), u32::MAX);
    }

    #[test]
    fn cover_simple() {
        let cover = Prefix::tight(0, 6);
        // [0..=3] at depth 30, [4..=5] at depth 31.
        assert_eq!(cover.len(), 2);
        assert_eq!(cover[0].first(), 0);
        assert_eq!(cover[0].last(), 3);
        assert_eq!(cover[1].first(), 4);
        assert_eq!(cover[1].last(), 5);

        let single = Prefix::tight(0, 4);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].first(), 0);
        assert_eq!(single[0].last(), 3);
    }
}
