//! GGM tree PRF for nullifier derivation.
//!
//! A `k`-ary tree pseudorandom function instantiated from Poseidon, with
//! `k = 1 << LOG2_ARITY`. Each step hashes the current node with a chunk
//! of `LOG2_ARITY` bits drawn from the epoch index (MSB-first), so that
//! left subtrees cover lower-numbered leaves and contiguous ranges map to
//! sparse prefix covers.
//!
//! The tree is sized to tile the full epoch space:
//! `GGM_TREE_DEPTH * LOG2_ARITY == EPOCH_BITS`.

use alloc::vec::Vec;
use core::{num::NonZeroU8, ops::RangeInclusive};

use ff::PrimeField as _;
// TODO(#39): replace halo2_poseidon with Ragu Poseidon params
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use crate::{
    constants::{EPOCH_BITS, GGM_TREE_DEPTH, LOG2_ARITY, NOTE_NULLIFIER_DOMAIN},
    note::Nullifier,
    primitives::EpochIndex,
};

/// Tree arity — i.e. `1 << LOG2_ARITY`, the number of children per non-leaf.
pub const ARITY: u8 = 1u8 << LOG2_ARITY;

/// Mask covering exactly one chunk: low `LOG2_ARITY` bits set.
const CHUNK_MASK: u32 = (1u32 << LOG2_ARITY) - 1u32;

/// Per-note master root key.
///
/// Root of the GGM tree PRF for a single note. Derived by the user device
/// from [`NullifierKey`](super::NullifierKey) and the note's psi trapdoor.
///
/// ## Delegation chain
///
/// ```text
/// nk + psi → mk (per-note root, user device)
///              ├── nf = F_mk(flavor)     nullifier for a specific epoch
///              └── psi_t = GGM(mk, t)    prefix key for epochs e ≤ t (OSS)
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoteMasterKey(pub(crate) Fp);

impl NoteMasterKey {
    /// Descend one level from the root of the GGM tree.
    #[must_use]
    pub fn step(&self, chunk: u8) -> NotePrefixedKey {
        debug_assert!(chunk < ARITY, "chunk must be less than arity");
        #[expect(clippy::expect_used, reason = "depth 1 is always valid")]
        NotePrefixedKey {
            inner: ggm_step(self.0, chunk),
            depth: NonZeroU8::new(1).expect("1 != 0"),
            index: u32::from(chunk),
        }
    }

    /// Derive a nullifier for the given epoch.
    #[must_use]
    pub fn derive_nullifier(&self, flavor: EpochIndex) -> Nullifier {
        Nullifier::from(&ggm_walk(self.0, flavor.0, GGM_TREE_DEPTH))
    }

    /// Derive epoch-restricted prefix keys covering the specified range.
    ///
    /// Recursively descends the tree, emitting fully-covered nodes and
    /// only hashing children that overlap the range.
    #[must_use]
    pub fn derive_note_delegates(&self, range: RangeInclusive<u32>) -> Vec<NotePrefixedKey> {
        assert!(
            *range.end() <= epoch_max(),
            "range {range:?} exceeds epoch space {:?}",
            0u32..=epoch_max(),
        );

        let child_size = 1u32 << (EPOCH_BITS - LOG2_ARITY);
        let mut result = Vec::new();
        for chunk in 0u8..ARITY {
            let child_lo = u32::from(chunk) * child_size;
            let child_hi = child_lo + child_size - 1;
            if *range.start() <= child_hi && *range.end() >= child_lo {
                let clamped = (*range.start()).max(child_lo)..=(*range.end()).min(child_hi);
                result.extend(self.step(chunk).derive_note_delegates(clamped));
            }
        }
        result
    }
}

impl TryFrom<[u8; 32]> for NoteMasterKey {
    type Error = NoteKeyError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        Ok(Self(
            Fp::from_repr(bytes)
                .into_option()
                .ok_or(NoteKeyError::InvalidRepr)?,
        ))
    }
}

impl From<NoteMasterKey> for [u8; 32] {
    fn from(key: NoteMasterKey) -> [u8; 32] {
        key.0.to_repr()
    }
}

/// A Tachyon prefix key for range-restricted nullifier delegation.
///
/// At depth `d` there are `ARITY^d` nodes. Node `i` covers the contiguous
/// epoch range of size `ARITY^(GGM_TREE_DEPTH - d)`. At depth
/// `GGM_TREE_DEPTH`, a key is a leaf whose `index` equals its single epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotePrefixedKey {
    /// GGM tree node value.
    pub(crate) inner: Fp,
    /// The number of levels already descended.
    pub(crate) depth: NonZeroU8,
    /// Node index at this depth.
    pub(crate) index: u32,
}

impl NotePrefixedKey {
    /// The epoch range covered by this key.
    #[must_use]
    pub fn range(self) -> RangeInclusive<u32> {
        let levels_remaining = GGM_TREE_DEPTH - self.depth.get();
        let span_bits = u32::from(levels_remaining) * LOG2_ARITY;
        let first = self.index << span_bits;
        let mask = 1u32
            .checked_shl(span_bits)
            .map_or(u32::MAX, |size| size - 1u32);
        let last = first | mask;
        first..=last
    }

    /// Descend one level in the GGM tree.
    ///
    /// # Panics
    ///
    /// Panics if already at a leaf (depth == `GGM_TREE_DEPTH`).
    #[must_use]
    pub fn step(&self, chunk: u8) -> Self {
        assert!(
            self.depth.get() < GGM_TREE_DEPTH,
            "must not step beyond leaf"
        );
        debug_assert!(chunk < ARITY, "chunk must be less than arity");
        Self {
            inner: ggm_step(self.inner, chunk),
            #[expect(clippy::expect_used, reason = "nonzero plus one is not zero")]
            depth: NonZeroU8::new(self.depth.get() + 1).expect("not zero"),
            index: self.index * u32::from(ARITY) + u32::from(chunk),
        }
    }

    /// Derive epoch-restricted prefix keys covering the specified range
    /// within this key's range.
    ///
    /// Recursively descends the tree, emitting fully-covered nodes and
    /// only hashing children that overlap the range.
    ///
    /// # Panics
    ///
    /// Panics if `range` is not a subset of [`Self::range`].
    #[must_use]
    pub fn derive_note_delegates(&self, range: RangeInclusive<u32>) -> Vec<Self> {
        assert!(
            self.range().contains(range.start()) && self.range().contains(range.end()),
            "prefix key for {:?} does not cover requested range {:?}",
            self.range(),
            range,
        );

        if range == self.range() {
            alloc::vec![*self]
        } else {
            let next_depth = u32::from(self.depth.get()) + 1u32;
            let child_span_bits = (u32::from(GGM_TREE_DEPTH) - next_depth) * LOG2_ARITY;
            let child_size = 1u32 << child_span_bits;
            let base = *self.range().start();

            let mut result = Vec::new();
            for chunk in 0u8..ARITY {
                let child_lo = base + u32::from(chunk) * child_size;
                let child_hi = child_lo + child_size - 1;
                if *range.start() <= child_hi && *range.end() >= child_lo {
                    let clamped = (*range.start()).max(child_lo)..=(*range.end()).min(child_hi);
                    result.extend(self.step(chunk).derive_note_delegates(clamped));
                }
            }
            result
        }
    }

    /// Derive a nullifier for the given epoch.
    ///
    /// # Panics
    ///
    /// Panics if the epoch is outside this key's authorized range.
    #[must_use]
    pub fn derive_nullifier(&self, flavor: EpochIndex) -> Nullifier {
        assert!(self.range().contains(&flavor.0), "epoch out of range");
        let remaining = GGM_TREE_DEPTH - self.depth.get();
        Nullifier::from(&ggm_walk(self.inner, flavor.0, remaining))
    }
}

impl TryFrom<[u8; 37]> for NotePrefixedKey {
    type Error = NoteKeyError;

    fn try_from(bytes: [u8; 37]) -> Result<Self, Self::Error> {
        // [repr(32) | depth(1) | index_le(4)]
        let fp_bytes: &[u8; 32] = bytes.first_chunk().ok_or(NoteKeyError::InvalidRepr)?;
        let inner = Fp::from_repr(*fp_bytes)
            .into_option()
            .ok_or(NoteKeyError::InvalidRepr)?;
        let tail: &[u8; 5] = bytes.last_chunk().ok_or(NoteKeyError::InvalidPrefix)?;
        let (&depth_byte, index_slice) = tail.split_first().ok_or(NoteKeyError::InvalidPrefix)?;
        let depth = NonZeroU8::new(depth_byte).ok_or(NoteKeyError::InvalidPrefix)?;
        if depth.get() > GGM_TREE_DEPTH {
            return Err(NoteKeyError::InvalidPrefix);
        }
        let index_bytes: &[u8; 4] = index_slice
            .first_chunk()
            .ok_or(NoteKeyError::InvalidPrefix)?;

        let index = u32::from_le_bytes(*index_bytes);
        let max_index = 1u32
            .checked_shl(u32::from(depth.get()) * LOG2_ARITY)
            .map_or(u32::MAX, |size| size - 1u32);
        if index > max_index {
            return Err(NoteKeyError::InvalidPrefix);
        }
        Ok(Self {
            inner,
            depth,
            index,
        })
    }
}

impl From<NotePrefixedKey> for [u8; 37] {
    fn from(key: NotePrefixedKey) -> [u8; 37] {
        // [repr(32) | depth(1) | index_le(4)]
        #[expect(clippy::expect_used, reason = "length is statically known")]
        [
            key.inner.to_repr().as_slice(),
            &[key.depth.get()],
            &key.index.to_le_bytes(),
        ]
        .concat()
        .try_into()
        .expect("32 + 1 + 4 = 37")
    }
}

#[derive(Debug)]
pub enum NoteKeyError {
    InvalidRepr,
    InvalidPrefix,
}

/// Maximum valid [`EpochIndex`] covered by the tree.
#[must_use]
pub const fn epoch_max() -> u32 {
    match 1u32.checked_shl(EPOCH_BITS) {
        | Some(size) => size - 1u32,
        | None => u32::MAX,
    }
}

/// One GGM tree step: `Poseidon(tag, node, chunk)`.
fn ggm_step(node: Fp, chunk: u8) -> Fp {
    debug_assert!(chunk < ARITY, "chunk must be less than arity");
    let domain = Fp::from_u128(u128::from_le_bytes(*NOTE_NULLIFIER_DOMAIN));
    Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
        domain,
        node,
        Fp::from(u64::from(chunk)),
    ])
}

/// Recursive GGM walk: consume the top `LOG2_ARITY` bits of `leaf` at each
/// level, MSB-first, for `remaining` levels.
fn ggm_walk(node: Fp, leaf: u32, remaining: u8) -> Fp {
    match remaining.checked_sub(1) {
        | None => node,
        | Some(next) => {
            let shift = u32::from(next) * LOG2_ARITY;
            let chunk_u32 = (leaf >> shift) & CHUNK_MASK;
            #[expect(
                clippy::expect_used,
                reason = "chunk bits fit in u8 because LOG2_ARITY <= u8::BITS"
            )]
            let chunk = u8::try_from(chunk_u32).expect("chunk fits in u8");
            ggm_walk(ggm_step(node, chunk), leaf, next)
        },
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    #[test]
    fn distinct_leaves() {
        let key =
            NoteMasterKey::try_from(Fp::random(&mut StdRng::seed_from_u64(0)).to_repr()).unwrap();

        assert_ne!(
            key.derive_nullifier(EpochIndex(0)),
            key.derive_nullifier(EpochIndex(1)),
        );
    }

    #[test]
    fn distinct_keys() {
        let mut rng = StdRng::seed_from_u64(0);
        let key1 = NoteMasterKey::try_from(Fp::random(&mut rng).to_repr()).unwrap();
        let key2 = NoteMasterKey::try_from(Fp::random(&mut rng).to_repr()).unwrap();

        assert_ne!(
            key1.derive_nullifier(EpochIndex(42)),
            key2.derive_nullifier(EpochIndex(42)),
        );
    }

    /// Delegate covering epoch 0 produces the same nullifier as the root.
    #[test]
    fn delegate_matches_root() {
        let root =
            NoteMasterKey::try_from(Fp::random(&mut StdRng::seed_from_u64(0)).to_repr()).unwrap();
        let cover_end = u32::from(ARITY) * u32::from(ARITY) - 1;
        for delegate in root.derive_note_delegates(0..=cover_end) {
            assert_eq!(
                delegate.derive_nullifier(EpochIndex(0)),
                root.derive_nullifier(EpochIndex(0)),
                "mismatch at depth {:?}",
                delegate.depth.get()
            );
        }
    }

    #[test]
    fn tight_cover() {
        let root = NoteMasterKey(Fp::from(1u64));
        let delegates = root.derive_note_delegates(0..=5);
        assert!(!delegates.is_empty());
        let union_end = delegates
            .iter()
            .map(|dk| *dk.range().end())
            .max()
            .expect("non-empty delegates");
        assert_eq!(union_end, 5);
        let union_start = delegates
            .iter()
            .map(|dk| *dk.range().start())
            .min()
            .expect("non-empty delegates");
        assert_eq!(union_start, 0);
    }

    #[test]
    fn single_epoch_delegate() {
        let root = NoteMasterKey(Fp::from(1u64));
        let delegates = root.derive_note_delegates(42..=42);
        assert_eq!(delegates.len(), 1);
        assert_eq!(delegates[0].range(), 42..=42);
        assert_eq!(delegates[0].depth.get(), GGM_TREE_DEPTH);
    }

    #[test]
    #[should_panic(expected = "must not step beyond leaf")]
    fn step_beyond_leaf_panics() {
        let root = NoteMasterKey(Fp::from(1u64));
        let mut key = root.step(0);
        for _ in 1..GGM_TREE_DEPTH {
            key = key.step(0);
        }
        let _boom = key.step(0);
    }

    #[test]
    fn full_range_from_master() {
        let root = NoteMasterKey(Fp::from(1u64));
        let delegates = root.derive_note_delegates(0..=epoch_max());
        assert_eq!(delegates.len(), usize::from(ARITY));
        for (idx, delegate) in delegates.iter().enumerate() {
            assert_eq!(delegate.depth.get(), 1);
            let idx_u32 = u32::try_from(idx).unwrap();
            assert_eq!(delegate.index, idx_u32);
        }
        assert_eq!(*delegates[0].range().start(), 0);
        assert_eq!(
            *delegates[usize::from(ARITY) - 1].range().end(),
            epoch_max()
        );
    }

    #[test]
    fn last_epoch_delegate() {
        let root = NoteMasterKey(Fp::from(1u64));
        let delegates = root.derive_note_delegates(epoch_max()..=epoch_max());
        assert_eq!(delegates.len(), 1);
        assert_eq!(delegates[0].range(), epoch_max()..=epoch_max());
        assert_eq!(delegates[0].depth.get(), GGM_TREE_DEPTH);
    }

    #[test]
    #[should_panic(expected = "does not cover requested range")]
    fn disjoint_range_panics() {
        let root = NoteMasterKey(Fp::from(1u64));
        // Depth-2 prefix rooted at chunk (0, 0) covers epochs
        // [0 .. ARITY^(D-2)).
        let prefix = root.step(0).step(0);
        let outside = *prefix.range().end() + 1;
        let _delegates = prefix.derive_note_delegates(outside..=outside);
    }

    #[test]
    #[should_panic(expected = "does not cover requested range")]
    fn partial_overlap_panics() {
        let root = NoteMasterKey(Fp::from(1u64));
        let prefix = root.step(0).step(0);
        let partial_hi = *prefix.range().end() + 1;
        let _delegates = prefix.derive_note_delegates(0..=partial_hi);
    }
}
