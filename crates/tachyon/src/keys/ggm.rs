//! GGM tree PRF for nullifier derivation.
//!
//! A binary-tree pseudorandom function instantiated from Poseidon.
//! Each step hashes the current node with a bit (0 = left, 1 = right).
//! Traversal is MSB-first so that left subtrees cover lower-numbered
//! leaves, enabling contiguous-range prefix delegation.

use alloc::vec::Vec;
use core::{fmt, num::NonZeroU8, ops::RangeInclusive};

use ff::PrimeField as _;
// TODO(#39): replace halo2_poseidon with Ragu Poseidon params
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use crate::{constants::NOTE_NULLIFIER_DOMAIN, note::Nullifier, primitives::EpochIndex};

/// GGM tree depth — 32-bit epochs, leaves at depth 32.
pub const GGM_TREE_DEPTH: u8 = 32;

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
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NoteMasterKey(pub(crate) Fp);

impl fmt::Debug for NoteMasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoteMasterKey").finish_non_exhaustive()
    }
}

impl NoteMasterKey {
    /// Descend one level from the root of the GGM tree.
    #[must_use]
    pub fn step(&self, direction: bool) -> NotePrefixedKey {
        #[expect(clippy::expect_used, reason = "depth 1 is always valid")]
        NotePrefixedKey {
            inner: ggm_step(self.0, direction),
            depth: NonZeroU8::new(1).expect("1 != 0"),
            index: u32::from(direction),
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
        // Children at depth 1 each own half of the u32 epoch space.
        let split: u32 = u32::MAX >> 1;

        let mut result = Vec::new();
        if *range.start() <= split {
            let lo = *range.start()..=(*range.end()).min(split);
            result.extend(self.step(false).derive_note_delegates(lo));
        }
        if *range.end() > split {
            let hi = (*range.start()).max(split + 1)..=*range.end();
            result.extend(self.step(true).derive_note_delegates(hi));
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
/// At depth `d` there are `2^d` nodes. Node `i` covers the contiguous epoch
/// range `[i * 2^(32-d) ..= (i+1) * 2^(32-d) - 1]`. At depth 32, a key
/// is a leaf whose `index` equals the epoch.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NotePrefixedKey {
    /// GGM tree node value.
    pub(crate) inner: Fp,
    /// The number of levels already descended.
    pub(crate) depth: NonZeroU8,
    /// Node index at this depth.
    pub(crate) index: u32,
}

impl fmt::Debug for NotePrefixedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotePrefixedKey")
            .field("depth", &self.depth)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl NotePrefixedKey {
    /// The epoch range covered by this key.
    #[must_use]
    pub const fn range(self) -> RangeInclusive<u32> {
        match self.depth.get() {
            | GGM_TREE_DEPTH => self.index..=self.index,
            | depth => {
                let first = self.index << (GGM_TREE_DEPTH - depth);
                let last = first | (u32::MAX >> depth);
                first..=last
            },
        }
    }

    /// Descend one level in the GGM tree.
    ///
    /// # Panics
    ///
    /// Panics if already at a leaf (depth == `GGM_TREE_DEPTH`).
    #[must_use]
    pub fn step(&self, direction: bool) -> Self {
        assert!(
            self.depth.get() < GGM_TREE_DEPTH,
            "must not step beyond leaf"
        );
        Self {
            inner: ggm_step(self.inner, direction),
            #[expect(clippy::expect_used, reason = "nonzero plus one is not zero")]
            depth: NonZeroU8::new(self.depth.get() + 1).expect("not zero"),
            index: self.index * 2 + u32::from(direction),
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
            // This node exactly covers the requested range.
            alloc::vec![*self]
        } else {
            // This node is larger than the requested range.
            let next_depth = u32::from(self.depth.get() + 1);
            let next_dyad_size = u32::MAX.checked_shr(next_depth).unwrap_or(0);
            let split = *self.range().start() | next_dyad_size;

            let mut result = Vec::new();
            if *range.start() <= split {
                let lo = *range.start()..=(*range.end()).min(split);
                result.extend(self.step(false).derive_note_delegates(lo));
            }
            if *range.end() > split {
                let hi = (*range.start()).max(split + 1)..=*range.end();
                result.extend(self.step(true).derive_note_delegates(hi));
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
        if index > u32::MAX >> (GGM_TREE_DEPTH - depth.get()) {
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

/// One GGM tree step: `Poseidon(tag, node, bit)`.
fn ggm_step(node: Fp, bit: bool) -> Fp {
    let domain = Fp::from_u128(u128::from_le_bytes(*NOTE_NULLIFIER_DOMAIN));
    Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([domain, node, Fp::from(bit)])
}

/// Recursive GGM walk: consume the top bit of `leaf` at each level,
/// MSB-first, for `remaining` levels.
fn ggm_walk(node: Fp, leaf: u32, remaining: u8) -> Fp {
    match remaining.checked_sub(1) {
        | None => node,
        | Some(next) => {
            let bit = (leaf >> next) & 1 != 0;
            ggm_walk(ggm_step(node, bit), leaf, next)
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
        // Single delegate covering [0..=63]
        for delegate in root.derive_note_delegates(0..=63) {
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
        // [0..=3] and [4..=5]
        assert_eq!(delegates.len(), 2);
        assert_eq!(delegates[0].range(), 0..=3);
        assert_eq!(delegates[1].range(), 4..=5);
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
        let mut key = root.step(false);
        for _ in 1..GGM_TREE_DEPTH {
            key = key.step(false);
        }
        // Now at depth 32 (leaf) — one more step should panic.
        let _boom = key.step(false);
    }

    #[test]
    fn full_range_from_master() {
        let root = NoteMasterKey(Fp::from(1u64));
        let delegates = root.derive_note_delegates(0..=u32::MAX);
        assert_eq!(delegates.len(), 2);
        assert_eq!(delegates[0].range(), 0..=(u32::MAX >> 1u32));
        assert_eq!(delegates[1].range(), (u32::MAX >> 1u32) + 1..=u32::MAX);
    }

    #[test]
    fn last_epoch_delegate() {
        let root = NoteMasterKey(Fp::from(1u64));
        let delegates = root.derive_note_delegates(u32::MAX..=u32::MAX);
        assert_eq!(delegates.len(), 1);
        assert_eq!(delegates[0].range(), u32::MAX..=u32::MAX);
        assert_eq!(delegates[0].depth.get(), GGM_TREE_DEPTH);
    }

    #[test]
    #[should_panic(expected = "does not cover requested range")]
    fn disjoint_range_panics() {
        let root = NoteMasterKey(Fp::from(1u64));
        // depth-2 prefix covering [0..=0x3FFF_FFFF].
        let prefix = root.step(false).step(false);
        let _delegates = prefix.derive_note_delegates(0x8000_0000..=0x8000_0010);
    }

    #[test]
    #[should_panic(expected = "does not cover requested range")]
    fn partial_overlap_panics() {
        let root = NoteMasterKey(Fp::from(1u64));
        // depth-2 prefix covering [0..=0x3FFF_FFFF].
        let prefix = root.step(false).step(false);
        let _delegates = prefix.derive_note_delegates(0..=0x4000_0000);
    }

    #[test]
    fn debug_master_key_redacts_value() {
        let key = NoteMasterKey(Fp::from(0xDEAD_BEEFu64));
        let dbg = alloc::format!("{key:?}");
        assert!(dbg.contains("NoteMasterKey"), "must name the type");
        assert!(!dbg.contains("DEAD"), "must not leak field element");
        assert!(!dbg.contains("dead"), "must not leak field element");
    }

    #[test]
    fn debug_prefixed_key_shows_coordinates_hides_inner() {
        let root = NoteMasterKey(Fp::from(1u64));
        let prefix = root.step(false);
        let dbg = alloc::format!("{prefix:?}");
        assert!(dbg.contains("NotePrefixedKey"), "must name the type");
        assert!(dbg.contains("depth"), "must show depth");
        assert!(dbg.contains("index"), "must show index");
    }
}
