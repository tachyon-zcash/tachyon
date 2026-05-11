//! GGM tree PRF for nullifier derivation.
//!
//! A `k`-ary tree pseudorandom function instantiated from Poseidon, with
//! `k = GGM_ARITY`. Each step hashes the current node with a
//! `GGM_CHUNK_SIZE`-bit chunk of the epoch index (MSB-first), so that
//! left subtrees cover lower-numbered leaves and contiguous ranges map
//! to sparse prefix covers.
//!
//! The tree is sized to tile the full epoch space exactly:
//! `GGM_ARITY^GGM_DEPTH == GGM_MAX_INDEX + 1`.

use alloc::vec::Vec;
use core::{fmt, num::NonZeroU8, ops::RangeInclusive};

use pasta_curves::Fp;

use crate::{constants::EPOCH_MAX, digest::poseidon, note::Nullifier, primitives::EpochIndex};

/// Maximum leaf index. Equal to [`EPOCH_MAX`] so every epoch maps to a
/// distinct leaf.
pub const GGM_MAX_INDEX: u32 = EPOCH_MAX;

/// Children per non-leaf node. Must be a power of two >= 2.
pub const GGM_TREE_ARITY: u8 = 4;

/// Bits of the leaf index absorbed per GGM step.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "const arithmetic"
)]
pub const GGM_CHUNK_SIZE: u8 = GGM_TREE_ARITY.trailing_zeros() as u8;

/// Mask covering exactly one chunk: low `GGM_CHUNK_SIZE` bits set.
pub const GGM_CHUNK_MASK: u8 = GGM_TREE_ARITY - 1;

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "const arithmetic"
)]
/// Tree depth such that `ARITY ** DEPTH == MAX_INDEX + 1`.
pub const GGM_TREE_DEPTH: u8 = GGM_MAX_INDEX.trailing_ones() as u8 / GGM_CHUNK_SIZE;

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

impl NoteMasterKey {
    /// Descend one level from the root of the GGM tree.
    #[must_use]
    pub fn step(&self, chunk: u8) -> NotePrefixedKey {
        debug_assert!(chunk < GGM_TREE_ARITY, "chunk must be less than arity");
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
        Nullifier::from(ggm_walk(self.0, flavor.0, GGM_TREE_DEPTH))
    }

    /// Derive epoch-restricted prefix keys covering the specified range.
    ///
    /// Recursively descends the tree, emitting fully-covered nodes and
    /// only hashing children that overlap the range.
    #[must_use]
    pub fn derive_note_delegates(&self, range: RangeInclusive<u32>) -> Vec<NotePrefixedKey> {
        assert!(
            *range.end() <= GGM_MAX_INDEX,
            "range {range:?} exceeds epoch space {:?}",
            0u32..=GGM_MAX_INDEX,
        );

        let child_size = 1u32 << ((GGM_TREE_DEPTH - 1) * GGM_CHUNK_SIZE);
        let mut result = Vec::new();
        for chunk in 0u8..GGM_TREE_ARITY {
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

/// A Tachyon prefix key for range-restricted nullifier delegation.
///
/// At depth `d` there are `GGM_ARITY^d` nodes. Node `i` covers the contiguous
/// epoch range of size `GGM_ARITY^(GGM_DEPTH - d)`. At depth
/// `GGM_DEPTH`, a key is a leaf whose `index` equals its single epoch.
#[derive(Clone, Copy, PartialEq, Eq)]
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
        let span_bits = levels_remaining * GGM_CHUNK_SIZE;
        let first = self.index << span_bits;
        let mask = 1u32
            .checked_shl(u32::from(span_bits))
            .map_or(u32::MAX, |size| size - 1u32);
        let last = first | mask;
        first..=last
    }

    /// Descend one level in the GGM tree.
    ///
    /// # Panics
    ///
    /// Panics if already at a leaf (depth == `GGM_DEPTH`).
    #[must_use]
    pub fn step(&self, chunk: u8) -> Self {
        assert!(
            self.depth.get() < GGM_TREE_DEPTH,
            "must not step beyond leaf"
        );
        debug_assert!(chunk < GGM_TREE_ARITY, "chunk must be less than arity");
        Self {
            inner: ggm_step(self.inner, chunk),
            #[expect(clippy::expect_used, reason = "nonzero plus one is not zero")]
            depth: NonZeroU8::new(self.depth.get() + 1).expect("not zero"),
            index: self.index * u32::from(GGM_TREE_ARITY) + u32::from(chunk),
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
            let next_depth = self.depth.get() + 1;
            let child_span_bits = (GGM_TREE_DEPTH - next_depth) * GGM_CHUNK_SIZE;
            let child_size = 1u32 << child_span_bits;
            let base = *self.range().start();

            let mut result = Vec::new();
            for chunk in 0u8..GGM_TREE_ARITY {
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
        Nullifier::from(ggm_walk(self.inner, flavor.0, remaining))
    }
}

/// Candidate starts for a cover of `[start..=end]`, rounded down to
/// `GGM_ARITY^j`-boundaries. Sorted by overage descending (`[0..=end]` first,
/// `[start..=end]` last), duplicates collapsed.
///
/// The caller picks based on its own effort/privacy trade-off; see the book's
/// "Delegation window" section for rationale.
///
/// # Panics
///
/// Panics if the range is empty or `end > GGM_MAX_INDEX`.
#[must_use]
pub fn cover_candidates(range: RangeInclusive<u32>) -> Vec<RangeInclusive<u32>> {
    assert!(!range.is_empty(), "range must not be empty");
    assert!(*range.end() <= GGM_MAX_INDEX, "end exceeds epoch space");

    let mut candidates: Vec<RangeInclusive<u32>> = Vec::new();
    for j in 0u8..=GGM_TREE_DEPTH {
        let alignment_bits = j * GGM_CHUNK_SIZE;
        let s_j = match 1u32.checked_shl(u32::from(alignment_bits)) {
            | Some(alignment) => range.start() & !(alignment - 1u32),
            | None => 0u32,
        };
        if candidates.last().is_some_and(|prev| *prev.start() == s_j) {
            continue;
        }
        candidates.push(s_j..=*range.end());
    }
    candidates.reverse();
    candidates
}

/// One GGM tree step: `Poseidon(tag, node, chunk)`.
fn ggm_step(node: Fp, chunk: u8) -> Fp {
    debug_assert!(chunk < GGM_TREE_ARITY, "chunk must be less than arity");
    poseidon::ggm_step(node, chunk)
}

/// Recursive GGM walk: consume the top `GGM_CHUNK_SIZE` bits of `leaf` at each
/// level, MSB-first, for `remaining` levels.
fn ggm_walk(node: Fp, leaf: u32, remaining: u8) -> Fp {
    match remaining.checked_sub(1) {
        | None => node,
        | Some(next) => {
            let shift = next * GGM_CHUNK_SIZE;
            let chunk_u32 = (leaf >> shift) & u32::from(GGM_CHUNK_MASK);
            #[expect(
                clippy::expect_used,
                reason = "chunk bits fit in u8 because GGM_CHUNK_SIZE <= u8::BITS"
            )]
            let chunk = u8::try_from(chunk_u32).expect("chunk fits in u8");
            ggm_walk(ggm_step(node, chunk), leaf, next)
        },
    }
}

impl fmt::Debug for NoteMasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoteMasterKey").finish_non_exhaustive()
    }
}

impl fmt::Debug for NotePrefixedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotePrefixedKey")
            .field("depth", &self.depth)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    #[test]
    fn distinct_leaves() {
        let rng = &mut StdRng::seed_from_u64(0);
        let key = NoteMasterKey(Fp::random(rng));

        assert_ne!(
            key.derive_nullifier(EpochIndex(0)),
            key.derive_nullifier(EpochIndex(1)),
        );
    }

    /// Delegate covering epoch 0 produces the same nullifier as the root.
    #[test]
    fn delegate_matches_root() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = NoteMasterKey(Fp::random(rng));
        let cover_end = u32::from(GGM_TREE_ARITY) * u32::from(GGM_TREE_ARITY) - 1;
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
        let rng = &mut StdRng::seed_from_u64(0);
        let root = NoteMasterKey(Fp::random(rng));
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
        let rng = &mut StdRng::seed_from_u64(0);
        let root = NoteMasterKey(Fp::random(rng));
        let delegates = root.derive_note_delegates(42..=42);
        assert_eq!(delegates.len(), 1);
        assert_eq!(delegates[0].range(), 42..=42);
        assert_eq!(delegates[0].depth.get(), GGM_TREE_DEPTH);
    }

    #[test]
    #[should_panic(expected = "must not step beyond leaf")]
    fn step_beyond_leaf_panics() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = NoteMasterKey(Fp::random(rng));
        let mut key = root.step(0);
        for _ in 1..GGM_TREE_DEPTH {
            key = key.step(0);
        }
        let _boom = key.step(0);
    }

    #[test]
    fn full_range_from_master() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = NoteMasterKey(Fp::random(rng));
        let delegates = root.derive_note_delegates(0..=GGM_MAX_INDEX);
        assert_eq!(delegates.len(), usize::from(GGM_TREE_ARITY));
        for (idx, delegate) in delegates.iter().enumerate() {
            assert_eq!(delegate.depth.get(), 1);
            let idx_u32 = u32::try_from(idx).unwrap();
            assert_eq!(delegate.index, idx_u32);
        }
        assert_eq!(*delegates[0].range().start(), 0);
        assert_eq!(
            *delegates[usize::from(GGM_TREE_ARITY) - 1].range().end(),
            GGM_MAX_INDEX
        );
    }

    #[test]
    fn last_epoch_delegate() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = NoteMasterKey(Fp::random(rng));
        let delegates = root.derive_note_delegates(GGM_MAX_INDEX..=GGM_MAX_INDEX);
        assert_eq!(delegates.len(), 1);
        assert_eq!(delegates[0].range(), GGM_MAX_INDEX..=GGM_MAX_INDEX);
        assert_eq!(delegates[0].depth.get(), GGM_TREE_DEPTH);
    }

    #[test]
    #[should_panic(expected = "does not cover requested range")]
    fn disjoint_range_panics() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = NoteMasterKey(Fp::random(rng));
        // Depth-2 prefix rooted at chunk (0, 0) covers epochs
        // [0 .. GGM_ARITY^(D-2)).
        let prefix = root.step(0).step(0);
        let outside = *prefix.range().end() + 1;
        let _delegates = prefix.derive_note_delegates(outside..=outside);
    }

    #[test]
    #[should_panic(expected = "does not cover requested range")]
    fn partial_overlap_panics() {
        let rng = &mut StdRng::seed_from_u64(0);
        let root = NoteMasterKey(Fp::random(rng));
        let prefix = root.step(0).step(0);
        let partial_hi = *prefix.range().end() + 1;
        let _delegates = prefix.derive_note_delegates(0..=partial_hi);
    }

    #[test]
    fn cover_candidates_start_zero_is_singleton() {
        let candidates = cover_candidates(0..=100);
        assert_eq!(candidates, alloc::vec![0..=100]);
    }

    #[test]
    fn cover_candidates_concrete_k4() {
        // At GGM_CHUNK_SIZE=2, start=23 rounds down to: 23 (4^0), 20 (4^1),
        // 16 (4^2), 0 (4^3 through epoch top). Effort-descending order
        // after reverse:
        let candidates = cover_candidates(23..=47);
        assert_eq!(candidates, alloc::vec![0..=47, 16..=47, 20..=47, 23..=47]);
    }

    #[test]
    fn cover_candidates_last_is_exact() {
        for (start, end) in [(0u32, 0u32), (5, 10), (42, 42), (100, 200)] {
            let candidates = cover_candidates(start..=end);
            assert_eq!(
                *candidates.last().expect("non-empty"),
                start..=end,
                "last entry must equal input range",
            );
        }
    }

    #[test]
    fn cover_candidates_first_has_smallest_start() {
        for (start, end) in [(1u32, 10u32), (23, 47), (123, 200)] {
            let candidates = cover_candidates(start..=end);
            let first_start = *candidates.first().expect("non-empty").start();
            for candidate in &candidates {
                assert!(
                    first_start <= *candidate.start(),
                    "first candidate must have smallest start",
                );
            }
        }
    }

    #[test]
    fn cover_candidates_epoch_max_no_panic() {
        let max = GGM_MAX_INDEX;
        assert!(!cover_candidates(0..=max).is_empty());
        assert!(!cover_candidates(max..=max).is_empty());
        assert!(!cover_candidates(42u32..=max).is_empty());
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
        let prefix = root.step(0);
        let dbg = alloc::format!("{prefix:?}");
        assert!(dbg.contains("NotePrefixedKey"), "must name the type");
        assert!(dbg.contains("depth"), "must show depth");
        assert!(dbg.contains("index"), "must show index");
    }
}
