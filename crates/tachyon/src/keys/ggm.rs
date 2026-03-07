//! GGM tree PRF for nullifier derivation.
//!
//! A binary-tree pseudorandom function instantiated from Poseidon.
//! Each step hashes the current node with a bit (0 = left, 1 = right).
//! Traversal is MSB-first so that left subtrees cover lower-numbered
//! leaves, enabling contiguous-range prefix delegation.

use core::num::NonZeroU8;

use ff::PrimeField as _;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use super::note::NoteKey;
use crate::{constants::NULLIFIER_DOMAIN, note::Nullifier, primitives::Epoch};

/// GGM tree depth — 32-bit epochs cover ~4 billion values.
pub(super) const MAX_TREE_DEPTH: u8 = 32;

/// Marker for a master (root, depth 0) note key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Master;

/// A GGM subtree identified by its depth and node index.
///
/// At depth `d` there are `2^d` nodes. Node `i` covers the contiguous epoch
/// range `[i * 2^(32-d) ..= (i+1) * 2^(32-d) - 1]`. The index encodes the
/// `d`-bit path from root (MSB-first).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Prefixed {
    depth: NonZeroU8,
    index: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub enum PrefixedError {
    DepthOutOfRange,
    IndexOutOfRange,
}

impl Prefixed {
    /// Create a new prefix identifying the specified node.
    pub const fn new(depth: NonZeroU8, index: u32) -> Result<Self, PrefixedError> {
        if depth.get() >= MAX_TREE_DEPTH {
            return Err(PrefixedError::DepthOutOfRange);
        }

        let height = MAX_TREE_DEPTH - depth.get();
        if index > (u32::MAX >> height) {
            return Err(PrefixedError::IndexOutOfRange);
        }

        Ok(Self { depth, index })
    }

    /// The node index at this depth.
    pub const fn index(self) -> u32 {
        self.index
    }

    /// First leaf index in the covered range.
    pub const fn first(self) -> u32 {
        let height = MAX_TREE_DEPTH - self.depth.get();
        self.index << height
    }

    /// Last leaf index in the covered range (inclusive).
    pub const fn last(self) -> u32 {
        self.first() | (u32::MAX >> self.depth.get())
    }

    /// Decompose the epoch range `[start..end)` into the minimal set of dyadic
    /// intervals.
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

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Master {}
    impl Sealed for super::Prefixed {}
}

pub trait GGMTreeDepth: Copy + sealed::Sealed {
    fn depth(self) -> u8;
}

impl GGMTreeDepth for Master {
    fn depth(self) -> u8 {
        u8::MIN
    }
}

impl GGMTreeDepth for Prefixed {
    fn depth(self) -> u8 {
        self.depth.get()
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
    /// Derive a nullifier for epoch `flavor`: $\mathsf{nf} =
    /// F_{\mathsf{mk}}(\text{flavor})$.
    #[must_use]
    pub fn derive_nullifier(&self, flavor: Epoch) -> Nullifier {
        Nullifier::from(self.evaluate(u32::from(flavor)))
    }

    /// Derive epoch-restricted prefix keys for OSS delegation.
    ///
    /// Each returned key can evaluate the PRF only for epochs within
    /// the subtree identified by its prefix.
    pub fn derive_note_delegates(
        &self,
        prefixes: impl IntoIterator<Item = Prefixed>,
    ) -> Vec<NoteKey<Prefixed>> {
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

impl NoteKey<Prefixed> {
    /// Derive a nullifier for epoch `flavor`, returning `None` if the
    /// epoch is outside this prefix's authorized range.
    #[must_use]
    pub fn derive_nullifier(&self, flavor: Epoch) -> Option<Nullifier> {
        let epoch = u32::from(flavor);
        if epoch < self.prefix.first() || epoch > self.prefix.last() {
            return None;
        }
        Some(Nullifier::from(self.evaluate(epoch)))
    }
}

/// One GGM tree step: `Poseidon(tag, node, bit)`.
pub(super) fn step(node: Fp, bit: Fp) -> Fp {
    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    let personalization = Fp::from_u128(u128::from_le_bytes(*NULLIFIER_DOMAIN));
    Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([personalization, node, bit])
}

/// Recursive GGM walk: consume the top bit of `leaf` at each level,
/// MSB-first, for `remaining` levels.
pub(super) fn walk(node: Fp, leaf: u32, remaining: u8) -> Fp {
    match remaining.checked_sub(1) {
        | None => node,
        | Some(next) => {
            let bit = (leaf >> next) & 0b0001;
            walk(step(node, Fp::from(u64::from(bit))), leaf, next)
        },
    }
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
            .map(|depth| Prefixed::new(NonZeroU8::new(depth).unwrap(), 0).unwrap())
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
    fn prefixed_new_rejects_invalid() {
        // depth=0 is prevented by NonZeroU8 parameter type
        // depth > TREE_DEPTH is invalid
        assert_eq!(
            Prefixed::new(NonZeroU8::new(33u8).unwrap(), 0).unwrap_err(),
            PrefixedError::DepthOutOfRange
        );
        // index >= 2^depth is invalid
        assert_eq!(
            Prefixed::new(NonZeroU8::new(1u8).unwrap(), 2).unwrap_err(),
            PrefixedError::IndexOutOfRange
        );
        assert_eq!(
            Prefixed::new(NonZeroU8::new(2u8).unwrap(), 4).unwrap_err(),
            PrefixedError::IndexOutOfRange
        );
        // depth == MAX_TREE_DEPTH (single leaf) is not delegable.
        assert_eq!(
            Prefixed::new(NonZeroU8::new(32u8).unwrap(), 0).unwrap_err(),
            PrefixedError::DepthOutOfRange
        );
        // Rightmost valid nodes at each depth.
        assert_eq!(
            Prefixed::new(NonZeroU8::new(1u8).unwrap(), 1).unwrap(),
            Prefixed {
                depth: NonZeroU8::new(1u8).unwrap(),
                index: 1
            }
        );
        assert_eq!(
            Prefixed::new(NonZeroU8::new(2u8).unwrap(), 3).unwrap(),
            Prefixed {
                depth: NonZeroU8::new(2u8).unwrap(),
                index: 3
            }
        );
        assert_eq!(
            Prefixed::new(NonZeroU8::new(31u8).unwrap(), u32::MAX >> 1).unwrap(),
            Prefixed {
                depth: NonZeroU8::new(31u8).unwrap(),
                index: u32::MAX >> 1
            }
        );
    }

    #[test]
    fn prefixed_epoch_range() {
        let minute = Prefixed::new(NonZeroU8::new(26u8).unwrap(), 1).unwrap();
        assert_eq!(minute.first(), 64);
        assert_eq!(minute.last(), 127);

        let half = Prefixed::new(NonZeroU8::new(1u8).unwrap(), 0).unwrap();
        assert_eq!(half.first(), 0);
        assert_eq!(half.last(), 0b0111_1111_1111_1111_1111_1111_1111_1111);

        // Rightmost subtree at depth 1 covers [2^31 ..= u32::MAX].
        let upper_half = Prefixed::new(NonZeroU8::new(1u8).unwrap(), 1).unwrap();
        assert_eq!(
            upper_half.first(),
            0b1000_0000_0000_0000_0000_0000_0000_0000
        );
        assert_eq!(upper_half.last(), u32::MAX);
    }

    #[test]
    fn cover_simple() {
        let cover = Prefixed::tight(0, 6);
        // [0..=3] at depth 30, [4..=5] at depth 31.
        assert_eq!(cover.len(), 2);
        assert_eq!(cover[0].first(), 0);
        assert_eq!(cover[0].last(), 3);
        assert_eq!(cover[1].first(), 4);
        assert_eq!(cover[1].last(), 5);

        let single = Prefixed::tight(0, 4);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].first(), 0);
        assert_eq!(single[0].last(), 3);
    }
}
