//! GGM tree PRF for nullifier derivation.
//!
//! A binary-tree pseudorandom function instantiated from Poseidon.
//! Each step hashes the current node with a bit (0 = left, 1 = right).
//! Traversal is MSB-first so that left subtrees cover lower-numbered
//! leaves, enabling contiguous-range prefix delegation.

#![allow(clippy::redundant_pub_crate, reason = "pub(crate) in private module")]

use ff::Field as _;
use pasta_curves::Fp;

use crate::poseidon;

/// GGM tree depth — 32-bit epochs cover ~4 billion values.
pub(crate) const TREE_DEPTH: usize = 32;

/// GGM tree PRF: walk all 32 bits of `leaf` from root `key`.
///
/// Traverses MSB-first (bit 31 to bit 0) so that left subtrees cover
/// lower-numbered leaves, enabling contiguous-range prefix delegation.
pub(crate) fn evaluate(key: Fp, leaf: u32) -> Fp {
    walk(key, leaf, TREE_DEPTH, 0)
}

/// Descend `depth` left-child (zero-bit) levels from `root`.
///
/// Returns the intermediate node covering epochs `0..2^(32 - depth)`.
pub(crate) fn prefix_node(root: Fp, depth: usize) -> Fp {
    assert!(depth <= TREE_DEPTH, "depth exceeds GGM tree depth");
    let mut node = root;
    for _ in 0..depth {
        node = poseidon::hash([node, Fp::ZERO]);
    }
    node
}

/// Continue a GGM walk from an intermediate node at `start_depth`.
///
/// Walks bits `(31 - start_depth)` down to `0` of `leaf`.
pub(crate) fn evaluate_from(node: Fp, leaf: u32, start_depth: usize) -> Fp {
    walk(node, leaf, TREE_DEPTH, start_depth)
}

/// Internal: walk bits of `leaf` from `start_depth` to `total_depth`,
/// MSB-first.
fn walk(mut node: Fp, leaf: u32, total_depth: usize, start_depth: usize) -> Fp {
    assert!(
        start_depth <= total_depth,
        "start_depth exceeds total_depth"
    );
    for idx in start_depth..total_depth {
        let bit_pos = total_depth - 1 - idx;
        let bit = u64::from((leaf >> bit_pos) & 1);
        node = poseidon::hash([node, Fp::from(bit)]);
    }
    node
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_leaves() {
        let key = Fp::from(123u64);
        assert_ne!(evaluate(key, 0), evaluate(key, 1));
    }

    #[test]
    fn distinct_keys() {
        assert_ne!(evaluate(Fp::from(1u64), 42), evaluate(Fp::from(2u64), 42),);
    }

    /// Full-depth prefix node equals direct evaluation of leaf 0.
    #[test]
    fn prefix_full_depth_equals_leaf_zero() {
        let key = Fp::from(77u64);
        assert_eq!(prefix_node(key, TREE_DEPTH), evaluate(key, 0));
    }

    /// Prefix node + suffix evaluation equals direct evaluation for
    /// leaves covered by the prefix subtree.
    #[test]
    fn prefix_then_suffix_equals_direct() {
        let key = Fp::from(77u64);
        for depth in [0, 1, 8, 16, 31, 32] {
            let prefix = prefix_node(key, depth);
            let result = evaluate_from(prefix, 0, depth);
            assert_eq!(result, evaluate(key, 0), "mismatch at depth {depth}");
        }
    }
}
