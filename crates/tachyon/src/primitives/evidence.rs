use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};

use crate::pasta::Fp;

/// The root of a Poseidon Merkle tree over sealed bucket digests.
///
/// A one-leaf tree's root is the leaf digest itself, so every subtree root
/// along a path has this type.
///
/// # Injectivity
///
/// A root is a [leaf digest](crate::digest::poseidon::evidence_tree_leaf) or a
/// [node digest](crate::digest::poseidon::evidence_tree_node). The two have
/// different tags, so under the
/// [Poseidon assumption](crate::stamp::proof#assumptions) no element is known
/// to be both. A leaf digest determines the eight header elements of one
/// bucket. A node digest determines its four subtree roots in order. A root
/// built from bucket headers therefore determines the shape of its tree and
/// the bucket header at every leaf.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct EvidenceTreeRoot(pub Fp);
