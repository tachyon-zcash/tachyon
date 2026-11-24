use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};

use crate::pasta::Fp;

/// The root of a Poseidon Merkle tree over sealed bucket digests.
///
/// A one-leaf tree's root is the leaf digest itself, so every subtree root
/// along a path has this type.
///
/// # Injectivity
///
/// A root built from bucket headers determines its tree shape and every leaf's
/// bucket header. Each valid root is a leaf or node digest of
/// [`poseidon`](crate::digest::poseidon#injectivity) and determines what it
/// absorbed. Producing both kinds of preimage for one root would be a
/// collision. The native wrapper itself accepts any field element.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct EvidenceTreeRoot(pub Fp);
