use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};

use crate::pasta::Fp;

/// The root of a Poseidon Merkle tree over sealed bucket digests.
///
/// A one-leaf tree's root is the leaf digest itself, so every subtree root
/// along a path has this type.
///
/// # Injectivity
///
/// A root is a leaf digest or a node digest of
/// [`poseidon`](crate::digest::poseidon#injectivity). It is not known to be
/// both and determines what it absorbed, so a root determines its tree down
/// to the bucket headers.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct EvidenceTreeRoot(pub Fp);
