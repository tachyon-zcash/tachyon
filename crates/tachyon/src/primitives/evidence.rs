use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use udon::field::{FieldAdapter, PallasBase};
/// The root of a Poseidon Merkle tree over sealed bucket digests.
///
/// A one-leaf tree's root is the leaf digest itself, so every subtree root
/// along a path has this type.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct EvidenceTreeRoot(pub FieldAdapter<PallasBase>);
