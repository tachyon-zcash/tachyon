use derive_more::{Debug, From, Into};
use udon::field::Fp;

/// The root of a Poseidon Merkle tree over sealed bucket digests.
///
/// A one-leaf tree's root is the leaf digest itself, so every subtree root
/// along a path has this type.
#[derive(Clone, Copy, Debug, From, Into)]
pub struct EvidenceTreeRoot(pub Fp);

impl PartialEq for EvidenceTreeRoot {
    fn eq(&self, other: &Self) -> bool {
        self.0.reduce() == other.0.reduce()
    }
}

impl Eq for EvidenceTreeRoot {}
