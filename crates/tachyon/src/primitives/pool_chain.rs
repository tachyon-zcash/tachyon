use ff::PrimeField as _;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{Fp, arithmetic::CurveAffine as _};

use super::BlockCommit;
use crate::constants::POOL_CHAIN_DOMAIN;

/// Per-block hash chain over completed pool history.
///
/// $$\mathsf{chain}_n =
/// \text{Poseidon}_\text{Tachyon-PoolChn}(\mathsf{chain}_{n-1} \|
/// x(\mathsf{block\_commit}_n) \| y(\mathsf{block\_commit}_n))$$
///
/// Anchors expose `chain_n` so that any verifier with a known prior
/// `chain_{n-1}` can reach the same value, and so that two proofs at the same
/// anchor are bound to the same per-block history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolChain(pub(crate) Fp);

impl PoolChain {
    /// Initial chain value before any block has been mined.
    #[must_use]
    pub fn genesis() -> Self {
        let domain = Fp::from_u128(u128::from_le_bytes(*POOL_CHAIN_DOMAIN));
        Self(
            Hash::<_, P128Pow5T3, ConstantLength<4>, 3, 2>::init().hash([
                domain,
                Fp::from(0u64),
                Fp::from(0u64),
                Fp::from(0u64),
            ]),
        )
    }

    /// Advance the chain by one block.
    #[must_use]
    pub fn advance(self, block_commit: &BlockCommit) -> Self {
        let domain = Fp::from_u128(u128::from_le_bytes(*POOL_CHAIN_DOMAIN));
        let point = block_commit.0.inner();
        let coords = point
            .coordinates()
            .expect("block commit should be a valid curve point");
        let (x, y) = (
            Fp::from_repr(coords.x().to_repr()).expect("interpret as Fp"),
            Fp::from_repr(coords.y().to_repr()).expect("interpret as Fp"),
        );
        Self(Hash::<_, P128Pow5T3, ConstantLength<4>, 3, 2>::init().hash([domain, self.0, x, y]))
    }
}

impl From<&PoolChain> for Fp {
    fn from(chain: &PoolChain) -> Self {
        chain.0
    }
}

impl From<PoolChain> for [u8; 32] {
    fn from(chain: PoolChain) -> Self {
        chain.0.to_repr()
    }
}

impl TryFrom<&[u8; 32]> for PoolChain {
    type Error = &'static str;

    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        let fp: Fp = Option::from(Fp::from_repr(*bytes)).ok_or("invalid field element")?;
        Ok(Self(fp))
    }
}
