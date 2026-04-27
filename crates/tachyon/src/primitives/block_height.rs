use ff::PrimeField as _;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use crate::{
    constants::{BLOCK_HEIGHT_DOMAIN, EPOCH_SIZE},
    primitives::{EpochIndex, PoolChain, Tachygram},
};

/// A block height in the pool chain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockHeight(pub u32);

impl From<BlockHeight> for u32 {
    fn from(height: BlockHeight) -> Self {
        height.0
    }
}

impl BlockHeight {
    /// Returns the next block height.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// Epoch index for this block height.
    #[must_use]
    pub const fn epoch(self) -> EpochIndex {
        EpochIndex(self.0 >> EPOCH_SIZE.trailing_zeros())
    }

    /// Whether this is the last block of its epoch.
    #[must_use]
    pub const fn is_epoch_final(self) -> bool {
        self.0 & (EPOCH_SIZE - 1) == EPOCH_SIZE - 1
    }

    /// Whether this is the first block of a new epoch.
    #[must_use]
    pub const fn is_epoch_boundary(self) -> bool {
        self.0 & (EPOCH_SIZE - 1) == 0
    }

    /// Canonical tachygram representing this block height, blinded by the
    /// chain hash of the prior block.
    ///
    /// `Poseidon(BLOCK_HEIGHT_DOMAIN, prev_chain, height)`. Binding to
    /// `prev_chain` makes the canonical height element non-precomputable: an
    /// attacker who wants to forge a height tachygram for block N must know
    /// the chain hash through block N-1, which depends on every prior
    /// block's commitment. Consensus inserts exactly one such tachygram per
    /// block; circuits prove the height by witnessing `prev_chain`,
    /// recomputing this tachygram, and asserting membership.
    #[must_use]
    pub fn tachygram(self, prev_chain: PoolChain) -> Tachygram {
        let domain = Fp::from_u128(u128::from_le_bytes(*BLOCK_HEIGHT_DOMAIN));
        let fp = Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
            domain,
            Fp::from(&prev_chain),
            Fp::from(u64::from(self.0)),
        ]);
        Tachygram::from(&fp)
    }
}
