use core::num::TryFromIntError;

use pasta_curves::Fp;

use crate::{constants::EPOCH_SIZE, primitives::EpochIndex};

/// A block height in the pool chain.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct BlockHeight(pub u32);

impl From<BlockHeight> for u32 {
    fn from(height: BlockHeight) -> Self {
        height.0
    }
}

impl From<u32> for BlockHeight {
    fn from(height: u32) -> Self {
        Self(height)
    }
}

impl TryFrom<BlockHeight> for usize {
    type Error = TryFromIntError;

    fn try_from(height: BlockHeight) -> Result<Self, Self::Error> {
        height.0.try_into()
    }
}

impl TryFrom<usize> for BlockHeight {
    type Error = TryFromIntError;

    fn try_from(height: usize) -> Result<Self, Self::Error> {
        u32::try_from(height).map(Self)
    }
}

impl From<BlockHeight> for Fp {
    fn from(height: BlockHeight) -> Self {
        Self::from(u64::from(height.0))
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
}
