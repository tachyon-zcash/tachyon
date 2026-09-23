use core::num::TryFromIntError;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};

use crate::{constants::EPOCH_SIZE, primitives::EpochIndex};

/// A block height in the pool chain.
#[derive(Clone, Copy, Debug, From, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct BlockHeight(pub u32);

impl TryFrom<BlockHeight> for usize {
    type Error = TryFromIntError;

    fn try_from(height: BlockHeight) -> Result<Self, Self::Error> {
        height.0.try_into()
    }
}

impl From<usize> for BlockHeight {
    fn from(height: usize) -> Self {
        Self(
            #[expect(clippy::expect_used, reason = "don't index higher than u32::MAX")]
            u32::try_from(height).expect("fits u32"),
        )
    }
}

impl BlockHeight {
    /// Returns the next block height, or `None` for [`BLOCK_MAX`].
    ///
    /// [`BLOCK_MAX`]: crate::constants::BLOCK_MAX
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(height) => Some(Self(height)),
            None => None,
        }
    }

    /// Returns the previous block height, or `None` for the genesis block.
    #[must_use]
    pub const fn prev(self) -> Option<Self> {
        match self.0.checked_sub(1) {
            Some(height) => Some(Self(height)),
            None => None,
        }
    }

    /// Epoch index for this block height.
    #[must_use]
    pub const fn epoch(self) -> EpochIndex {
        EpochIndex::new(self.0.div_euclid(EPOCH_SIZE))
    }

    /// Whether this is the last block of its epoch.
    #[must_use]
    pub const fn is_last_in_epoch(self) -> bool {
        self.0 & (EPOCH_SIZE - 1) == EPOCH_SIZE - 1
    }

    /// Whether this is the first block of a new epoch.
    #[must_use]
    pub const fn is_first_in_epoch(self) -> bool {
        self.0 & (EPOCH_SIZE - 1) == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::BLOCK_MAX;

    #[test]
    fn next_stops_at_the_final_block() {
        assert_eq!(
            BlockHeight(BLOCK_MAX - 1).next(),
            Some(BlockHeight(BLOCK_MAX))
        );
        assert_eq!(BlockHeight(BLOCK_MAX).next(), None);
    }

    #[test]
    fn prev_stops_at_the_genesis_block() {
        assert_eq!(BlockHeight(1).prev(), Some(BlockHeight(0)));
        assert_eq!(BlockHeight(0).prev(), None);
    }
}
