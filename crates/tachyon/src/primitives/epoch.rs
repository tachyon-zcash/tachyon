use core::ops;

use derive_more::{Debug, Eq as TotalEq, Into, PartialEq};

use super::BlockHeight;
use crate::{
    constants::{EPOCH_MAX, EPOCH_SIZE},
    pasta::Fp,
};

/// A tachyon epoch: a point in the accumulator's history.
///
/// The tachyon accumulator evolves as tachygrams are included. Each
/// epoch identifies a specific pool accumulator state.
///
/// Indexes nullifier derivation. A note's nullifier for an epoch is a squeeze
/// of the Poseidon sponge keyed on the note's master key $\mathsf{mk}$ and the
/// epoch's group start. Different epochs produce different nullifiers for the
/// same note. A wallet delegates a window of epochs by handing out that
/// window's nullifiers.
///
/// Always in `0..=EPOCH_MAX`: every index maps to a block height in the
/// protocol's range.
#[derive(Clone, Copy, Debug, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct EpochIndex(u32);

/// A non-negative distance between two [`EpochIndex`]es, from subtraction.
#[derive(Clone, Copy, Debug, Into, Ord, PartialEq, PartialOrd, TotalEq)]
#[into(u32, u64)]
pub struct EpochDiff(u32);

impl EpochIndex {
    /// The epoch at `index`.
    ///
    /// # Panics
    ///
    /// Above [`EPOCH_MAX`], which maps to no block height.
    #[must_use]
    pub const fn new(index: u32) -> Self {
        assert!(index <= EPOCH_MAX, "epoch index above EPOCH_MAX");
        Self(index)
    }

    /// Returns the next epoch index, or `None` for the final epoch.
    ///
    /// Indexes past [`EPOCH_MAX`] map to no block height in the protocol's
    /// range, so the final epoch has no successor.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        if self.0 < EPOCH_MAX {
            Some(Self(self.0 + 1))
        } else {
            None
        }
    }

    /// Returns the first block height of the epoch.
    #[must_use]
    pub const fn first_block(self) -> BlockHeight {
        BlockHeight(self.0 * EPOCH_SIZE)
    }

    /// Returns the last block height of the epoch.
    ///
    /// Computed from this epoch's own first block, so the final epoch
    /// ([`EPOCH_MAX`], whose last block is `BLOCK_MAX`) does not overflow.
    #[must_use]
    pub const fn last_block(self) -> BlockHeight {
        BlockHeight(self.first_block().0 + (EPOCH_SIZE - 1))
    }
}

impl From<EpochIndex> for u64 {
    fn from(epoch: EpochIndex) -> Self {
        epoch.0.into()
    }
}

impl From<EpochIndex> for Fp {
    fn from(epoch: EpochIndex) -> Self {
        Self::from(u64::from(epoch.0))
    }
}

impl ops::Sub<Self> for EpochIndex {
    type Output = EpochDiff;

    fn sub(self, rhs: Self) -> Self::Output {
        #[expect(clippy::expect_used, reason = "don't do it wrong")]
        EpochDiff(
            self.0
                .checked_sub(rhs.0)
                .expect("epoch difference is positive"),
        )
    }
}

#[cfg(test)]
mod tests;
