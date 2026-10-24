use core::ops;

use derive_more::{Debug, Eq as TotalEq, Into, PartialEq};
use pasta_curves::Fp;

use super::BlockHeight;
use crate::constants::{EPOCH_MAX, EPOCH_SIZE};

/// A tachyon epoch: a point in the accumulator's history.
///
/// The tachyon accumulator evolves as tachygrams are included. Each
/// epoch identifies a specific pool accumulator state.
///
/// Indexes nullifier derivation: $mk = \text{KDF}(\psi, nk)$, then
/// $nf_e = F_{mk}(e)$. Different epochs produce different nullifiers for
/// the same note, enabling range-restricted delegation via the GGM tree PRF.
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
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::{constants::BLOCK_MAX, testing::check};

    /// An epoch index, weighted towards the first and final epochs.
    fn epoch_index() -> impl Strategy<Value = u32> {
        prop_oneof![0..=EPOCH_MAX, Just(0), Just(EPOCH_MAX - 1), Just(EPOCH_MAX)]
    }

    /// An epoch is the run of `EPOCH_SIZE` heights from its first block, each
    /// of which maps back to it; the next epoch starts right after, and the
    /// final epoch ends at the final block with no successor.
    #[test]
    fn an_epoch_spans_its_blocks() {
        check(256, (epoch_index(), 0..EPOCH_SIZE), |(index, offset)| {
            let epoch = EpochIndex::new(index);
            let (first, last) = (epoch.first_block(), epoch.last_block());
            prop_assert_eq!(last.0 - first.0, EPOCH_SIZE - 1);
            prop_assert_eq!(BlockHeight(first.0 + offset).epoch(), epoch);
            prop_assert!(first.is_first_in_epoch() && last.is_last_in_epoch());
            if let Some(next) = epoch.next() {
                prop_assert_eq!(u32::from(next), index + 1);
                prop_assert_eq!(next.first_block().prev(), Some(last));
            } else {
                prop_assert_eq!(index, EPOCH_MAX);
                prop_assert_eq!(last, BlockHeight(BLOCK_MAX));
            }
            Ok(())
        });
    }

    #[test]
    #[should_panic(expected = "epoch difference is positive")]
    fn epoch_difference_rejects_reversed_operands() {
        let reversed = EpochIndex(3) - EpochIndex(7);
        panic!("reversed operands must not produce a difference, got {reversed:?}");
    }

    #[test]
    #[should_panic(expected = "epoch index above EPOCH_MAX")]
    fn new_rejects_an_index_past_the_final_epoch() {
        let past_the_end = EpochIndex::new(EPOCH_MAX + 1);
        panic!("an index above EPOCH_MAX is not an epoch, got {past_the_end:?}");
    }
}
