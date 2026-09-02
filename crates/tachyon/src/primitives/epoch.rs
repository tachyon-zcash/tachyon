use core::ops;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use pasta_curves::Fp;

use super::BlockHeight;
use crate::constants::{EPOCH_MAX, EPOCH_SIZE};

/// A tachyon epoch — a point in the accumulator's history.
///
/// The tachyon accumulator evolves as tachygrams are included. Each
/// epoch identifies a specific pool accumulator state.
///
/// Indexes nullifier derivation: $mk = \text{KDF}(\psi, nk)$, then
/// $nf_e = F_{mk}(e)$. Different epochs produce different nullifiers for
/// the same note, enabling range-restricted delegation via the GGM tree PRF.
#[derive(Clone, Copy, Debug, From, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct EpochIndex(pub u32);

/// A non-negative distance between two [`EpochIndex`]es, from subtraction.
#[derive(Clone, Copy, Debug, Into, Ord, PartialEq, PartialOrd, TotalEq)]
#[into(u64)]
pub struct EpochDiff(u32);

impl EpochIndex {
    /// Returns the next epoch index.
    ///
    /// Panics rather than step past [`EPOCH_MAX`]: indexes beyond it map to
    /// no block height in the protocol's range.
    #[must_use]
    pub const fn next(self) -> Self {
        assert!(self.0 < EPOCH_MAX, "epoch index past EPOCH_MAX");
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "the assert above bounds the index below EPOCH_MAX"
        )]
        Self(self.0 + 1)
    }

    /// Returns the first block height of the epoch.
    #[must_use]
    pub const fn first_block(self) -> BlockHeight {
        #[expect(
            clippy::expect_used,
            reason = "wrapping would alias an earlier block; panic instead past the last representable height"
        )]
        BlockHeight(self.0.checked_mul(EPOCH_SIZE).expect("block height overflow"))
    }

    /// Returns the last block height of the epoch.
    ///
    /// Computed from this epoch's own first block, so the final epoch
    /// ([`EPOCH_MAX`], whose last block is `BLOCK_MAX`) does not overflow.
    #[must_use]
    pub const fn last_block(self) -> BlockHeight {
        #[expect(
            clippy::expect_used,
            reason = "every epoch index up to EPOCH_MAX ends at or below BLOCK_MAX"
        )]
        BlockHeight(
            self.first_block()
                .0
                .checked_add(EPOCH_SIZE - 1)
                .expect("block height overflow"),
        )
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
    use super::*;

    #[test]
    fn epoch_difference_counts_the_span() {
        assert_eq!(u64::from(EpochIndex(7) - EpochIndex(3)), 4);
        assert_eq!(u64::from(EpochIndex(3) - EpochIndex(3)), 0);
    }

    #[test]
    #[should_panic(expected = "epoch difference is positive")]
    fn epoch_difference_rejects_reversed_operands() {
        let reversed = EpochIndex(3) - EpochIndex(7);
        panic!("reversed operands must not produce a difference, got {reversed:?}");
    }

    #[test]
    fn final_epoch_ends_at_the_final_block() {
        use crate::constants::BLOCK_MAX;

        assert_eq!(EpochIndex(EPOCH_MAX).last_block(), BlockHeight(BLOCK_MAX));
        assert_eq!(EpochIndex(EPOCH_MAX - 1).next(), EpochIndex(EPOCH_MAX));
        assert_eq!(BlockHeight(BLOCK_MAX).epoch(), EpochIndex(EPOCH_MAX));
    }

    #[test]
    #[should_panic(expected = "epoch index past EPOCH_MAX")]
    fn next_rejects_the_final_epoch() {
        let past_the_end = EpochIndex(EPOCH_MAX).next();
        panic!("the final epoch must have no successor, got {past_the_end:?}");
    }
}
