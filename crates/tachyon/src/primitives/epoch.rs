use core::ops;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use pasta_curves::Fp;

use super::BlockHeight;
use crate::constants::EPOCH_SIZE;

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
    #[must_use]
    pub const fn next(self) -> Self {
        #[expect(
            clippy::expect_used,
            reason = "wrapping would alias epoch 0; panic instead at the end of the epoch space"
        )]
        Self(self.0.checked_add(1).expect("epoch index overflow"))
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
    #[must_use]
    pub const fn last_block(self) -> BlockHeight {
        #[expect(
            clippy::expect_used,
            reason = "the next epoch's first block is at least EPOCH_SIZE, so the subtraction cannot fail"
        )]
        BlockHeight(
            self.next()
                .first_block()
                .0
                .checked_sub(1)
                .expect("the next epoch's first block is positive"),
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
}
