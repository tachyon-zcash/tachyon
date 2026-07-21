use core::ops;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use pasta_curves::Fp;

/// A tachyon epoch — a point in the accumulator's history.
///
/// The tachyon accumulator evolves as tachygrams are included. Each
/// epoch identifies a specific pool accumulator state.
///
/// Used as **epoch** in nullifier derivation:
/// $mk = \text{KDF}(\psi, nk)$, then $nf = F_{mk}(\text{epoch})$.
/// Different epochs produce different nullifiers for the same note.
#[derive(Clone, Copy, Debug, From, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct EpochIndex(pub u32);

/// A non-negative distance between two [`EpochIndex`]es, from subtraction.
#[derive(Clone, Copy, Debug, From, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct EpochDiff(u32);

impl EpochIndex {
    /// Returns the next epoch index.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<EpochIndex> for Fp {
    fn from(epoch: EpochIndex) -> Self {
        Self::from(u64::from(epoch.0))
    }
}

impl From<EpochDiff> for Fp {
    fn from(epoch: EpochDiff) -> Self {
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

impl From<EpochDiff> for u64 {
    fn from(diff: EpochDiff) -> Self {
        diff.0.into()
    }
}
