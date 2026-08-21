use core::ops;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use pasta_curves::Fp;

use crate::{constants::EPOCH_MAX, digest::poseidon::NF_GROUP, nullifier::NF_DERIVATION_WIDTH};

/// A tachyon epoch — a point in the accumulator's history.
///
/// The tachyon accumulator evolves as tachygrams are included. Each
/// epoch identifies a specific pool accumulator state.
///
/// Indexes nullifier derivation: $mk = \text{KDF}(\psi, nk)$, then
/// $nf_e = F_{mk}(e)$. Different epochs produce different nullifiers for
/// the same note.
#[derive(Clone, Copy, Debug, From, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct EpochIndex(pub u32);

/// A non-negative distance between two [`EpochIndex`]es, from subtraction.
///
/// Subtraction is the only constructor, and $\mathbb{N}$ the only target: a
/// distance indexes a multiplicative order, so it is never an $\mathbb{F}_p$
/// element.
#[derive(Clone, Copy, Debug, Into, Ord, PartialEq, PartialOrd, TotalEq)]
#[into(u64)]
pub struct EpochDiff(u32);

/// The index of a group of [`NF_GROUP`] consecutive epochs, and so of the
/// derivation window it opens.
///
/// Epoch $e$ belongs to group $\lfloor e / \mathsf{NF\_GROUP} \rfloor$ and
/// arrives as that group's squeeze $e \bmod \mathsf{NF\_GROUP}$.
#[derive(Clone, Copy, Debug, From, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct EpochGroup(pub u32);

impl EpochIndex {
    /// Returns the next epoch index.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "the group and window widths are small constants, and flooring to \
              the last whole group is the intended bound"
)]
impl EpochGroup {
    /// The largest group whose window fits inside the epoch space.
    pub const MAX: Self = Self((EPOCH_MAX - NF_DERIVATION_WIDTH as u32) / NF_GROUP as u32);

    /// The window's first epoch.
    #[must_use]
    pub const fn start_epoch(self) -> EpochIndex {
        EpochIndex(self.0 * NF_GROUP as u32)
    }

    /// One past the window's last epoch.
    #[must_use]
    pub const fn end_epoch(self) -> EpochIndex {
        EpochIndex(self.start_epoch().0 + NF_DERIVATION_WIDTH as u32)
    }
}

impl From<EpochIndex> for EpochGroup {
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "the group width is a small constant, and flooring to the \
                  containing group is the intended index"
    )]
    fn from(epoch: EpochIndex) -> Self {
        Self(epoch.0 / NF_GROUP as u32)
    }
}

impl From<EpochIndex> for Fp {
    fn from(epoch: EpochIndex) -> Self {
        Self::from(u64::from(epoch.0))
    }
}

impl From<EpochGroup> for Fp {
    fn from(group: EpochGroup) -> Self {
        Self::from(u64::from(group.0))
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
