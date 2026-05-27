/// A tachyon epoch — a point in the accumulator's history.
///
/// The tachyon accumulator evolves as tachygrams are included. Each
/// epoch identifies a specific pool accumulator state.
///
/// Used as the per-epoch **index** into a note's pronullifier polynomial
/// $M$: the epoch-$e$ nullifier is $nf_e = M_e + cm$. Different epochs
/// select different coefficients, so the same note has a distinct nullifier
/// each epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EpochIndex(pub u32);

impl EpochIndex {
    /// Returns the next epoch index.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<u32> for EpochIndex {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<EpochIndex> for u32 {
    fn from(epoch: EpochIndex) -> Self {
        epoch.0
    }
}
