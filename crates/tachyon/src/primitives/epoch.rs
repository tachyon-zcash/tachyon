use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use pasta_curves::Fp;

/// A tachyon epoch — a point in the accumulator's history.
///
/// The tachyon accumulator evolves as tachygrams are included. Each
/// epoch identifies a specific pool accumulator state.
///
/// Used as the cipher input in nullifier derivation:
/// $mk = \text{KDF}(\psi, nk)$, then $nf = E_{mk}(\text{epoch})$.
/// Different epochs produce different nullifiers for the same note.
#[derive(Clone, Copy, Debug, From, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct EpochIndex(pub u32);

impl EpochIndex {
    /// Returns the next epoch index.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }

    /// The offset of this epoch from an earlier `origin` (`self − origin`): the
    /// `d = e − E_0` a nullifier query is taken at.
    #[must_use]
    pub const fn offset_from(self, origin: Self) -> EpochOffset {
        EpochOffset(self.0 - origin.0)
    }
}

impl From<EpochIndex> for Fp {
    fn from(epoch: EpochIndex) -> Self {
        Self::from(u64::from(epoch.0))
    }
}

/// An epoch offset `d = e − E_0`: epochs elapsed since a note's creation, the
/// exponent of a nullifier query `nf_d = Σ_j ρ_j^d·T_j(c·γ^d)`.
///
/// Bounded by the query-coset order `S` (a note's maximum life); an offset at
/// or beyond `S` is past the note's life and unspendable (terminal expiry). The
/// in-circuit query decomposes `d` into `log₂(S)` bits and forms `γ^d`, `ρ_j^d`
/// by square-and-multiply (which also enforces `d < S`); the mock takes the
/// shortcut of native exponentiation by the integer offset.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EpochOffset(pub u32);

impl EpochOffset {
    /// The next offset.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
}

impl From<EpochOffset> for u64 {
    fn from(offset: EpochOffset) -> Self {
        Self::from(offset.0)
    }
}
