/// A tachyon epoch — a point in the accumulator's history.
///
/// The tachyon accumulator evolves as tachygrams are included. Each
/// epoch identifies a specific pool accumulator state.
///
/// Used as **flavor** in nullifier derivation:
/// $mk = \text{KDF}(\psi, nk)$, then $nf = F_{mk}(\text{flavor})$.
/// Different epochs produce different nullifiers for the same note,
/// enabling range-restricted delegation via the GGM tree PRF.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Epoch(pub u32);

impl From<u32> for Epoch {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<Epoch> for u32 {
    fn from(epoch: Epoch) -> Self {
        epoch.0
    }
}
