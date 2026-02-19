use ff::PrimeField as _;
use pasta_curves::Fp;

/// A tachygram is a field element ($\mathbb{F}_p$) representing either a
/// note commitment or a nullifier in the Tachyon polynomial accumulator.
///
/// The accumulator does not distinguish between commitments and nullifiers.
/// This unified approach simplifies the proof system and enables efficient
/// batch operations.
///
/// The number of tachygrams in a stamp need not equal the number of
/// actions. The invariant is consistency between the listed tachygrams
/// and the proof's `tachygram_acc`, not a fixed ratio to actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "[u8; 32]", try_from = "[u8; 32]"))]
pub struct Tachygram(Fp);

impl From<Fp> for Tachygram {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<Tachygram> for Fp {
    fn from(tg: Tachygram) -> Self {
        tg.0
    }
}

impl From<Tachygram> for [u8; 32] {
    fn from(tg: Tachygram) -> Self {
        tg.0.to_repr()
    }
}

impl TryFrom<[u8; 32]> for Tachygram {
    type Error = &'static str;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        Option::from(Fp::from_repr(bytes))
            .map(Self)
            .ok_or("invalid field element")
    }
}
