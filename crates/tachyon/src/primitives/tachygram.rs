use core::cmp::Ordering;

use corez::io::{self, Read, Write};
use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::PrimeField as _;
use pasta_curves::Fp;
#[cfg(test)]
use rand_core::CryptoRng;

use crate::serialization;

/// A field element ($\mathbb{F}_p$) in the Tachyon polynomial accumulator.
///
/// [`Nullifier`](crate::nullifier::Nullifier) and
/// [`Commitment`](crate::note::Commitment) both wrap a tachygram, and the
/// accumulator does not distinguish them.
///
/// Every action publishes exactly two: a spend its epoch nullifier pair, an
/// output its commitment and padding tachygram. The uniform arity is what
/// keeps a stamp's tachygram count from revealing its spend/output split.
///
/// Consensus rejects a published tachygram that has already appeared in
/// any block of the current or immediately preceding epoch. See the
/// Tachygrams book chapter for why the window spans two epochs.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct Tachygram(Fp);

impl Tachygram {
    #[cfg(test)]
    pub(crate) fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        use ff::Field as _;

        Self(Fp::random(rng))
    }

    /// Read as a field element from the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or the bytes are not a canonical
    /// field element.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let tg = serialization::read_fp(&mut reader)?;
        Ok(Self(tg))
    }

    /// Write as a field element to the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_fp(&mut writer, &self.0)?;
        Ok(())
    }
}

impl PartialOrd for Tachygram {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Tachygram {
    /// Order by the canonical little-endian byte encoding of the field
    /// element, matching the byte-lexicographic order the stamp digest
    /// commits to. `Fp` has no intrinsic `Ord`.
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.to_repr().as_ref().cmp(other.0.to_repr().as_ref())
    }
}
