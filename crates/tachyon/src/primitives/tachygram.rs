use core::cmp::Ordering;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::PrimeField as _;
use pasta_curves::Fp;
#[cfg(test)]
use rand_core::{CryptoRng, RngCore};

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
    pub(crate) fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        use ff::Field as _;

        Self(Fp::random(rng))
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
