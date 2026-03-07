use ff::{Field as _, PrimeField as _};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use crate::{constants::TACHYGRAM_DIGEST_DOMAIN, primitives::Tachygram};

/// Hash a single tachygram for accumulation.
///
/// Returns `Poseidon(domain, tg) + 1`.
///
/// The `+1` offset guarantees a nonzero output, preventing product
/// collapse in multiplicative accumulation.
fn digest_tachygram(tg: Tachygram) -> Fp {
    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    let domain = Fp::from_u128(u128::from_le_bytes(*TACHYGRAM_DIGEST_DOMAIN));

    Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([domain, Fp::from(tg)]) + Fp::ONE
}

/// Order-independent digest of one or more tachygrams.
///
/// Each tachygram (nullifier or note commitment) is hashed to a nonzero
/// field element via Poseidon. Multiple digests combine via field
/// multiplication (commutative, order-independent):
///
/// $$\mathsf{tachygram\_acc} = \prod_i (H(\mathsf{tg}_i) + 1)$$
///
/// Multiplicative accumulation prevents the post-proof tachygram
/// substitution attack: finding substitute values whose product matches
/// the proven accumulator reduces to the discrete logarithm problem,
/// maintaining 128-bit security regardless of the number of tachygrams.
///
/// The accumulation scheme is accessed through
/// [`accumulate`](Self::accumulate), [`Default`], and [`FromIterator`]
/// so that the underlying operation can be changed without affecting
/// callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TachygramDigest(Fp);

impl TachygramDigest {
    /// Digest a single tachygram.
    #[must_use]
    pub fn new(tg: Tachygram) -> Self {
        Self(digest_tachygram(tg))
    }

    /// Combine two digests.
    #[must_use]
    pub fn accumulate(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl FromIterator<Self> for TachygramDigest {
    fn from_iter<I: IntoIterator<Item = Self>>(iter: I) -> Self {
        iter.into_iter().fold(Self::default(), Self::accumulate)
    }
}

/// The identity element for accumulation (currently `Fp::ONE`).
impl Default for TachygramDigest {
    fn default() -> Self {
        Self(Fp::ONE)
    }
}

impl From<TachygramDigest> for [u8; 32] {
    fn from(digest: TachygramDigest) -> Self {
        digest.0.to_repr()
    }
}

impl TryFrom<&[u8; 32]> for TachygramDigest {
    type Error = &'static str;

    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        Option::from(Fp::from_repr(*bytes))
            .ok_or("invalid field element")
            .map(Self)
    }
}

#[cfg(test)]
mod tests {
    use pasta_curves::Fp;

    use super::*;

    /// Digest merge is commutative: A·B == B·A.
    #[test]
    fn digest_commutative() {
        let tg_a = Tachygram::from(Fp::from(42u64));
        let tg_b = Tachygram::from(Fp::from(99u64));

        let digest_a = TachygramDigest::new(tg_a);
        let digest_b = TachygramDigest::new(tg_b);

        assert_eq!(digest_a.accumulate(digest_b), digest_b.accumulate(digest_a));
    }

    /// Different tachygrams produce different digests.
    #[test]
    fn distinct_tachygrams_distinct_digests() {
        let tg_a = Tachygram::from(Fp::from(42u64));
        let tg_b = Tachygram::from(Fp::from(99u64));

        assert_ne!(TachygramDigest::new(tg_a), TachygramDigest::new(tg_b));
    }

    /// Identity element: merging with identity is a no-op.
    #[test]
    fn identity_element() {
        let tg = Tachygram::from(Fp::from(42u64));
        let digest = TachygramDigest::new(tg);

        assert_eq!(digest.accumulate(TachygramDigest::default()), digest);
        assert_eq!(TachygramDigest::default().accumulate(digest), digest);
    }

    /// Empty accumulation produces the identity.
    #[test]
    fn empty_accumulate_is_identity() {
        let acc: TachygramDigest = vec![].into_iter().collect();
        assert_eq!(acc, TachygramDigest::default());
    }
}
