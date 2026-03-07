use ff::{Field as _, PrimeField as _};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use crate::{constants::TACHYGRAM_DIGEST_DOMAIN, primitives::Tachygram};

/// Order-independent accumulator of one or more tachygrams.
///
/// $$\mathsf{tachygram\_acc} = \prod_i
///     \text{Poseidon}(\text{domain},\; \mathsf{tg}_i)$$
///
/// Each tachygram is hashed. Multiple digests combine via field multiplication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TachygramDigest(Fp);

/// Hash a single tachygram into the accumulation domain.
///
/// # Panics
///
/// Panics if the digest is zero. Do not digest a preimage for zero.
fn digest_tachygram(tg: Tachygram) -> Fp {
    #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
    let domain = Fp::from_u128(u128::from_le_bytes(*TACHYGRAM_DIGEST_DOMAIN));
    let hash = Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([domain, Fp::from(tg)]);
    assert!(!hash.is_zero_vartime(), "Poseidon hash was zero");
    hash
}

impl TachygramDigest {
    /// Accumulate two digests.
    #[must_use]
    pub fn accumulate(self, other: Self) -> Self {
        Self(self.0 * other.0)
    }
}

impl FromIterator<Tachygram> for TachygramDigest {
    fn from_iter<I: IntoIterator<Item = Tachygram>>(iter: I) -> Self {
        Self(
            iter.into_iter()
                .map(digest_tachygram)
                .fold(Fp::ONE, |acc, hash| acc * hash),
        )
    }
}

/// The identity element for accumulation (`Fp::ONE`).
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
        let fp: Fp = Option::from(Fp::from_repr(*bytes)).ok_or("invalid field element")?;
        if fp.is_zero_vartime() {
            return Err("zero digest");
        }
        Ok(Self(fp))
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for TachygramDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use ff::PrimeField as _;

        serializer.serialize_bytes(&self.0.to_repr())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for TachygramDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use crate::serde_helpers::FpVisitor;

        deserializer.deserialize_bytes(FpVisitor).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use core::iter;

    use pasta_curves::Fp;

    use super::*;

    /// Accumulation is commutative: {a, b} == {b, a}.
    #[test]
    fn accumulate_commutative() {
        let tg_a = Tachygram::from(Fp::from(42u64));
        let tg_b = Tachygram::from(Fp::from(99u64));

        let ab: TachygramDigest = [tg_a, tg_b].into_iter().collect();
        let ba: TachygramDigest = [tg_b, tg_a].into_iter().collect();

        assert_eq!(ab, ba);
    }

    /// Different tachygram sets produce different digests.
    #[test]
    fn distinct_tachygrams_distinct_digests() {
        let tg_a = Tachygram::from(Fp::from(42u64));
        let tg_b = Tachygram::from(Fp::from(99u64));

        let digest_a: TachygramDigest = iter::once(tg_a).collect();
        let digest_b: TachygramDigest = iter::once(tg_b).collect();

        assert_ne!(digest_a, digest_b);
    }

    /// Identity element: accumulating with identity is a no-op.
    #[test]
    fn identity_element() {
        let tg = Tachygram::from(Fp::from(42u64));
        let digest: TachygramDigest = iter::once(tg).collect();

        assert_eq!(digest.accumulate(TachygramDigest::default()), digest);
        assert_eq!(TachygramDigest::default().accumulate(digest), digest);
    }

    /// Empty accumulation produces the identity.
    #[test]
    fn empty_accumulate_is_identity() {
        let acc: TachygramDigest = iter::empty().collect();
        assert_eq!(acc, TachygramDigest::default());
    }
}
