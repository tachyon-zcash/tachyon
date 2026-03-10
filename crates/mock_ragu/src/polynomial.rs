//! Polynomial and Pedersen vector commitment types.
//!
//! Mock equivalents of Ragu's polynomial commitment scheme. The
//! [`Polynomial`] type mirrors
//! `ragu_circuits::polynomials::unstructured::Polynomial`
//! and the [`Commitment`] type represents a real Pedersen vector commitment
//! (EC point on Vesta). Only the proof system (IPA opening, Fiat-Shamir,
//! etc.) is mocked — the commitment itself is real crypto.
//!
//! These are public so that validators can recompute accumulators from
//! public data outside the proof.

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::ops::Neg;
use std::sync::LazyLock;

use ff::Field;
use pasta_curves::{Eq, EqAffine, Fp};

/// Maximum number of generators to precompute.
///
/// Supports polynomials up to degree `MAX_GENERATORS - 1`. This is enough
/// for stamps with up to `MAX_GENERATORS - 1` elements. If a polynomial
/// exceeds this, `commit` will panic — increase the bound when needed.
const MAX_GENERATORS: usize = 256;

/// Lazily derived fixed generators for Pedersen vector commitments.
///
/// Each generator is derived via `hash_to_curve` with a domain separator
/// and index. When real Ragu lands, these are replaced by Ragu's baked
/// generators.
static GENERATORS: LazyLock<Vec<EqAffine>> = LazyLock::new(|| {
    use pasta_curves::{arithmetic::CurveExt as _, group::Curve as _};

    let hasher = Eq::hash_to_curve("mock_ragu:generators");

    (0..MAX_GENERATORS)
        .map(|i| {
            #[expect(clippy::little_endian_bytes, reason = "deterministic derivation")]
            let point = hasher(&i.to_le_bytes());
            point.to_affine()
        })
        .collect()
});

/// A polynomial in monomial basis (coefficients in ascending degree order).
///
/// Mirrors `ragu_circuits::polynomials::unstructured::Polynomial`.
/// Represents `∏(X - rᵢ)` when built via [`from_roots`](Self::from_roots).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial(Vec<Fp>);

impl Polynomial {
    /// Builds the monic polynomial whose roots are the given field elements.
    ///
    /// `from_roots(&[r₀, r₁, ...]) = (X - r₀)(X - r₁)...`
    ///
    /// Mirrors `ragu_arithmetic::poly_with_roots`. Returns coefficients
    /// in ascending degree order; the leading coefficient is always 1.
    ///
    /// Empty roots returns the constant polynomial `1`.
    #[must_use]
    pub fn from_roots(roots: &[Fp]) -> Self {
        let mut coeffs = vec![Fp::ONE];

        for &root in roots {
            // Multiply current polynomial by (X - root):
            // new[i] = old[i-1] - root * old[i]
            let mut new_coeffs = vec![Fp::ZERO; coeffs.len() + 1];
            for (i, &c) in coeffs.iter().enumerate() {
                new_coeffs[i + 1] = new_coeffs[i + 1] + c;
                new_coeffs[i] = new_coeffs[i] + c * root.neg();
            }
            coeffs = new_coeffs;
        }

        Self(coeffs)
    }

    /// Polynomial multiplication (convolution).
    ///
    /// Used in MergeStep to combine `poly_left · poly_right`.
    #[must_use]
    pub fn multiply(&self, other: &Self) -> Self {
        let result_len = self.0.len() + other.0.len() - 1;
        let mut result = vec![Fp::ZERO; result_len];

        for (i, &a) in self.0.iter().enumerate() {
            for (j, &b) in other.0.iter().enumerate() {
                result[i + j] = result[i + j] + a * b;
            }
        }

        Self(result)
    }

    /// Returns the coefficients in ascending degree order.
    #[must_use]
    pub fn coefficients(&self) -> &[Fp] {
        &self.0
    }

    /// Computes a Pedersen vector commitment to this polynomial.
    ///
    /// `Commit(f) = ∑ coeffᵢ · Gᵢ`
    ///
    /// No blinding factor — the commitment is deterministic so that the
    /// verifier can reconstruct it from public data. When real Ragu lands,
    /// blinding is added for zero-knowledge.
    ///
    /// # Panics
    ///
    /// Panics if the polynomial degree exceeds `MAX_GENERATORS - 1`.
    #[must_use]
    pub fn commit(&self) -> Commitment {
        use pasta_curves::group::{Curve as _, Group as _};

        let generators = &*GENERATORS;
        assert!(
            self.0.len() <= generators.len(),
            "polynomial degree {} exceeds max generators {}",
            self.0.len() - 1,
            generators.len() - 1,
        );

        let mut acc = Eq::identity();
        for (&coeff, &point) in self.0.iter().zip(generators.iter()) {
            acc = acc + Eq::from(point) * coeff;
        }

        Commitment(acc.to_affine())
    }
}

/// The identity element for polynomial multiplication: the constant `1`.
impl Default for Polynomial {
    fn default() -> Self {
        Self(vec![Fp::ONE])
    }
}

/// A Pedersen vector commitment — an elliptic curve point on Pallas.
///
/// In real Ragu, this is the result of `polynomial.commit(generators, blind)`.
/// Here it wraps `EqAffine` directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(EqAffine);

impl Commitment {
    /// Returns the underlying affine point.
    #[must_use]
    pub fn inner(&self) -> &EqAffine {
        &self.0
    }
}

impl From<Commitment> for [u8; 32] {
    fn from(c: Commitment) -> Self {
        use pasta_curves::group::GroupEncoding as _;
        c.0.to_bytes().into()
    }
}

impl TryFrom<&[u8; 32]> for Commitment {
    type Error = &'static str;

    fn try_from(bytes: &[u8; 32]) -> core::result::Result<Self, Self::Error> {
        use pasta_curves::group::GroupEncoding as _;
        Option::from(EqAffine::from_bytes(bytes))
            .map(Self)
            .ok_or("invalid curve point")
    }
}

#[cfg(test)]
mod tests {
    use core::ops::Neg as _;

    use ff::Field as _;
    use pasta_curves::Fp;

    use super::*;

    /// `from_roots([])` returns the constant polynomial `[1]`.
    #[test]
    fn empty_roots_is_one() {
        let poly = Polynomial::from_roots(&[]);
        assert_eq!(poly.coefficients(), &[Fp::ONE]);
    }

    /// `from_roots([r])` returns `[-r, 1]` (i.e. `X - r`).
    #[test]
    fn single_root() {
        let r = Fp::from(42u64);
        let poly = Polynomial::from_roots(&[r]);
        assert_eq!(poly.coefficients(), &[r.neg(), Fp::ONE]);
    }

    /// The product of two single-root polynomials equals a two-root polynomial.
    #[test]
    fn multiply_equals_combined_roots() {
        let a = Fp::from(3u64);
        let b = Fp::from(7u64);

        let pa = Polynomial::from_roots(&[a]);
        let pb = Polynomial::from_roots(&[b]);
        let product = pa.multiply(&pb);

        let combined = Polynomial::from_roots(&[a, b]);
        assert_eq!(product, combined);
    }

    /// Polynomial evaluates to zero at each root.
    #[test]
    fn roots_evaluate_to_zero() {
        let roots = [Fp::from(1u64), Fp::from(2u64), Fp::from(3u64)];
        let poly = Polynomial::from_roots(&roots);

        for &root in &roots {
            let mut val = Fp::ZERO;
            let mut power = Fp::ONE;
            for &coeff in poly.coefficients() {
                val = val + coeff * power;
                power = power * root;
            }
            assert_eq!(val, Fp::ZERO, "polynomial should be zero at its roots");
        }
    }

    /// Commitment is deterministic: same polynomial produces same commitment.
    #[test]
    fn commitment_deterministic() {
        let poly = Polynomial::from_roots(&[Fp::from(42u64)]);
        assert_eq!(poly.commit(), poly.commit());
    }

    /// Different polynomials produce different commitments.
    #[test]
    fn distinct_polys_distinct_commitments() {
        let c1 = Polynomial::from_roots(&[Fp::from(1u64)]).commit();
        let c2 = Polynomial::from_roots(&[Fp::from(2u64)]).commit();
        assert_ne!(c1, c2);
    }

    /// Commitment roundtrips through serialization.
    #[test]
    fn commitment_serialization_roundtrip() {
        let commitment = Polynomial::from_roots(&[Fp::from(99u64)]).commit();
        let bytes: [u8; 32] = commitment.into();
        let recovered = Commitment::try_from(&bytes).expect("valid point");
        assert_eq!(commitment, recovered);
    }

    /// Multiplying by the default (identity) polynomial is a no-op.
    #[test]
    fn multiply_by_identity() {
        let poly = Polynomial::from_roots(&[Fp::from(5u64), Fp::from(10u64)]);
        let identity = Polynomial::default();
        assert_eq!(poly.multiply(&identity), poly);
        assert_eq!(identity.multiply(&poly), poly);
    }
}
