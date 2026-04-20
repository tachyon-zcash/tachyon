//! Polynomial commitments — mirrors Ragu's polynomial commitment scheme.
//!
//! Real Pedersen crypto on Vesta. Only the proof system is mocked.

use alloc::vec::Vec;
use core::ops::Neg;

use ff::Field;
use lazy_static::lazy_static;
use pasta_curves::{Eq, EqAffine, Fp};

const MAX_GENERATORS: usize = 8192;

lazy_static! {
    /// Coefficient generators `g[0..n]`.
    static ref GENERATORS: Vec<EqAffine> = {
        use pasta_curves::{arithmetic::CurveExt as _, group::Curve as _};
        let hasher = Eq::hash_to_curve("mock_ragu:generators");
        (0..MAX_GENERATORS)
            .map(|i| {
                let point = hasher(&i.to_le_bytes());
                point.to_affine()
            })
            .collect()
    };

    /// Blinding generator `h` (unknown discrete log relative to `g`).
    static ref BLINDING_GENERATOR: EqAffine = {
        use pasta_curves::{arithmetic::CurveExt as _, group::Curve as _};
        Eq::hash_to_curve("mock_ragu:blinding")(b"h").to_affine()
    };
}

/// Mirrors `ragu_arithmetic::poly_with_roots`.
#[must_use]
pub fn poly_with_roots(roots: &[Fp]) -> Vec<Fp> {
    let mut coeffs = alloc::vec![Fp::ONE];
    for &root in roots {
        let mut new_coeffs = alloc::vec![Fp::ZERO; coeffs.len() + 1];
        for (i, &c) in coeffs.iter().enumerate() {
            new_coeffs[i + 1] += c;
            new_coeffs[i] += c * root.neg();
        }
        coeffs = new_coeffs;
    }
    coeffs
}

/// Mirrors `ragu_circuits::polynomials::unstructured::Polynomial`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial(Vec<Fp>);

impl Polynomial {
    #[must_use]
    pub fn from_coeffs(coeffs: Vec<Fp>) -> Self {
        Self(coeffs)
    }

    #[must_use]
    pub fn from_roots(roots: &[Fp]) -> Self {
        Self(poly_with_roots(roots))
    }

    #[must_use]
    pub fn multiply(&self, other: &Self) -> Self {
        let result_len = self.0.len() + other.0.len() - 1;
        let mut result = alloc::vec![Fp::ZERO; result_len];
        for (i, &a) in self.0.iter().enumerate() {
            for (j, &b) in other.0.iter().enumerate() {
                result[i + j] += a * b;
            }
        }
        Self(result)
    }

    #[must_use]
    pub fn coefficients(&self) -> &[Fp] {
        &self.0
    }

    /// Evaluate via Horner's method: `p(x) = c₀ + x(c₁ + x(c₂ + …))`.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.iter().rev().fold(Fp::ZERO, |acc, &c| acc * x + c)
    }

    /// `commit(blind) = ∑ coeffᵢ·gᵢ + blind·h`
    #[must_use]
    pub fn commit(&self, blind: Fp) -> Commitment {
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
            acc += Eq::from(point) * coeff;
        }
        acc += Eq::from(*BLINDING_GENERATOR) * blind;

        Commitment(acc.to_affine())
    }
}

impl Default for Polynomial {
    fn default() -> Self {
        Self(alloc::vec![Fp::ONE])
    }
}

/// A Pedersen vector commitment (EC point on Vesta).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(EqAffine);

impl Commitment {
    #[must_use]
    pub fn inner(&self) -> &EqAffine {
        &self.0
    }
}

impl From<Commitment> for [u8; 32] {
    fn from(c: Commitment) -> Self {
        use pasta_curves::group::GroupEncoding as _;
        c.0.to_bytes()
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
