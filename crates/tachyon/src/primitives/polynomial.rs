//! Polynomial construction and Pedersen vector commitment.
//!
//! Builds the characteristic polynomial `∏(x - root_i)` from a set of
//! roots and computes a Pedersen vector commitment on Vesta using
//! generators from `mock_ragu`.

extern crate alloc;

use alloc::vec::Vec;
use core::iter;

use ff::Field as _;
use pasta_curves::{
    Eq, EqAffine, Fp,
    group::{Curve as _, Group as _},
};

/// Build the coefficient vector of `∏(x - root_i)`.
///
/// Returns `[c_0, c_1, ..., c_n]` where the polynomial is
/// `c_0 + c_1·x + c_2·x² + ... + c_n·x^n`.
/// For an empty root set, returns `[1]` (the constant polynomial 1).
pub(crate) fn poly_from_roots(roots: &[Fp]) -> Vec<Fp> {
    let mut coeffs = alloc::vec![Fp::ONE];
    for &root in roots {
        let (fp0_coeffs, coeffs_fp0) = (
            coeffs.iter().chain(iter::once(&Fp::ZERO)),
            iter::once(&Fp::ZERO).chain(coeffs.iter()),
        );

        coeffs = coeffs_fp0
            .zip(fp0_coeffs)
            .map(|(&hi, &lo)| hi - lo * root)
            .collect();
    }
    coeffs
}

/// Evaluate a polynomial (given as coefficient vector) at a point.
///
/// Uses Horner's method.
pub(crate) fn poly_eval(coeffs: &[Fp], point: Fp) -> Fp {
    coeffs
        .iter()
        .rev()
        .fold(Fp::ZERO, |acc, &coeff| acc * point + coeff)
}

/// Pedersen vector commitment: `C = ∑ v_i · G_i`.
///
/// Uses generators `G_0..G_{len-1}` from `mock_ragu::VESTA_GENERATORS`.
/// No blinding — all commitments are public.
///
/// This is the canonical vector commitment primitive. Polynomial commitments,
/// nullifier set commitments, and product vector commitments all go through
/// this function — they share the same generator basis so that homomorphic
/// properties (e.g. pool-commit additivity) hold across contexts.
///
/// # Panics
///
/// Panics if the vector length exceeds the number of available generators.
pub(crate) fn pedersen_commit(values: &[Fp]) -> EqAffine {
    let generators = &*mock_ragu::VESTA_GENERATORS;
    assert!(
        values.len() <= generators.len(),
        "vector has {} elements but only {} generators",
        values.len(),
        generators.len(),
    );

    let mut acc = Eq::identity();
    for (&value, &generator) in values.iter().zip(generators.iter()) {
        acc += Eq::from(generator) * value;
    }
    acc.to_affine()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_roots_gives_one() {
        let coeffs = poly_from_roots(&[]);
        assert_eq!(coeffs, alloc::vec![Fp::ONE]);
    }

    #[test]
    fn single_root() {
        let coeffs = poly_from_roots(&[Fp::from(3u64)]);
        assert_eq!(coeffs.len(), 2);
        assert_eq!(coeffs[0], -Fp::from(3u64));
        assert_eq!(coeffs[1], Fp::ONE);
    }

    #[test]
    fn two_roots() {
        let coeffs = poly_from_roots(&[Fp::from(2u64), Fp::from(5u64)]);
        assert_eq!(coeffs.len(), 3);
        assert_eq!(coeffs[0], Fp::from(10u64));
        assert_eq!(coeffs[1], -Fp::from(7u64));
        assert_eq!(coeffs[2], Fp::ONE);
    }

    #[test]
    fn eval_at_root_is_zero() {
        let root = Fp::from(42u64);
        let coeffs = poly_from_roots(&[root, Fp::from(7u64)]);
        assert_eq!(poly_eval(&coeffs, root), Fp::ZERO);
    }

    #[test]
    fn eval_at_non_root_is_nonzero() {
        let coeffs = poly_from_roots(&[Fp::from(1u64), Fp::from(2u64)]);
        assert_ne!(poly_eval(&coeffs, Fp::from(3u64)), Fp::ZERO);
    }

    #[test]
    fn commitment_is_deterministic() {
        let coeffs = poly_from_roots(&[Fp::from(1u64), Fp::from(2u64)]);
        assert_eq!(pedersen_commit(&coeffs), pedersen_commit(&coeffs));
    }

    #[test]
    fn different_polynomials_different_commitments() {
        let first = pedersen_commit(&poly_from_roots(&[Fp::from(1u64)]));
        let second = pedersen_commit(&poly_from_roots(&[Fp::from(2u64)]));
        assert_ne!(first, second);
    }

    #[test]
    fn root_order_independent() {
        let forward = poly_from_roots(&[Fp::from(3u64), Fp::from(7u64)]);
        let reverse = poly_from_roots(&[Fp::from(7u64), Fp::from(3u64)]);
        assert_eq!(forward, reverse);
    }

    #[test]
    fn commitment_is_additive() {
        let coeffs_left = poly_from_roots(&[Fp::from(1u64)]);
        let coeffs_right = poly_from_roots(&[Fp::from(2u64)]);

        let len = coeffs_left.len().max(coeffs_right.len());
        let mut coeffs_sum = alloc::vec![Fp::ZERO; len];
        for (idx, &coeff) in coeffs_left.iter().enumerate() {
            coeffs_sum[idx] += coeff;
        }
        for (idx, &coeff) in coeffs_right.iter().enumerate() {
            coeffs_sum[idx] += coeff;
        }

        let commit_left = pedersen_commit(&coeffs_left);
        let commit_right = pedersen_commit(&coeffs_right);
        let commit_sum = pedersen_commit(&coeffs_sum);

        let point_sum = (Eq::from(commit_left) + Eq::from(commit_right)).to_affine();
        assert_eq!(
            point_sum, commit_sum,
            "Pedersen commitment must be additively homomorphic"
        );
    }

}
