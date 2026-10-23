extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::Fp;
use ragu_arithmetic as arithmetic;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};

pub(crate) mod indexed_multiset;
pub(crate) mod multiset;
pub(crate) mod qr;

fn trim(coeffs: &mut Vec<Fp>) {
    if let Some(last_nonzero_idx) = coeffs.iter().rposition(|co| co != &Fp::ZERO) {
        coeffs.truncate(last_nonzero_idx + 1);
    }
}

pub(super) fn poly_mul(
    input_a: &Polynomial<Fp, ProductionRank>,
    input_b: &Polynomial<Fp, ProductionRank>,
) -> Polynomial<Fp, ProductionRank> {
    let mut a_coeffs = input_a.iter_coeffs().collect::<Vec<_>>();
    let mut b_coeffs = input_b.iter_coeffs().collect::<Vec<_>>();

    trim(&mut a_coeffs);
    trim(&mut b_coeffs);

    let mut out_coeffs = Vec::new();

    arithmetic::poly_mul(&a_coeffs, &b_coeffs, &mut out_coeffs);

    trim(&mut out_coeffs);

    Polynomial::from_coeffs(out_coeffs)
}

#[expect(clippy::as_conversions, reason = "degree is under u64::MAX")]
fn derivative(coeffs: &[Fp]) -> Polynomial<Fp, ProductionRank> {
    Polynomial::from_coeffs(
        coeffs
            .iter()
            .enumerate()
            .skip(1)
            .map(|(degree, coeff)| Fp::from(degree as u64) * coeff)
            .collect(),
    )
}

/// The coefficients of the polynomial of least degree through `points`.
///
/// Returns `None` when two points share an abscissa.
pub(crate) fn interpolate(points: &[(Fp, Fp)]) -> Option<Vec<Fp>> {
    fn reduced(range: &[(Fp, Fp)]) -> (Vec<Fp>, Vec<Fp>) {
        if let &[(at, weighted_value)] = range {
            return ([weighted_value].to_vec(), [-at, Fp::ONE].to_vec());
        }
        let (left, right) = range.split_at(range.len().div_ceil(2));
        let (left_interp, left_vanishing) = reduced(left);
        let (right_interp, right_vanishing) = reduced(right);

        let mut combined = Vec::new();
        let mut cross = Vec::new();
        let mut vanishing = Vec::new();
        arithmetic::poly_mul(&left_interp, &right_vanishing, &mut combined);
        arithmetic::poly_mul(&right_interp, &left_vanishing, &mut cross);
        arithmetic::poly_mul(&left_vanishing, &right_vanishing, &mut vanishing);
        for (coeff, cross_coeff) in combined.iter_mut().zip(cross.iter()) {
            *coeff += cross_coeff;
        }
        (combined, vanishing)
    }

    let abscissas: Vec<Fp> = points.iter().map(|&(at, _)| at).collect();
    let vanishing = arithmetic::poly_with_roots(&abscissas);

    // The normalizer for each point is $v'(x_i) = \prod_{j \neq i}(x_i -
    // x_j)$; a non-invertible normalizer marks a repeated abscissa.
    let normalizers = derivative(&vanishing);

    let weighted: Vec<(Fp, Fp)> = points
        .iter()
        .map(|&(at, value)| {
            let weight = Option::<Fp>::from(normalizers.eval(at).invert())?;
            Some((at, weight * value))
        })
        .collect::<Option<Vec<_>>>()?;
    if weighted.is_empty() {
        return Some([Fp::ZERO].to_vec());
    }

    let (mut coeffs, _) = reduced(&weighted);
    coeffs.resize(points.len(), Fp::ZERO);
    Some(coeffs)
}

#[cfg(test)]
mod tests {
    use core::iter;

    use proptest::prelude::*;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::testing::check;

    /// `count` random field elements drawn from `seed`.
    fn elements(seed: u64, count: usize) -> Vec<Fp> {
        let rng = &mut StdRng::seed_from_u64(seed);
        iter::repeat_with(|| Fp::random(&mut *rng))
            .take(count)
            .collect()
    }

    /// `count` points with random abscissas and values, drawn from `seed`.
    fn points(seed: u64, count: usize) -> Vec<(Fp, Fp)> {
        elements(seed, count)
            .into_iter()
            .zip(elements(!seed, count))
            .collect()
    }

    /// The set encoding is monic of degree the member count, vanishes at
    /// every member, and evaluates to the product of the root factors.
    #[test]
    fn set_encoding_is_monic_over_its_members() {
        check(256, (any::<u64>(), 0usize..=16), |(seed, count)| {
            let members = elements(seed, count);
            let x = elements(!seed, 1)[0];
            let encoded = multiset::encode(members.iter().copied());
            let mut coeffs = encoded.iter_coeffs().collect::<Vec<_>>();
            trim(&mut coeffs);
            prop_assert_eq!(coeffs.len(), count + 1);
            prop_assert_eq!(coeffs.last(), Some(&Fp::ONE));
            prop_assert_eq!(
                encoded.eval(x),
                members.iter().map(|&member| x - member).product::<Fp>()
            );
            for &member in &members {
                prop_assert_eq!(encoded.eval(member), Fp::ZERO);
            }
            Ok(())
        });
    }

    /// The product of two nonzero polynomials evaluates as the product of
    /// their evaluations. The zero polynomial is no set encoding: `trim`
    /// keeps its padding, so its product overflows the rank.
    #[test]
    fn poly_mul_evaluates_as_the_product() {
        let strategy = (any::<u64>(), 1usize..=12, 1usize..=12);
        check(256, strategy, |(seed, left_len, right_len)| {
            let left = Polynomial::from_coeffs(elements(seed, left_len));
            let right = Polynomial::from_coeffs(elements(!seed, right_len));
            let x = elements(seed ^ 1, 1)[0];
            prop_assert_eq!(
                poly_mul(&left, &right).eval(x),
                left.eval(x) * right.eval(x)
            );
            Ok(())
        });
    }

    /// The interpolant has one coefficient per point and passes through
    /// every point; a repeated abscissa has none.
    #[test]
    fn interpolation_passes_through_its_points() {
        check(256, (any::<u64>(), 0usize..=16), |(seed, count)| {
            let mut points = points(seed, count);
            let coeffs = interpolate(&points).unwrap();
            prop_assert_eq!(coeffs.len(), count.max(1));
            let interpolant = Polynomial::<Fp, ProductionRank>::from_coeffs(coeffs);
            for &(at, value) in &points {
                prop_assert_eq!(interpolant.eval(at), value);
            }

            if let Some(&(at, _)) = points.first() {
                points.push((at, elements(seed ^ 1, 1)[0]));
                prop_assert!(interpolate(&points).is_none());
            }
            Ok(())
        });
    }
}
