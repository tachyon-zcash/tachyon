extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::Fp;
use ragu_arithmetic as arithmetic;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};

pub(crate) mod indexed_multiset;
pub(crate) mod multiset;
pub(crate) mod qr;

#[cfg(test)]
fn trim(coeffs: &mut Vec<Fp>) {
    if let Some(last_nonzero_idx) = coeffs.iter().rposition(|co| co != &Fp::ZERO) {
        coeffs.truncate(last_nonzero_idx + 1);
    }
}

/// Realized polynomial product, kept as a test-only reference implementation:
/// production multiset composition happens in set form
/// ([`indexed_multiset::IndexedMultiset::union`]).
#[cfg(test)]
pub(super) fn poly_mul(
    input_a: &Polynomial<Fp, ProductionRank>,
    input_b: &Polynomial<Fp, ProductionRank>,
) -> Polynomial<Fp, ProductionRank> {
    let mut a_coeffs = Vec::from_iter(input_a.iter_coeffs());
    let mut b_coeffs = Vec::from_iter(input_b.iter_coeffs());

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
