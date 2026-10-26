extern crate alloc;

use alloc::vec::Vec;

use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::pasta;
use udon::field::{Fp, Reduced};

pub(crate) mod indexed_multiset;
pub(crate) mod multiset;
pub(crate) mod qr;

mod arithmetic;

fn trim(coeffs: &mut Vec<Fp>) {
    if let Some(last_nonzero_idx) = coeffs.iter().rposition(|co| !co.is_zero()) {
        coeffs.truncate(last_nonzero_idx + 1);
    }
}

pub(super) fn poly_mul(
    input_a: &Polynomial<pasta::Fp, ProductionRank>,
    input_b: &Polynomial<pasta::Fp, ProductionRank>,
) -> Polynomial<pasta::Fp, ProductionRank> {
    let mut a_coeffs = input_a
        .iter_coeffs()
        .map(pasta::Fp::into_inner)
        .collect::<Vec<_>>();
    let mut b_coeffs = input_b
        .iter_coeffs()
        .map(pasta::Fp::into_inner)
        .collect::<Vec<_>>();

    trim(&mut a_coeffs);
    trim(&mut b_coeffs);

    let mut out_coeffs = Vec::new();

    arithmetic::poly_mul(&a_coeffs, &b_coeffs, &mut out_coeffs);

    trim(&mut out_coeffs);

    Polynomial::from_coeffs(out_coeffs.into_iter().map(pasta::Fp::new).collect())
}

#[expect(clippy::as_conversions, reason = "degree is under u64::MAX")]
fn derivative(coeffs: &[Fp]) -> Polynomial<pasta::Fp, ProductionRank> {
    Polynomial::from_coeffs(
        coeffs
            .iter()
            .enumerate()
            .skip(1)
            .map(|(degree, coeff)| pasta::Fp::new(<Fp>::from_u64(degree as u64).mul(coeff)))
            .collect(),
    )
}

/// The coefficients of the polynomial of least degree through `points`.
///
/// Returns `None` when two points share an abscissa.
pub(crate) fn interpolate(points: &[(Fp<Reduced>, Fp<Reduced>)]) -> Option<Vec<Fp>> {
    fn reduced(range: &[(Fp, Fp)]) -> (Vec<Fp>, Vec<Fp>) {
        if let &[(at, weighted_value)] = range {
            return ([weighted_value].to_vec(), [at.neg(), <Fp>::ONE].to_vec());
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
            *coeff = coeff.add(cross_coeff);
        }
        (combined, vanishing)
    }

    let abscissas: Vec<Fp> = points.iter().map(|&(at, _)| at.into_loose()).collect();
    let vanishing = arithmetic::poly_with_roots(&abscissas);

    // The normalizer for each point is $v'(x_i) = \prod_{j \neq i}(x_i -
    // x_j)$; a non-invertible normalizer marks a repeated abscissa.
    let normalizers = derivative(&vanishing);

    let weighted: Vec<(Fp, Fp)> = points
        .iter()
        .map(|&(abscissa, value)| {
            let at = abscissa.into_loose();
            let weight = normalizers.eval(at.into()).into_inner().invert()?;
            Some((at, weight.mul(&value)))
        })
        .collect::<Option<Vec<_>>>()?;
    if weighted.is_empty() {
        return Some([<Fp>::ZERO].to_vec());
    }

    let (mut coeffs, _) = reduced(&weighted);
    coeffs.resize(points.len(), <Fp>::ZERO);
    Some(coeffs)
}
