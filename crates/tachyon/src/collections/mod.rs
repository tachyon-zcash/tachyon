extern crate alloc;

use alloc::vec::Vec;

use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::pasta::Fp;
use udon::field::Field as _;

pub(crate) mod indexed_multiset;
pub(crate) mod multiset;
pub(crate) mod qr;

mod arithmetic;

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
            let weight = normalizers.eval(at).invert()?;
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
    use alloc::{vec, vec::Vec};

    use ragu_circuits::polynomials::Rank as _;
    use udon::polynomial::evaluate_iter;

    use super::*;

    fn coefficient_product(left: &[Fp], right: &[Fp]) -> Vec<Fp> {
        let mut result = Vec::new();
        arithmetic::poly_mul(left, right, &mut result);
        let length = result
            .iter()
            .rposition(|value| value != &Fp::ZERO)
            .map_or(0, |index| index + 1);
        result.truncate(length);
        result
    }

    #[test]
    fn fft_multiplication_handles_zero_small_and_sparse_wide_products() {
        assert_eq!(coefficient_product(&[], &[Fp::ONE]), Vec::<Fp>::new());
        assert_eq!(
            coefficient_product(&[Fp::ZERO, Fp::ZERO], &[Fp::ONE]),
            Vec::<Fp>::new()
        );
        assert_eq!(
            coefficient_product(&[Fp::from(1), Fp::from(2)], &[Fp::from(3), Fp::from(4)]),
            [Fp::from(3), Fp::from(10), Fp::from(8)]
        );
        let capacity = ProductionRank::num_coeffs();
        let mut sparse = vec![Fp::ZERO; capacity];
        *sparse.first_mut().expect("positive rank") = Fp::ONE;
        *sparse.last_mut().expect("positive rank") = Fp::from(2);
        let wide = coefficient_product(&sparse, &[Fp::from(3), Fp::ZERO, Fp::from(4)]);
        assert_eq!(wide.len(), capacity + 2);
        assert_eq!(wide.first(), Some(&Fp::from(3)));
        assert_eq!(wide.last(), Some(&Fp::from(8)));
    }

    #[test]
    fn interpolation_handles_the_rank_boundary_vanishing_scratch() {
        let capacity = ProductionRank::num_coeffs();
        let points: Vec<_> = (0..capacity)
            .map(|index| {
                let x = Fp::from(u64::try_from(index).expect("rank fits in u64"));
                (x, x.square())
            })
            .collect();
        let roots: Vec<_> = points.iter().map(|&(root, _)| root).collect();
        let vanishing = arithmetic::poly_with_roots(&roots);
        assert_eq!(vanishing.len(), capacity + 1);
        let normalizers = derivative(&vanishing);
        assert_eq!(normalizers.iter_coeffs().count(), capacity);
        let interpolant = interpolate(&points).expect("distinct interpolation abscissas");
        assert_eq!(interpolant.len(), capacity);
        for index in [0, capacity >> 1, capacity - 1] {
            let x = Fp::from(u64::try_from(index).expect("rank fits in u64"));
            assert_eq!(evaluate_iter(&interpolant, x), x.square());
        }
    }
}
