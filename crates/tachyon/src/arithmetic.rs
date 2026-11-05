//! Dense polynomial arithmetic over ascending `Fp` coefficient slices.

use alloc::{vec, vec::Vec};

use udon::{
    exec::{ExecutionOptions, SerialExecutor},
    fft::{Domain, Expansion, Transform},
    field::Field as _,
    polynomial::{divide_linear_in_place, evaluate_iter, vanishing_polynomial},
};

use crate::pasta::Fp;

/// Roots per leaf of the [`poly_with_roots`] product tree.
const ROOT_CHUNK: usize = 128;

/// The product of `left` and `right`, empty when either factor is empty.
pub(crate) fn poly_mul(left: &[Fp], right: &[Fp]) -> Vec<Fp> {
    if left.is_empty() || right.is_empty() {
        return Vec::new();
    }

    let schoolbook_cost = left.len().saturating_mul(right.len());
    let fft_cost = (left.len() + right.len() - 1)
        .next_power_of_two()
        .saturating_mul(16);
    if schoolbook_cost <= fft_cost {
        poly_mul_schoolbook(left, right)
    } else {
        poly_mul_fft(left, right)
    }
}

#[expect(clippy::indexing_slicing, reason = "the output spans the convolution")]
fn poly_mul_schoolbook(left: &[Fp], right: &[Fp]) -> Vec<Fp> {
    let mut out = vec![Fp::ZERO; left.len() + right.len() - 1];
    for (i, ai) in left.iter().enumerate() {
        for (j, bj) in right.iter().enumerate() {
            out[i + j] += *ai * bj;
        }
    }
    out
}

#[expect(
    clippy::expect_used,
    reason = "the product fits the FFT domain, which expands onto itself"
)]
fn poly_mul_fft(left: &[Fp], right: &[Fp]) -> Vec<Fp> {
    let result_len = left.len() + right.len() - 1;
    let n = result_len.next_power_of_two();
    let transform = Transform::new(
        Domain::for_size(n)
            .expect("product fits the FFT domain")
            .subgroup(),
    );
    let expansion = Expansion::new(transform, transform.domain(), None)
        .expect("a subgroup expands onto itself");

    let mut out = vec![Fp::ZERO; 2 * n];
    let (product, factor) = Fp::as_slice_mut(&mut out).split_at_mut(n);
    expansion
        .coefficients(
            Fp::as_slice(right),
            factor,
            ExecutionOptions::default(),
            &SerialExecutor,
            &mut [],
        )
        .expect("factor fits the FFT domain");
    expansion
        .short_product(
            Fp::as_slice(left),
            expansion.view(factor),
            product,
            ExecutionOptions::default(),
            &SerialExecutor,
            &mut [],
        )
        .expect("product fits the FFT domain");
    transform
        .inverse(
            product,
            ExecutionOptions::default(),
            &SerialExecutor,
            &mut [],
        )
        .expect("serial transform needs no scratch");
    out.truncate(result_len);
    out
}

/// The monic polynomial whose roots are `roots`, with multiplicity.
#[expect(
    clippy::expect_used,
    reason = "each leaf spans its roots and leading one; the nonempty product tree has a root"
)]
pub(crate) fn poly_with_roots(roots: &[Fp]) -> Vec<Fp> {
    if roots.is_empty() {
        return vec![Fp::ONE];
    }

    let mut polys: Vec<Vec<Fp>> = roots
        .chunks(ROOT_CHUNK)
        .map(|chunk| {
            let mut leaf = vec![Fp::ZERO; chunk.len() + 1];
            vanishing_polynomial(Fp::as_slice(chunk), Fp::as_slice_mut(&mut leaf))
                .expect("leaf spans its roots and leading one");
            leaf
        })
        .collect();

    while polys.len() > 1 {
        let mut next = Vec::with_capacity(polys.len().div_ceil(2));
        let mut iter = polys.into_iter();
        while let Some(first) = iter.next() {
            next.push(match iter.next() {
                Some(second) => poly_mul(&first, &second),
                None => first,
            });
        }
        polys = next;
    }

    polys.into_iter().next().expect("nonempty product tree")
}

/// The exact quotient of `coeffs` by $(X - \mathsf{root})$, or `None` when a
/// remainder is left.
pub(crate) fn divide_by_root(coeffs: &[Fp], root: Fp) -> Option<Vec<Fp>> {
    let mut quotient = coeffs.to_vec();
    let split = divide_linear_in_place(Fp::as_slice_mut(&mut quotient), root.as_inner());
    (split == 1 && quotient.first() == Some(&Fp::ZERO)).then(|| quotient.split_off(split))
}

/// The polynomial of least degree through `points`, or `None` when two points
/// share an abscissa.
pub(crate) fn interpolate(points: &[(Fp, Fp)]) -> Option<Vec<Fp>> {
    fn reduced(range: &[(Fp, Fp)]) -> (Vec<Fp>, Vec<Fp>) {
        if let &[(at, weighted_value)] = range {
            return ([weighted_value].to_vec(), [-at, Fp::ONE].to_vec());
        }
        let (left, right) = range.split_at(range.len().div_ceil(2));
        let (left_interp, left_vanishing) = reduced(left);
        let (right_interp, right_vanishing) = reduced(right);

        let mut combined = poly_mul(&left_interp, &right_vanishing);
        let cross = poly_mul(&right_interp, &left_vanishing);
        for (coeff, cross_coeff) in combined.iter_mut().zip(cross.iter()) {
            *coeff += cross_coeff;
        }
        (combined, poly_mul(&left_vanishing, &right_vanishing))
    }

    let abscissas: Vec<Fp> = points.iter().map(|&(at, _)| at).collect();
    let vanishing = poly_with_roots(&abscissas);

    // The normalizer for each point is $v'(x_i) = \prod_{j \neq i}(x_i -
    // x_j)$; a non-invertible normalizer marks a repeated abscissa.
    #[expect(clippy::as_conversions, reason = "degree is under u64::MAX")]
    let derivative: Vec<Fp> = vanishing
        .iter()
        .enumerate()
        .skip(1)
        .map(|(degree, coeff)| Fp::from(degree as u64) * coeff)
        .collect();

    let weighted: Vec<(Fp, Fp)> = points
        .iter()
        .map(|&(at, value)| {
            let weight = evaluate_iter(&derivative, at).invert()?;
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
