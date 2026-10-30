use alloc::{vec, vec::Vec};
use core::mem;

use ragu_core::pasta::Fp;
use udon::{
    exec::{ExecutionOptions, SerialExecutor},
    fft::{Domain, Expansion, Transform},
    field::{Field as _, FieldAdapter},
    polynomial::vanishing_polynomial,
};

/// Roots per leaf of the [`poly_with_roots`] product tree.
const ROOT_CHUNK: usize = 128;

pub(super) fn poly_mul(left: &[Fp], right: &[Fp], out: &mut Vec<Fp>) {
    out.clear();

    if left.is_empty() || right.is_empty() {
        return;
    }

    let schoolbook_cost = left.len().saturating_mul(right.len());
    let fft_cost = (left.len() + right.len() - 1)
        .next_power_of_two()
        .saturating_mul(16);
    if schoolbook_cost <= fft_cost {
        poly_mul_schoolbook(left, right, out);
    } else {
        poly_mul_fft(left, right, out);
    }
}

#[expect(clippy::indexing_slicing, reason = "the output spans the convolution")]
fn poly_mul_schoolbook(left: &[Fp], right: &[Fp], out: &mut Vec<Fp>) {
    out.resize(left.len() + right.len() - 1, Fp::ZERO);
    for (i, &ai) in left.iter().enumerate() {
        for (j, &bj) in right.iter().enumerate() {
            out[i + j] += ai * bj;
        }
    }
}

#[expect(
    clippy::expect_used,
    reason = "the product fits the FFT domain, which expands onto itself"
)]
fn poly_mul_fft(left: &[Fp], right: &[Fp], out: &mut Vec<Fp>) {
    let result_len = left.len() + right.len() - 1;
    let n = result_len.next_power_of_two();
    let transform = Transform::new(
        Domain::for_size(n)
            .expect("product fits the FFT domain")
            .subgroup(),
    );
    let expansion = Expansion::new(transform, transform.domain(), None)
        .expect("a subgroup expands onto itself");

    out.resize(2 * n, Fp::ZERO);
    let (product, factor) = FieldAdapter::as_slice_mut(out).split_at_mut(n);
    expansion
        .coefficients(
            FieldAdapter::as_slice(right),
            factor,
            ExecutionOptions::default(),
            &SerialExecutor,
            &mut [],
        )
        .expect("factor fits the FFT domain");
    expansion
        .short_product(
            FieldAdapter::as_slice(left),
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
}

#[expect(
    clippy::expect_used,
    reason = "each leaf spans its roots and leading one; the nonempty product tree has a root"
)]
pub(super) fn poly_with_roots(roots: &[Fp]) -> Vec<Fp> {
    if roots.is_empty() {
        return vec![Fp::ONE];
    }

    let mut polys: Vec<Vec<Fp>> = roots
        .chunks(ROOT_CHUNK)
        .map(|chunk| {
            let mut leaf = vec![Fp::ZERO; chunk.len() + 1];
            vanishing_polynomial(
                FieldAdapter::as_slice(chunk),
                FieldAdapter::as_slice_mut(&mut leaf),
            )
            .expect("leaf spans its roots and leading one");
            leaf
        })
        .collect();
    let mut out = Vec::new();

    while polys.len() > 1 {
        let mut next = Vec::with_capacity(polys.len().div_ceil(2));
        let mut iter = polys.into_iter();
        while let Some(mut first) = iter.next() {
            if let Some(second) = iter.next() {
                poly_mul(&first, &second, &mut out);
                mem::swap(&mut first, &mut out);
            }
            next.push(first);
        }
        polys = next;
    }

    polys.into_iter().next().expect("nonempty product tree")
}
