//! Dense polynomial arithmetic over ascending `Fp` coefficient slices.

use alloc::{vec, vec::Vec};

use udon::{
    exec::{ExecutionOptions, SerialExecutor},
    fft::{Domain, Expansion, Transform},
    field::Field as _,
};

use crate::pasta::Fp;

/// The product of `left` and `right`, empty when either factor is empty.
/// Udon computes the product over a domain large enough to avoid wraparound;
/// the inverse transform recovers the ascending coefficients.
#[expect(
    clippy::expect_used,
    reason = "the product fits the FFT domain, which expands onto itself"
)]
pub(crate) fn poly_mul(left: &[Fp], right: &[Fp]) -> Vec<Fp> {
    if left.is_empty() || right.is_empty() {
        return Vec::new();
    }

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
