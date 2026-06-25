//! Spec tests.

#![cfg(test)]

use ff::PrimeField;
use zcash_mimc::{Spec, encrypt_with};

mod tachyon;

fn check_constants<S, F: PrimeField, const P: u64, const R: usize>(cases: &[(usize, F)])
where
    S: Spec<F, P, R>,
{
    for &(index, expected) in cases {
        assert_eq!(S::CONSTANTS[index], expected, "constant c_{index} mismatch");
    }
}

fn check_encryptions<S, F: PrimeField, const P: u64, const R: usize>(
    inputs: &[(&[F], F)],
    expected: &[F],
) where
    S: Spec<F, P, R>,
{
    assert_eq!(
        inputs.len(),
        expected.len(),
        "inputs and expected length mismatch"
    );
    for (&(keys, input), &output) in inputs.iter().zip(expected) {
        assert_eq!(
            encrypt_with::<S, F, P, R>(keys, input),
            output,
            "encryption output mismatch"
        );
    }
}
