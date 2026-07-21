//! Spec tests.

#![cfg(test)]

use zcash_mimc::{Spec, encrypt_with};

mod tachyon;

fn check_constants<S, const R: usize>(cases: &[(usize, S::Field)])
where
    S: Spec<R>,
{
    for &(index, expected) in cases {
        assert_eq!(S::CONSTANTS[index], expected, "constant c_{index} mismatch");
    }
}

fn check_encryptions<S, const R: usize>(inputs: &[(&[S::Field], S::Field)], expected: &[S::Field])
where
    S: Spec<R>,
{
    assert_eq!(
        inputs.len(),
        expected.len(),
        "inputs and expected length mismatch"
    );
    for (&(keys, input), &output) in inputs.iter().zip(expected) {
        assert_eq!(
            encrypt_with::<S, R>(keys, input, None),
            output,
            "encryption output mismatch"
        );
    }
}
