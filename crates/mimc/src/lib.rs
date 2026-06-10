//! # zcash_mimc
//!
//! Implements MiMC-p/p for a defined [`Spec`].
//!
//! [cryptoeprint 2016/492]: https://eprint.iacr.org/2016/492

#![no_std]

use ff::{Field as _, PrimeField};

pub mod specs;

/// A specification for MiMC-p/p over a prime field.
pub trait Spec<const R: usize> {
    /// The field over which the cipher operates.
    type Field: PrimeField;

    /// The round-constant schedule, which must start with the field's additive
    /// identity element (zero).
    const CONSTANTS: &'static [Self::Field; R];

    /// The s-box exponent: each round computes $x \mapsto x^{\mathsf{POW}}$.
    ///
    /// This must produce a permutation, meaning $\gcd(\mathsf{POW}, p - 1)$
    /// must be 1.
    const POW: u64;

    /// The number of rounds.
    #[expect(clippy::as_conversions, reason = "compile time")]
    const ROUNDS: u64 = R as u64;
}

/// The per-round S-box input state sequence.
#[must_use]
#[inline]
pub fn sbox_input_sequence<S: Spec<R>, const R: usize>(
    keys: &[S::Field],
    input: S::Field,
) -> [S::Field; R] {
    let mut key_cycle = keys.iter().cycle();
    let mut state = input;
    S::CONSTANTS.map(|round_constant| {
        #[expect(clippy::expect_used, reason = "cycling a non-empty slice never ends")]
        let round_key = key_cycle.next().expect("keys must not be empty");

        let sbox_input = state + round_constant + round_key;
        let sbox_output = sbox_input.pow([S::POW]);

        state = sbox_output;
        sbox_input
    })
}

/// The per-round S-box output state sequence.
#[must_use]
#[inline]
pub fn sbox_output_sequence<S: Spec<R>, const R: usize>(
    keys: &[S::Field],
    input: S::Field,
) -> [S::Field; R] {
    let mut key_cycle = keys.iter().cycle();
    let mut state = input;
    S::CONSTANTS.map(|round_constant| {
        #[expect(clippy::expect_used, reason = "cycling a non-empty slice never ends")]
        let round_key = key_cycle.next().expect("keys must not be empty");

        let sbox_input = state + round_constant + round_key;
        let sbox_output = sbox_input.pow([S::POW]);

        state = sbox_output;
        sbox_output
    })
}

/// The per-round S-box input and output state sequence.
#[must_use]
#[inline]
pub fn state_sequence<S: Spec<R>, const R: usize>(
    keys: &[S::Field],
    input: S::Field,
) -> [(S::Field, S::Field); R] {
    let mut key_cycle = keys.iter().cycle();
    let mut state = input;
    S::CONSTANTS.map(|round_constant| {
        #[expect(clippy::expect_used, reason = "never ends")]
        let round_key = key_cycle.next().expect("keys must not be empty");

        let sbox_input = state + round_constant + round_key;
        let sbox_output = sbox_input.pow([S::POW]);

        state = sbox_output;
        (sbox_input, sbox_output)
    })
}

/// MiMC-$p$/$p$ encryption under the cyclic key schedule `keys`.
///
/// If a final whitening key is not provided, the next round key is used.
#[must_use]
#[inline]
pub fn encrypt_with<S: Spec<R>, const R: usize>(
    keys: &[S::Field],
    input: S::Field,
    whitening: Option<S::Field>,
) -> S::Field {
    assert!(!keys.is_empty(), "keys must not be empty");

    let mut key_cycle = keys.iter().cycle();

    let state = S::CONSTANTS
        .iter()
        .zip(key_cycle.by_ref())
        .fold(input, |state, (round_constant, round_key)| {
            (state + round_constant + round_key).pow([S::POW])
        });

    state
        + whitening.unwrap_or_else(|| {
            #[expect(clippy::expect_used, reason = "already asserted")]
            *key_cycle.next().expect("never ends")
        })
}
