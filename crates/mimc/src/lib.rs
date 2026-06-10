//! # zcash_mimc
//!
//! Instances are described by a [`Spec`]: a pure-data trait carrying the
//! S-box exponent `P`, the round count `R`, and the pinned round-constant
//! table, all compile-time constants. Each shipped instantiation lives in
//! its own module.
//!
//! [eprint 2016/492]: https://eprint.iacr.org/2016/492

#![no_std]
#![allow(clippy::pub_use, reason = "crate exports")]
#![allow(clippy::indexing_slicing, reason = "simple indexing")]
#![allow(clippy::integer_division_remainder_used, reason = "todo")]

#[cfg(test)]
extern crate alloc;

use ff::PrimeField;

pub mod spec;

pub use spec::tachyon::{TachyonP5R64, TachyonP5R8192};

/// A specification for a MiMC instance over a prime field: `R` rounds of the
/// monomial S-box $x \mapsto x^P$ under a pinned constant schedule.
///
/// A `Spec` is pure data, entirely in compile-time constants; golden vectors
/// pin the `Spec`, and constructions derive the behavior from it.
pub trait Spec<F: PrimeField, const P: u64, const R: usize> {
    /// The field over which the cipher operates.
    type Field: PrimeField;

    /// The number of rounds.
    const ROUNDS: usize = R;

    /// The round-constant schedule, with $c_0 = 0$, pinned as literals from
    /// an independent reference implementation (a test re-derives the chain
    /// and cross-checks the table).
    const CONSTANTS: &'static [F; R];

    /// The S-box exponent: each round computes $x \mapsto x^P$.
    ///
    /// $\gcd(P, p - 1) = 1$ is required for the round function to be a
    /// permutation, which MiMC-$p$/$p$ use requires.
    const POW: u64 = P;
}

/// One MiMC round, the construction's S-box: $x \mapsto (x + \text{key} +
/// \text{constant})^P$.
///
/// The S-box is the single `pow_vartime` raising to the public exponent `P`, so
/// any `P` is supported (the variable-time exponentiation leaks only `P`, which
/// is public, never the secret base). This is the single source of the
/// per-round step: both [`encrypt_with`] and [`state_sequence`] are built on
/// it.
#[must_use]
pub fn round<S: Spec<F, P, R>, F: PrimeField, const P: u64, const R: usize>(
    state: F,
    key: F,
    constant: F,
) -> F {
    (state + key + constant).pow([S::POW])
}

/// The per-round pre-whitening state sequence for `R` rounds under the cyclic
/// key schedule. The caller's `input` state (before round 0) is not included.
///
/// Shares its per-round step with [`encrypt_with`] via [`round`], so the two
/// never diverge: `encrypt_with` is this sequence's final element plus the
/// whitening key.
#[must_use]
pub fn state_sequence<S: Spec<F, P, R>, F: PrimeField, const P: u64, const R: usize>(
    keys: &[F],
    input: F,
) -> [F; R] {
    assert!(!keys.is_empty(), "no keys");

    let mut states = [input; R];
    let mut state = input;
    for ((i, &constant), slot) in S::CONSTANTS.iter().enumerate().zip(states.iter_mut()) {
        state = round::<S, F, P, R>(state, keys[i % keys.len()], constant);
        *slot = state;
    }
    states
}

/// MiMC-$p$/$p$ encryption under the cyclic key schedule `keys`.
///
/// One [`round`] per constant, each adding $k_{i \bmod \kappa}$, with final
/// whitening by the next key in the cycle ($k_{r \bmod \kappa}$). For a
/// single key this is the §2.1 cipher; for several it is the §5.2 larger-key
/// variant. Plain field arithmetic over the pinned compile-time constant
/// table, with a compile-time-fixed iteration count and no allocation.
#[must_use]
pub fn encrypt_with<S: Spec<F, P, R>, F: PrimeField, const P: u64, const R: usize>(
    keys: &[F],
    input: F,
) -> F {
    assert!(!keys.is_empty(), "no keys");

    let after_rounds = S::CONSTANTS
        .iter()
        .enumerate()
        .fold(input, |state, (i, &constant)| {
            round::<S, F, P, R>(state, keys[i % keys.len()], constant)
        });

    // After `R` rounds the cyclic schedule's next key is the whitening key.
    after_rounds + keys[R % keys.len()]
}
