//! # zcash_mimc
//!
//! Instances are described by a [`Spec`]: a pure-data trait carrying the
//! S-box exponent `P`, the round count `R`, and the pinned round-constant
//! table, all compile-time constants. Each shipped instantiation lives in
//! its own module.
//!
//! [eprint 2016/492]: https://eprint.iacr.org/2016/492

#![no_std]

use ff::Field as _;

pub mod specs;

/// A specification for a MiMC instance over a prime field: `R` rounds of the
/// monomial S-box $x \mapsto x^P$ under a pinned constant schedule.
///
/// A `Spec` is pure data, entirely in compile-time constants; golden vectors
/// pin the `Spec`, and constructions derive the behavior from it.
pub trait Spec<const R: usize> {
    /// The field over which the cipher operates.
    type Field: ff::PrimeField;

    /// The round-constant schedule, with $c_0 = 0$, pinned as literals from
    /// an independent reference implementation (a test re-derives the chain
    /// and cross-checks the table).
    const CONSTANTS: &'static [Self::Field; R];

    /// The S-box exponent: each round computes $x \mapsto x^{\mathsf{POW}}$.
    ///
    /// $\gcd(\mathsf{POW}, p - 1) = 1$ is required for the round function to
    /// be a permutation, which MiMC-$p$/$p$ use requires.
    const POW: u64;

    /// The number of rounds.
    #[expect(clippy::as_conversions, reason = "constant widths fit u64")]
    const ROUNDS: u64 = { R as u64 };
}

/// The per-round pre-S-box sequence under the cyclic key schedule.
///
/// Entry $i$ is round $i$'s S-box input $x_i + k_{i \bmod \kappa} + c_i$.
#[must_use]
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

/// The per-round post-S-box (pre-whitening) state sequence under the cyclic
/// key schedule.
///
/// Entry $i$ is round $i$'s output $x_{i+1}$. The caller's `input` state
/// (before round 0) is not included.
#[must_use]
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

/// The per-round pre-S-box and post-S-box state sequence under the cyclic
/// key schedule.
///
/// Entry $i$ is round $i$'s S-box input $x_i + k_{i \bmod \kappa} + c_i$ and
/// output $x_{i+1}$. The caller's input (before round 0) is not
/// included.
#[must_use]
pub fn state_sequence<S: Spec<R>, const R: usize>(
    keys: &[S::Field],
    input: S::Field,
) -> [(S::Field, S::Field); R] {
    let mut key_cycle = keys.iter().cycle();
    let mut state = input;
    S::CONSTANTS.map(|round_constant| {
        #[expect(clippy::expect_used, reason = "cycling a non-empty slice never ends")]
        let round_key = key_cycle.next().expect("keys must not be empty");
        let sbox_input = state + round_constant + round_key;
        let sbox_output = sbox_input.pow([S::POW]);
        state = sbox_output;
        (sbox_input, sbox_output)
    })
}

/// MiMC-$p$/$p$ encryption under the cyclic key schedule `keys`.
///
/// One round per constant, $x \mapsto (x + k_{i \bmod \kappa} + c_i)^P$,
/// with final whitening by the next key in the cycle
/// ($k_{r \bmod \kappa}$). For a single key this is the §2.1 cipher; for
/// several it is the §5.2 larger-key variant. Plain field arithmetic over
/// the pinned compile-time constant table, with a compile-time-fixed
/// iteration count and no allocation.
#[must_use]
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

    // If no specific whitening key is provided, use the schedule's next key.
    state
        + whitening.unwrap_or_else(|| {
            #[expect(clippy::expect_used, reason = "cycling a non-empty slice never ends")]
            *key_cycle.next().expect("keys must not be empty")
        })
}
