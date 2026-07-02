//! The relations the proof system enforces, in two faces:
//!
//! - [`enforce`]: the in-circuit constraint side. Every relation takes a
//!   `StepCtx`, derives a Fiat-Shamir challenge from the operand commitments,
//!   and opens them to check the identity point-wise.
//! - [`quotient`]: the off-circuit native side. Pure field/FFT arithmetic that
//!   builds the witness polynomials those relations open.
//!
//! [`subgroup_generator`] is the evaluation-domain vocabulary both faces share.

use ff::PrimeField as _;
use pasta_curves::Fp;
use ragu::Domain;

pub(crate) mod enforce;
pub(crate) mod quotient;

/// The generator (`omega`) of the size-`N` evaluation-domain subgroup: a
/// primitive `N`-th root of unity in `Fp`. `N` is the domain size, not its rank
/// (log2): a power of two no larger than `2^Fp::S` (both checked at compile
/// time). Mirrors ragu's `Domain::new(N.ilog2()).omega()`.
pub(crate) fn subgroup_generator<const N: usize>() -> Fp {
    const {
        assert!(N.is_power_of_two(), "domain size must be a power of two");
        assert!(
            N.ilog2() <= Fp::S,
            "domain size exceeds the field's two-adicity"
        );
    }

    Domain::new(N.ilog2()).omega()
}
