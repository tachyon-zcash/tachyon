//! The relations the proof system enforces, in two faces:
//!
//! - [`enforce`]: the in-circuit constraint side. Every relation takes a
//!   `StepCtx`, derives a Fiat-Shamir challenge from the operand commitments,
//!   and opens them to check the identity point-wise.
//! - [`quotient`]: the off-circuit native side. Pure field/FFT arithmetic that
//!   builds the witness polynomials those relations open.
//!
//! Each vanishing relation pairs with the quotient builder that produces its
//! witness; the remaining relations are constraint-only (they open committed
//! operands directly and need no prover-built quotient):
//!
//! | [`enforce`] relation | [`quotient`] builder |
//! | --- | --- |
//! | `enforce_committed_row_recurrence` | `expansion_round_quotient` |
//! | `enforce_committed_offset_recurrence` | `nf_emitter_round_quotient` |
//! | `enforce_first_column_values` | `nf_emitter_boundary_quotient` |
//! | `enforce_strided_column` (column raised to a fixed exponent) | `strided_column_quotient` |
//! | `enforce_affine_recurrence` (geometric weights and affine progressions) | `weight_recurrence` / `affine_recurrence_inner` |
//! | `enforce_accumulator_recurrence` | `accumulator_recurrence` |
//! | `enforce_arc_match` | constraint-only (opens the accumulator splits; offsets range-limited to the coset order) |
//! | `enforce_weighted_opening`, `enforce_geometric_opening_pair` | constraint-only (the pair's offset range-limited) |
//! | `enforce_poly_product`, `enforce_shifted_combination` | constraint-only |
//! | `enforce_interpolant` | constraint-only (opens at a challenge against the Lagrange closed form) |
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
