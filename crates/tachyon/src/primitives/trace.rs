//! Expansion-trace polynomial newtypes.
//!
//! One GGM node expansion is proven as a committed trace polynomial plus its
//! bound output polynomial. The trace `T` interpolates the row-major
//! `GGM_TREE_ARITY × ROUNDS` cipher-state grid over the order-`POLY_LEN_MAX`
//! subgroup `⟨ω⟩` (`T(ω^{ROUNDS·r + c})` is row `r`'s `c`-th cipher state);
//! the output polynomial interpolates the whitened final column over the
//! order-`GGM_TREE_ARITY` subgroup `⟨ζ⟩ = ⟨ω^ROUNDS⟩`. Interpolation lives
//! with the producers in [`keys`](crate::keys); these are the succinct
//! carriers steps witness and headers commit to, plus the one public
//! polynomial they all share, [`struct@CONSTANT_SCHEDULE`].

extern crate alloc;

use alloc::{vec, vec::Vec};

use derive_more::{Debug, Eq as TotalEq, PartialEq};
use ff::Field as _;
use lazy_static::lazy_static;
use pasta_curves::{Eq, Fp};
use ragu::{Domain, Polynomial};
use zcash_mimc::spec::tachyon::TachyonP5R128;

use crate::keys::GGM_TREE_ARITY;

lazy_static! {
    /// The public constant schedule `C`: the full-domain interpolant of the
    /// per-column round-constant offset, `C(ω^i) = CONSTANTS[(i mod ROUNDS) +
    /// 1]` off the wrap column, and `0` on it (`i ≡ ROUNDS − 1`, whose step
    /// the recurrence masks). This is the committed constants operand the
    /// in-circuit committed-offset recurrence opens at `z`, so it must be the
    /// interpolant (ifft) of the column values, never the raw values as
    /// coefficients. The values are column-periodic, so the interpolant is
    /// `C_col(X^{GGM_TREE_ARITY})`: the order-`ROUNDS` column interpolant
    /// with coefficient `k` spread to degree `k·GGM_TREE_ARITY`.
    pub static ref CONSTANT_SCHEDULE: Polynomial = {
        let mut columns: Vec<Fp> = TachyonP5R128::CONSTANTS
            .iter()
            .skip(1)
            .copied()
            .chain([Fp::ZERO])
            .collect();
        Domain::new(TachyonP5R128::ROUNDS.ilog2()).ifft(&mut columns);
        let mut coeffs = vec![Fp::ZERO; (TachyonP5R128::ROUNDS - 1) * GGM_TREE_ARITY + 1];
        for (slot, coeff) in coeffs.iter_mut().step_by(GGM_TREE_ARITY).zip(columns) {
            *slot = coeff;
        }
        Polynomial::from_coeffs(&coeffs)
    };
}

/// One node expansion's committed trace interpolant `T` over `⟨ω⟩`.
///
/// Wallet-only secret material.
#[derive(Clone, Debug)]
pub struct NfPrefixTracePoly(#[debug(skip)] pub Polynomial);

/// The eval-form child-schedule polynomial over `⟨ζ⟩`
/// (`K(ζ^r) = child schedule key r`), bound to its parent's trace final
/// column by the decimation relation.
///
/// Wallet-only secret material.
#[derive(Clone, Debug)]
pub struct NfPrefixPoly(#[debug(skip)] pub Polynomial);

/// Commitment to a [`NfPrefixPoly`]: the succinct node identity headers carry.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct NfPrefixCommit(pub Eq);

/// The eval-form leaf-nullifier polynomial over `⟨ζ⟩` (`B(ζ^p) = nf_{base+p}`).
///
/// A depth-2 node's own expansion output, whose values are the covered epochs'
/// nullifiers. Internal to `NullifierDerivationStep`, which binds it to the
/// published coeff-form sequence; never carried on a header.
///
/// Wallet-only secret material until individual nullifiers are published.
#[derive(Clone, Debug)]
pub struct NfLeafPoly(#[debug(skip)] pub Polynomial);

#[cfg(test)]
mod tests {
    #![allow(
        clippy::as_conversions,
        clippy::indexing_slicing,
        clippy::integer_division_remainder_used,
        reason = "test code"
    )]

    use super::*;
    use crate::{constants::POLY_LEN_MAX, relations::subgroup_generator};

    /// `C(ω^i)` is column `i mod ROUNDS`'s rotated constant everywhere off
    /// the wrap column, and zero on it — in every row, not just the first.
    #[test]
    fn constant_schedule_interpolates_the_column_constants() {
        let omega = subgroup_generator::<POLY_LEN_MAX>();
        let constants = TachyonP5R128::CONSTANTS;

        for position in [0usize, 1, 130, 8000] {
            assert_eq!(
                CONSTANT_SCHEDULE.eval(omega.pow_vartime([position as u64])),
                constants[(position % TachyonP5R128::ROUNDS) + 1],
                "C(omega^i) must be the rotated constant of column i mod ROUNDS"
            );
        }

        for wrap in [TachyonP5R128::ROUNDS - 1, POLY_LEN_MAX - 1] {
            assert_eq!(
                CONSTANT_SCHEDULE.eval(omega.pow_vartime([wrap as u64])),
                Fp::ZERO,
                "the masked wrap column carries a zero constant"
            );
        }
    }
}
