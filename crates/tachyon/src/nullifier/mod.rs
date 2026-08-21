//! Nullifiers and nullifier operations.

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::Fp;
use rand_core::{CryptoRng, RngCore};

use crate::primitives::Tachygram;

/// Epochs covered per nullifier derivation step.
pub(crate) const NF_DERIVATION_WIDTH: usize = 16;

/// The longest epoch span one factor-product sequence can hold: each member
/// is a cubic factor, so a span of $n$ epochs costs $3n + 1$ coefficients
/// against the $2^{\mathsf{R}}$ polynomial cap.
///
/// Host-side constructors assert this bound; in-circuit no enforcement is
/// needed, since an oversized product exceeds the coefficient cap and cannot
/// be committed at all.
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "flooring to the last whole factor is the intended bound"
)]
pub const NF_MAX_FUSED_SPAN: usize = ((1 << ragu::Polynomial::R) - 1) / 3;

/// A Tachyon nullifier.
///
/// Derived from the note's master key $\mathsf{mk} =
/// \mathsf{Poseidon}(\mathtt{NF\_MASTER\_DOMAIN}, \psi, \mathsf{nk})$ as one
/// squeeze of the sponge keyed on $\mathsf{mk}$ and the epoch's group index.
/// Published when a note is spent.
///
/// Unlike Orchard, Tachyon nullifiers:
/// - Don't need collision resistance (no faerie gold defense)
/// - Have an epoch component for sync delegation
/// - Are prunable by validators after a window of blocks
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
#[from(Fp, Tachygram)]
#[into(Fp, Tachygram)]
pub struct Nullifier(Tachygram);

/// Nullifier trapdoor ($\psi$), per-note randomness for nullifier derivation.
///
/// Used to derive the note's master key $\mathsf{mk} =
/// \mathsf{Poseidon}(\mathtt{NF\_MASTER\_DOMAIN}, \psi, \mathsf{nk})$, which
/// evaluates every epoch. Delegation carries proven value windows.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct Trapdoor(#[debug(skip)] Fp);

impl Trapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<RNG: RngCore + CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(rng))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_nullifier_trapdoor_redacts_value() {
        let psi = Trapdoor::from(Fp::from(0xCAFEu64));
        let dbg = alloc::format!("{psi:?}");
        assert!(dbg.contains("Trapdoor"), "must name the type");
        assert!(!dbg.contains("CAFE"), "must not leak field element");
        assert!(!dbg.contains("51966"), "must not leak decimal value");
    }
}
