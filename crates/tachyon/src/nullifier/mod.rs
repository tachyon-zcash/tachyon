//! Nullifiers and nullifier operations.

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::Fp;
use rand_core::{CryptoRng, RngCore};

use crate::{digest::poseidon::NF_GROUP, primitives::Tachygram};

/// Epoch nullifiers per derivation window.
///
/// A multiple of [`NF_GROUP`], so the sponge count is exact: 16 epochs is
/// four sponges, one permutation each.
pub const NF_DERIVATION_WIDTH: usize = 16;

/// Sponges one derivation window costs, a compile-time constant because
/// window bases are group-aligned.
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "both operands are powers of two and divide exactly"
)]
pub const NF_DERIVATION_GROUPS: usize = NF_DERIVATION_WIDTH / NF_GROUP;

const _: () = assert!(
    NF_DERIVATION_GROUPS * NF_GROUP == NF_DERIVATION_WIDTH,
    "the window width must be a whole number of sponges"
);

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
