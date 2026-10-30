//! Nullifiers and nullifier operations.

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu_core::pasta::Fp;
use rand_core::CryptoRng;
use udon::field::{Field as _, FieldAdapter, PallasBase};

use crate::primitives::Tachygram;

/// Epochs covered per nullifier derivation step.
pub const NF_DERIVATION_WIDTH: usize = 16;

/// A Tachyon nullifier.
///
/// Derived from the note's master key $\mathsf{mk} =
/// \mathsf{Poseidon}_\texttt{Tachyon-NfMaster}(\psi, \mathsf{nk})$ as one
/// squeeze of the sponge keyed on $\mathsf{mk}$ and the epoch's group start.
/// Published when a note is spent.
///
/// Unlike Orchard, Tachyon nullifiers:
/// - Don't need collision resistance (no faerie gold defense)
/// - Have an epoch component for sync delegation
/// - Are prunable by validators after a window of blocks
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
#[from(FieldAdapter<PallasBase>, Tachygram)]
#[into(FieldAdapter<PallasBase>, Tachygram)]
pub struct Nullifier(Tachygram);

/// Nullifier trapdoor ($\psi$), per-note randomness for nullifier derivation.
///
/// Used to derive the note's master key $\mathsf{mk} =
/// \mathsf{Poseidon}_\texttt{Tachyon-NfMaster}(\psi, \mathsf{nk})$, which
/// evaluates every epoch. Delegation carries proven value windows.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct Trapdoor(#[debug(skip)] FieldAdapter<PallasBase>);

impl Trapdoor {
    /// Generate a fresh random trapdoor.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(|bytes| rng.fill_bytes(bytes)))
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
