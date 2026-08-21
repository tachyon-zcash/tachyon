//! Nullifiers and nullifier operations.

#![allow(
    clippy::module_name_repetitions,
    reason = "name repetition is intentional"
)]

pub mod derivation;
mod trace;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::Fp;
use ragu::Polynomial;
use rand_core::{CryptoRng, RngCore};
pub use trace::{
    NfFoldAccumulator, NfFoldAccumulatorCommit, NfGridSpectrum, NfGridSpectrumCommit, NfTraceGrid,
    NfWindowSpectrum, NfWindowSpectrumCommit, NullifierTrace, SboxQuarticSpectrum,
    SboxQuarticSpectrumCommit, SboxQuotientSpectrum, SboxQuotientSpectrumCommit,
    SboxSquareSpectrum, SboxSquareSpectrumCommit, WrapQuotientSpectrum, WrapQuotientSpectrumCommit,
    WrapSpectrum, WrapSpectrumCommit,
};
pub use zcash_mimc::specs::tachyon::TachyonP5R64;

use crate::{constants::EPOCH_MAX, primitives::Tachygram};

/// Epoch nullifiers per derivation window.
///
/// One window's round-state grid fills exactly one commitment polynomial:
/// $W = 2^{R_{\mathsf{poly}}} / \mathsf{ROUNDS}$ rows of `ROUNDS` columns.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "the round count is a small constant, and both operands are \
              powers of two"
)]
pub const NF_DERIVATION_WIDTH: usize = (1 << Polynomial::R) / TachyonP5R64::ROUNDS as usize;

/// The largest window base whose window stays inside the epoch space.
#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "the window width is a small constant"
)]
pub const NF_BASE_MAX: u32 = EPOCH_MAX - (NF_DERIVATION_WIDTH as u32 - 1);

/// A Tachyon nullifier.
///
/// Derived directly from the note's master key: $\mathsf{mk} = [k, w] =
/// \mathsf{Poseidon}(\psi, \mathsf{nk})$, then $\mathsf{nf}_e = E_k(e) + w$
/// under the nullifier cipher. Published when a note is spent.
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
