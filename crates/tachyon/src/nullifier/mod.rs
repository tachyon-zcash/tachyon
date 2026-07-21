//! Nullifiers and nullifier operations.

#![allow(
    clippy::module_name_repetitions,
    reason = "name repetition is intentional"
)]

pub mod derivation;
mod mimc;
mod trace;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::Fp;
use rand_core::{CryptoRng, RngCore};
pub use trace::{
    NfFoldAccumulator, NfFoldAccumulatorCommit, NfGridSpectrum, NfGridSpectrumCommit, NfTraceGrid,
    NfWhitenedSpectrum, NfWhitenedSpectrumCommit, NullifierTrace, SboxQuarticSpectrum,
    SboxQuarticSpectrumCommit, SboxQuotientSpectrum, SboxQuotientSpectrumCommit,
    SboxSquareSpectrum, SboxSquareSpectrumCommit, WrapQuotientSpectrum, WrapQuotientSpectrumCommit,
    WrapSpectrum, WrapSpectrumCommit,
};
pub use zcash_mimc::specs::tachyon::TachyonP5R64;

use crate::{EpochIndex, keys::NoteMasterKey};

/// A Tachyon nullifier.
///
/// Derived directly from the master key: $mk = \text{KDF}(\psi, nk)$, then
/// $nf = F_{mk}(\text{epoch})$. Published when a note is spent;
/// becomes a tachygram in the polynomial accumulator.
///
/// Unlike Orchard, Tachyon nullifiers:
/// - Don't need collision resistance (no faerie gold defense)
/// - Have an epoch "epoch" component for sync delegation
/// - Are prunable by validators after a window of blocks
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct Nullifier(#[debug(skip)] Fp);

impl Nullifier {
    /// Derive a nullifier from a master key and an epoch.
    #[must_use]
    pub fn derive(mk: &NoteMasterKey, epoch: EpochIndex) -> Self {
        Self(mimc::nullifier(mk.0, Fp::from(epoch), mk.1))
    }

    /// Produce a nullifier derivation state sequence and final nullifier from a
    /// master key and an epoch.
    #[must_use]
    pub fn derive_trace(mk: &NoteMasterKey, epoch: EpochIndex) -> (NullifierTrace, Self) {
        let trace = mimc::nullifier_trace(mk.0, Fp::from(epoch));
        #[expect(clippy::indexing_slicing, reason = "known size")]
        let nullifier = Self(trace[trace.len() - 1] + mk.1);
        (NullifierTrace::from(trace), nullifier)
    }
}

/// Nullifier trapdoor ($\psi$) — per-note randomness for nullifier derivation.
///
/// Used to derive the master root key: $mk = \text{KDF}(\psi, nk)$, which
/// evaluates $nf = F_{mk}(\text{epoch})$ directly per epoch.
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

    #[test]
    fn debug_nullifier_redacts_value() {
        let nf = Nullifier::from(Fp::from(0xBEEFu64));
        let dbg = alloc::format!("{nf:?}");
        assert!(dbg.contains("Nullifier"), "must name the type");
        assert!(!dbg.contains("BEEF"), "must not leak field element");
        assert!(!dbg.contains("48879"), "must not leak decimal value");
    }
}
