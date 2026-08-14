//! Per-note master key for nullifier derivation.

use core::array;

use derive_more::{Debug, Eq as TotalEq, PartialEq};
use pasta_curves::Fp;

use crate::{
    nullifier::{NF_DERIVATION_WIDTH, Nullifier, NullifierTrace, derivation},
    primitives::EpochIndex,
};

/// Per-note master key $\mathsf{mk} = \[k, w\]$ representing a round key and
/// whitening key.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct NoteMasterKey(#[debug(skip)] pub(crate) Fp, #[debug(skip)] pub(crate) Fp);

impl NoteMasterKey {
    /// Derive a nullifier for the given epoch.
    #[must_use]
    pub fn derive_nullifier(&self, epoch: EpochIndex) -> Nullifier {
        Nullifier::from(derivation::nullifier(self.0, self.1, epoch))
    }

    /// Derive the nullifier trace for the given epoch.
    ///
    /// The trace is unwhitened; [`NullifierTrace::whiten`] reads the nullifier
    /// off it.
    #[must_use]
    pub fn derive_nullifier_trace(&self, epoch: EpochIndex) -> NullifierTrace {
        NullifierTrace::from(derivation::nullifier_trace(self.0, epoch))
    }

    /// Derive one derivation window: the nullifiers for
    /// `[base, base + NF_DERIVATION_WIDTH)`, from any base.
    #[must_use]
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "the window width is a small constant"
    )]
    pub fn derive_window(&self, base: EpochIndex) -> [Nullifier; NF_DERIVATION_WIDTH] {
        array::from_fn(|offset| self.derive_nullifier(EpochIndex(base.0 + offset as u32)))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "epoch arithmetic over a constant window width"
    )]

    extern crate alloc;

    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    fn master(seed: u64) -> NoteMasterKey {
        let rng = &mut StdRng::seed_from_u64(seed);
        NoteMasterKey(Fp::random(&mut *rng), Fp::random(rng))
    }

    /// The window is the per-epoch derivation, laid out.
    #[test]
    fn window_matches_per_epoch_derivation() {
        let mk = master(0);
        let base = EpochIndex(391);

        for (offset, nf) in mk.derive_window(base).into_iter().enumerate() {
            let epoch = EpochIndex(base.0 + offset as u32);
            assert_eq!(nf, mk.derive_nullifier(epoch), "epoch {}", epoch.0);
        }
    }

    /// Distinct master keys must not collide at the same epoch.
    #[test]
    fn distinct_keys_differ() {
        assert_ne!(
            master(2).derive_nullifier(EpochIndex(7)),
            master(3).derive_nullifier(EpochIndex(7)),
        );
    }

    /// The two cipher entry points agree: the unwhitened trace's final cell,
    /// whitened, is the epoch's nullifier. `derive_nullifier` runs
    /// `encrypt_with` and whitens internally; `derive_nullifier_trace` runs
    /// `sbox_output_sequence` and stops short.
    #[test]
    fn trace_whitens_to_the_derived_nullifier() {
        let mk = master(1);

        for epoch in [0u32, 1, 127] {
            assert_eq!(
                mk.derive_nullifier_trace(EpochIndex(epoch)).whiten(&mk),
                mk.derive_nullifier(EpochIndex(epoch)),
            );
        }
    }

    /// Both components are secret, so neither may reach a debug rendering.
    #[test]
    fn debug_master_key_redacts_both_components() {
        let mk = NoteMasterKey(Fp::from(0xDEADu64), Fp::from(0xBEEFu64));
        let dbg = alloc::format!("{mk:?}");
        assert!(dbg.contains("NoteMasterKey"), "must name the type");
        assert!(!dbg.contains("DEAD"), "must not leak the round key");
        assert!(!dbg.contains("57005"), "must not leak the round key");
        assert!(!dbg.contains("BEEF"), "must not leak the whitening key");
        assert!(!dbg.contains("48879"), "must not leak the whitening key");
    }
}
