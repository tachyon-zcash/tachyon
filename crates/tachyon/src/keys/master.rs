//! Per-note master key for nullifier derivation.

use core::array;

use derive_more::{Debug, Eq as TotalEq, Into, PartialEq};
use pasta_curves::Fp;
use ragu_arithmetic::PoseidonPermutation as _;
use ragu_pasta::PoseidonFp;

use crate::{
    digest::poseidon,
    nullifier::{NF_DERIVATION_WIDTH, Nullifier},
    primitives::EpochIndex,
};

/// Per-note master key.
///
/// Derived by the user device from [`NullifierKey`](super::NullifierKey) and
/// the note's $\psi$ trapdoor, and the only key material a nullifier
/// derivation needs. Epochs are derived `PoseidonFp::RATE` at a time from
/// one sponge keyed on the group's start epoch.
///
/// `mk` grants derivation over the whole epoch space; a delegate receives
/// proven value windows.
#[derive(Clone, Copy, Debug, Into, PartialEq, TotalEq)]
pub struct NoteMasterKey(#[debug(skip)] pub(crate) Fp);

impl NoteMasterKey {
    /// Derive the nullifier for a single epoch.
    #[must_use]
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        clippy::integer_division_remainder_used,
        reason = "the remainder indexes an array of PoseidonFp::RATE"
    )]
    pub fn derive_nullifier(&self, epoch: EpochIndex) -> Nullifier {
        let index = u32::from(epoch);
        let inner_index = index as usize % PoseidonFp::RATE;
        let epoch_start = EpochIndex::new(index - (inner_index as u32));
        Nullifier::from(poseidon::nullifier_group(self.0, epoch_start.into())[inner_index])
    }

    /// Derive one derivation window: the nullifiers for
    /// `[epoch_start, … + NF_DERIVATION_WIDTH)`.
    ///
    /// `epoch_start` must be group-aligned;
    /// [`NullifierDerive`](crate::stamp::proof::delegation::NullifierDerive)
    /// constrains its witnessed start epoch accordingly. Group alignment
    /// makes the sponge count a compile-time constant inside the step:
    /// `NF_DERIVATION_WIDTH / PoseidonFp::RATE` permutations each way.
    ///
    /// # Panics
    ///
    /// If the window would run past [`EPOCH_MAX`](crate::constants::EPOCH_MAX).
    #[must_use]
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "both widths are small powers of two and divide exactly"
    )]
    pub fn derive_window(&self, epoch_start: EpochIndex) -> [Nullifier; NF_DERIVATION_WIDTH] {
        debug_assert_eq!(
            u32::from(epoch_start) % (PoseidonFp::RATE as u32),
            0,
            "epoch_start must be group-aligned"
        );
        let groups: [[Fp; PoseidonFp::RATE]; NF_DERIVATION_WIDTH / PoseidonFp::RATE] =
            array::from_fn(|offset| {
                let group_start = u32::from(epoch_start) + (offset * PoseidonFp::RATE) as u32;
                poseidon::nullifier_group(self.0, Fp::from(EpochIndex::new(group_start)))
            });
        array::from_fn(|slot| {
            Nullifier::from(groups[slot / PoseidonFp::RATE][slot % PoseidonFp::RATE])
        })
    }
}
