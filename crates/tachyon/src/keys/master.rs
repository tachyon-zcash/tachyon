//! Per-note master key for nullifier derivation.

use core::array;

use derive_more::{Debug, Eq as TotalEq, Into, PartialEq};
use pasta_curves::Fp;

use crate::{
    digest::poseidon::{self, NF_GROUP},
    nullifier::{NF_DERIVATION_GROUPS, NF_DERIVATION_WIDTH, Nullifier},
    primitives::EpochIndex,
};

/// Per-note master key.
///
/// Derived by the user device from [`NullifierKey`](super::NullifierKey) and
/// the note's $\psi$ trapdoor, and the only key material a nullifier
/// derivation needs. Epochs are derived `NF_GROUP` at a time from one sponge
/// keyed on the group index $w = \lfloor e / \mathsf{NF\_GROUP} \rfloor$.
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
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "the group width is a small constant, and the remainder \
                  indexes an array of exactly NF_GROUP entries"
    )]
    pub fn derive_nullifier(&self, epoch: EpochIndex) -> Nullifier {
        let group = poseidon::nullifier_group(self.0, epoch.0 / NF_GROUP as u32);
        Nullifier::from(group[epoch.0 as usize % NF_GROUP])
    }

    /// Derive one derivation window: the nullifiers for
    /// `[NF_GROUP * group_base, … + NF_DERIVATION_WIDTH)`.
    ///
    /// `group_base` is the window's *group* index. Group alignment makes the
    /// sponge count a compile-time constant inside
    /// [`NfDerive`](crate::stamp::proof::delegation::NfDerive):
    /// `NF_DERIVATION_GROUPS` permutations.
    #[must_use]
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "both widths are small powers of two and divide exactly"
    )]
    pub fn derive_window(&self, group_base: u32) -> [Nullifier; NF_DERIVATION_WIDTH] {
        let groups: [[Fp; NF_GROUP]; NF_DERIVATION_GROUPS] =
            array::from_fn(|offset| poseidon::nullifier_group(self.0, group_base + offset as u32));
        array::from_fn(|slot| Nullifier::from(groups[slot / NF_GROUP][slot % NF_GROUP]))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing,
        clippy::integer_division,
        clippy::integer_division_remainder_used,
        reason = "epoch and group arithmetic over constant widths, indexing \
                  arrays of exactly those widths"
    )]

    extern crate alloc;

    use alloc::vec::Vec;

    use ff::Field as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;

    fn master(seed: u64) -> NoteMasterKey {
        NoteMasterKey(Fp::random(&mut StdRng::seed_from_u64(seed)))
    }

    /// The window is the per-epoch derivation, laid out.
    #[test]
    fn window_matches_per_epoch_derivation() {
        let mk = master(0);
        let group_base = 24u32;

        for (offset, nf) in mk.derive_window(group_base).into_iter().enumerate() {
            let epoch = EpochIndex(group_base * NF_GROUP as u32 + offset as u32);
            assert_eq!(nf, mk.derive_nullifier(epoch), "epoch {}", epoch.0);
        }
    }

    /// An epoch's nullifier depends only on its own group, so overlapping
    /// windows agree on the epochs they share. `UnspentBind` reads a window
    /// that merely *covers* its span.
    #[test]
    fn overlapping_windows_agree() {
        let mk = master(0);
        let low = mk.derive_window(10);
        let high = mk.derive_window(11);
        let shared = NF_DERIVATION_WIDTH - NF_GROUP;

        for offset in 0..shared {
            assert_eq!(
                low[offset + NF_GROUP],
                high[offset],
                "epoch {}",
                11 * NF_GROUP + offset
            );
        }
    }

    /// Distinct epochs within one group must not collide: the four squeezes
    /// of a single permutation are distinct outputs.
    #[test]
    fn distinct_epochs_within_a_group_differ() {
        let mk = master(1);
        let derived: Vec<Nullifier> = (0..NF_GROUP)
            .map(|epoch| mk.derive_nullifier(EpochIndex(epoch as u32)))
            .collect();

        for (index, nf) in derived.iter().enumerate() {
            for other in derived.iter().skip(index + 1) {
                assert_ne!(*nf, *other, "squeeze {index} collides within its group");
            }
        }
    }

    /// Distinct groups must not collide either: the group index is absorbed.
    #[test]
    fn distinct_groups_differ() {
        let mk = master(1);
        assert_ne!(
            mk.derive_nullifier(EpochIndex(0)),
            mk.derive_nullifier(EpochIndex(NF_GROUP as u32)),
        );
    }

    /// Distinct master keys must not collide at the same epoch.
    #[test]
    fn distinct_keys_differ() {
        assert_ne!(
            master(2).derive_nullifier(EpochIndex(7)),
            master(3).derive_nullifier(EpochIndex(7)),
        );
    }
}
