//! Per-note master key for nullifier derivation.

use core::array;

use derive_more::{Debug, Eq as TotalEq, Into, PartialEq};
use ragu::PoseidonPermutation as _;
use ragu::pasta::PoseidonFp;

use crate::digest::poseidon;
use crate::nullifier::{NF_DERIVATION_WIDTH, Nullifier};
use crate::pasta::Fp;
use crate::primitives::EpochIndex;

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
        clippy::indexing_slicing,
        reason = "the remainder indexes an array of PoseidonFp::RATE"
    )]
    #[expect(
        clippy::expect_used,
        reason = "the fixed Poseidon rate and derivation window bound the conversions"
    )]
    #[expect(
        clippy::missing_panics_doc,
        reason = "the fixed Poseidon rate bounds the converted lane index on supported targets"
    )]
    pub fn derive_nullifier(&self, epoch: EpochIndex) -> Nullifier {
        let index = u32::from(epoch);
        let rate = u32::try_from(PoseidonFp::RATE).expect("the fixed Poseidon rate fits u32");
        let inner_offset = index % rate;
        let inner_index = usize::try_from(inner_offset).expect("a Poseidon lane index fits usize");
        let epoch_start = EpochIndex::new(index - inner_offset);
        Nullifier::from(poseidon::nullifier_group(self.0, epoch_start.into())[inner_index])
    }

    /// Derive one derivation window: the nullifiers for
    /// `[epoch_start, epoch_start + NF_DERIVATION_WIDTH - 1]`.
    ///
    /// `epoch_start` must be group-aligned;
    /// [`NullifierDerive`](crate::stamp::proof::delegation::NullifierDerive)
    /// constrains its witnessed start epoch accordingly. Group alignment
    /// makes the sponge count a compile-time constant inside the step:
    /// `NF_DERIVATION_WIDTH / PoseidonFp::RATE` permutations each way.
    ///
    /// # Panics
    ///
    /// Panics if `epoch_start` is not group-aligned, or the window would run
    /// past [`EPOCH_MAX`](crate::constants::EPOCH_MAX).
    #[must_use]
    #[expect(
        clippy::indexing_slicing,
        reason = "both widths are small powers of two and divide exactly"
    )]
    #[expect(
        clippy::expect_used,
        reason = "the fixed Poseidon rate and derivation window bound the conversions"
    )]
    #[expect(
        clippy::integer_division,
        reason = "the sponge rate divides the window width, and each slot belongs to its floored group index"
    )]
    pub fn derive_window(&self, epoch_start: EpochIndex) -> [Nullifier; NF_DERIVATION_WIDTH] {
        assert_eq!(
            u32::from(epoch_start)
                % u32::try_from(PoseidonFp::RATE).expect("the fixed Poseidon rate fits u32"),
            0,
            "epoch_start must be group-aligned"
        );
        let groups: [[Fp; PoseidonFp::RATE]; NF_DERIVATION_WIDTH / PoseidonFp::RATE] =
            array::from_fn(|offset| {
                let group_offset = u32::try_from(offset * PoseidonFp::RATE)
                    .expect("a group offset fits within the fixed derivation window");
                let group_start = u32::from(epoch_start) + group_offset;
                poseidon::nullifier_group(self.0, Fp::from(EpochIndex::new(group_start)))
            });
        array::from_fn(|slot| {
            Nullifier::from(groups[slot / PoseidonFp::RATE][slot % PoseidonFp::RATE])
        })
    }
}
