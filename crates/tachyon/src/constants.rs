//! Protocol-wide non-hash constants.

/// Maximum representable value in zatoshis (§5.3 of the protocol spec).
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;

/// Maximum block height (the protocol spec uses u32).
pub const BLOCK_MAX: u32 = u32::MAX;

/// Number of blocks per epoch. Must be a power of two (block-height
/// arithmetic derives its shift and mask from this value).
pub const EPOCH_SIZE: u32 = 1 << { if cfg!(test) { 4 } else { 12 } };

/// Maximum epoch index: every block height maps to an epoch.
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "the trailing epoch is partial; flooring is the intended index"
)]
pub const EPOCH_MAX: u32 = BLOCK_MAX / EPOCH_SIZE;

/// Maximum tachygrams per epoch summary.
///
/// A summary's accumulator is a root-encoded set polynomial, one root per
/// tachygram below the monic top coefficient, so the polynomial rank cap
/// admits one root fewer than its coefficient count. Prover-side packing
/// only: no circuit reads a length. Small under test so walks exercise
/// multi-summary epochs.
pub const SUMMARY_CAPACITY: usize = if cfg!(test) {
    8
} else {
    (1 << ragu::Polynomial::R) - 1
};
