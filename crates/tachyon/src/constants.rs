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
