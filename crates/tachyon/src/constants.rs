//! Protocol-wide non-hash constants.

/// Maximum representable value in zatoshis (§5.3 of the protocol spec).
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;

const EPOCH_SHIFT: u32 = if cfg!(test) { 4 } else { 12 };

/// Number of blocks per epoch.
pub const EPOCH_SIZE: u32 = 1 << EPOCH_SHIFT;

/// Maximum epoch index.
pub const EPOCH_MAX: u32 = u32::MAX >> EPOCH_SHIFT;
