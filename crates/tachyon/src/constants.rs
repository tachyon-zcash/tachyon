//! Protocol-wide non-hash constants.

/// Maximum note value in zatoshis (§5.3 of the protocol spec)
pub const NOTE_VALUE_MAX: u64 = 2_100_000_000_000_000;

const EPOCH_SHIFT: u32 = if cfg!(test) { 4 } else { 12 };

/// Number of blocks per epoch.
pub const EPOCH_SIZE: u32 = 1 << EPOCH_SHIFT;

/// Maximum epoch index.
pub const EPOCH_MAX: u32 = u32::MAX >> EPOCH_SHIFT;

/// Length of each note's pronullifier polynomial `M` (its epoch
/// lifetime). Small for tests; a real note uses the maximum
/// (`ragu::MAX_GENERATORS = 2^13`) and rolls over before exhausting it.
pub(crate) const NOTE_LIFETIME_MAX: usize = 1 << if cfg!(test) { 4 } else { 13 };
