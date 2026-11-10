//! Protocol-wide non-hash constants.

/// Maximum representable value in zatoshis (§5.3 of the protocol spec).
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;

/// Maximum block height (the protocol spec uses u32).
pub const BLOCK_MAX: u32 = u32::MAX;

/// Number of blocks per epoch. Must be a power of two (block-height
/// arithmetic derives its shift and mask from this value).
pub const EPOCH_SIZE: u32 = if cfg!(feature = "test-epoch-size") {
    64
} else {
    4096
};

/// Maximum epoch index: every block height maps to an epoch.
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "the trailing epoch is partial; flooring is the intended index"
)]
pub const EPOCH_MAX: u32 = BLOCK_MAX / EPOCH_SIZE;

const _: () = assert!(
    EPOCH_SIZE.is_power_of_two(),
    "EPOCH_SIZE must be a power of two"
);

const _: () = assert!(
    match EPOCH_MAX.checked_mul(EPOCH_SIZE) {
        Some(start) => matches!(start.checked_add(EPOCH_SIZE - 1), Some(BLOCK_MAX)),
        None => false,
    },
    "the last epoch must end exactly at BLOCK_MAX"
);

/// Children of one node of the evidence tree.
pub const EVIDENCE_TREE_ARITY: usize = 4;
