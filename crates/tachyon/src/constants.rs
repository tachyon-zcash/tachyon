//! Protocol-wide non-hash constants.

#![allow(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "const arithmetic"
)]

use ragu::Polynomial;
use zcash_mimc::specs::tachyon::TachyonP5R64;

/// Maximum representable value in zatoshis (§5.3 of the protocol spec).
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;

/// Maximum block height (the protocol spec uses u32).
pub const BLOCK_MAX: u32 = u32::MAX;

/// Number of blocks per epoch. Must be a power of two (block-height
/// arithmetic derives its shift and mask from this value).
///
/// 16384 blocks leaves an 18-bit epoch space.
pub const EPOCH_SIZE: u32 = 1 << { if cfg!(test) { 10 } else { 14 } };

/// Maximum epoch index: every block height maps to an epoch.
pub const EPOCH_MAX: u32 = BLOCK_MAX / EPOCH_SIZE;

/// Epoch nullifiers per derivation window.
pub const NF_DERIVATION_WIDTH: u32 = (1 << Polynomial::R) / (TachyonP5R64::ROUNDS as u32);
