//! Protocol-wide non-hash constants.

/// Maximum representable value in zatoshis (§5.3 of the protocol spec).
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;

/// Maximum block height (the protocol spec uses u32).
pub const BLOCK_MAX: u32 = u32::MAX;

/// Number of blocks per epoch. Must be a power of two (block-height
/// arithmetic derives its shift and mask from this value).
///
/// `2^14` blocks (about two weeks at the 75-second target spacing) leaves an
/// 18-bit epoch space, which the 64-ary nullifier GGM tree tiles exactly in
/// three levels of 6-bit chunks.
pub const EPOCH_SIZE: u32 = 0x4000;
const _: () = assert!(
    EPOCH_SIZE.is_power_of_two(),
    "epoch size must be a power of two"
);

/// Maximum epoch index: every block height maps to an epoch.
#[expect(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "const division"
)]
pub const EPOCH_MAX: u32 = BLOCK_MAX / EPOCH_SIZE;

/// Ragu's `ProductionRank`, `R<13>`.
///
/// Fixes the polynomial commitment domain at `2^13` coefficients. The mock
/// `ragu` crate does not re-export `Rank`/`ProductionRank`, so this literal
/// mirrors ragu's `R<13>`; source it from ragu directly should that ever be
/// exported. This is the only rank handled directly; everything downstream
/// is a size.
pub const RAGU_RANK: u32 = 13;

/// A committed polynomial holds at most `2^RAGU_RANK` coefficients.
///
/// Higher-degree polynomials must be handled as capacity-wide splits recombined
/// by Horner in `z^POLY_LEN_MAX`.
pub const POLY_LEN_MAX: usize = 1 << RAGU_RANK;

/// The number of `mk` parts, one derived per `NfMasterSeed` step.
///
/// Splitting the master key across `MK_PARTS` seeds keeps each seed's Poseidon
/// squeeze under the per-step gate ceiling (a single `MK_LENGTH` squeeze busts
/// it). The parts concatenate into the full `mk`.
pub const MK_PARTS: usize = 2;

/// The number of round keys per `mk` part.
pub const MK_PART_LEN: usize = 16;

/// The master-key round-key schedule width.
///
/// The round keys the root expansion's `TachyonP5R128` cipher cycles (four
/// times over its 128 rounds). Outputs are whitened by the dedicated `w`,
/// never by a wrapped round key.
pub const MK_LENGTH: usize = MK_PARTS * MK_PART_LEN;

/// The key-schedule prefix length absorbed by the parameter sponges.
///
/// The domain tag plus this prefix absorbs exactly `RATE = 4` elements and
/// squeezes three, so each expansion- or leaf-parameter derivation is one
/// Poseidon permutation. The expansion steps run it in-step; a second
/// permutation does not fit their gate budget.
pub const NF_EXPANSION_KEY_PREFIX: usize = 3;
