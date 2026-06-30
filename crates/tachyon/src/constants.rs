//! Protocol-wide non-hash constants.

#![allow(
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "constant definitions"
)]

use zcash_mimc::TachyonP5R32;

/// Number of blocks per epoch.
pub const EPOCH_SIZE: u32 = 1 << 12;

/// Maximum note value in zatoshis (§5.3 of the protocol spec)
pub const NOTE_VALUE_MAX: u64 = 2_100_000_000_000_000;

/// Maximum epoch index.
#[expect(clippy::as_conversions, reason = "safe conversion")]
pub const EPOCH_MAX: u32 = u16::MAX as u32;

/// The number of derivation polynomials per note: the cross-poly width `N`.
///
/// Floor `3` (underdetermination needs `S < N·8192`); v1 is `4`, so the
/// `N·8192 = 32768` secret amplitudes always exceed the `≤ S = 16384` published
/// `(epoch, nf)` pairs a note can ever expose.
pub const NF_EMITTERS: usize = 4;

/// The ragu commitment-domain rank.
///
/// Ragu's `ProductionRank` is `R<13>`, fixing the polynomial commitment domain
/// at `2^13` coefficients. The mock `ragu` crate does not re-export
/// `Rank`/`ProductionRank`, so this literal mirrors ragu's `R<13>`; source it
/// from ragu directly should that ever be exported.
///
/// This is the only rank handled directly; everything downstream is a size.
pub const RAGU_RANK: u32 = 13;

/// A committed polynomial holds at most `2^RAGU_RANK` coefficients.
///
/// Higher-degree polynomials must be handled as capacity-wide splits recombined
/// by Horner in `z^POLY_LEN_MAX`.
pub const POLY_LEN_MAX: usize = 1 << RAGU_RANK;

/// The size of a note's nullifier query domain `c·⟨γ⟩`: the count of distinct
/// nullifiers a note may safely emit (one per domain point).
///
/// Beyond this limit, the nullifiers will repeat.
///
/// `NF_EMITTERS * POLY_LEN_MAX` is the information-theoretic cliff (the `N`
/// derivation polys hold `~N·POLY_LEN_MAX` field elements that may be sensitive
/// to recovery); this is half that, for margin. Requires `NF_EMITTERS` a power
/// of two so the result stays a power of two for the FFT domain.
pub const NF_DOMAIN: usize = {
    assert!(
        NF_EMITTERS.is_power_of_two(),
        "NF_EMITTERS must be a power of two so NF_DOMAIN is a valid FFT domain size"
    );
    (NF_EMITTERS * POLY_LEN_MAX) >> 1
};

/// One expansion part fits as many `TachyonP5R32::ROUNDS` rows into a
/// polynomial as possible.
pub const EK_PART_SIZE: usize = POLY_LEN_MAX / TachyonP5R32::ROUNDS;

/// The number of `ExpandedKey` parts which make up a full expanded key.
///
/// Width lever: with the expansion held at a credible depth (`TachyonP5R32`),
/// `P = EK_PARTS` parts interleave into one `EK_FULL_SIZE`-key orbit, so the
/// schedule width is `P · EK_PART_SIZE` independent of the round count.
pub const EK_PARTS: usize = 4;

/// The full cyclic round-key schedule width (one orbit).
///
/// The emitter's 8192-round cipher cycles this many distinct keys
/// (`POLY_LEN_MAX / EK_FULL_SIZE` cycles; 8x at the default width).
pub const EK_FULL_SIZE: usize = EK_PARTS * EK_PART_SIZE;

/// The number of `mk` parts, one derived per `MasterSeed` step.
///
/// Splitting the master key across `MK_PARTS` seeds keeps each seed's Poseidon
/// squeeze under the per-step gate ceiling (a single `MK_LENGTH` squeeze busts
/// it). The parts concatenate into the full `mk`.
pub const MK_PARTS: usize = 2;

/// The number of round keys per `mk` part.
pub const MK_PART_LEN: usize = 16;

/// The master-key round-key schedule width: the round keys cycled by the
/// `TachyonP5R32` expansion cipher (`round_key(0..=ROUNDS)`; the whitening key
/// at index `ROUNDS` wraps to key `0`).
pub const MK_LENGTH: usize = MK_PARTS * MK_PART_LEN;

/// The fixed `mk` prefix that seeds the nullifier-query parameter sponges
/// (`nf_query_salts`/`nf_query_weights`). Rooting the salts and weights in a
/// fixed-length prefix keeps those sponges flat in `MK_LENGTH` and lets the
/// single-input `NullifierDerivation` carry only the prefix on its header. A
/// Poseidon sponge seeded by a few `mk` elements already yields full-entropy
/// outputs; `mk` is sound by construction.
pub const NF_QUERY_MK_PREFIX: usize = 4;
