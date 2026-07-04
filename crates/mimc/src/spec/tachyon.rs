//! The Tachyon MiMC instantiations over the Pallas base field.

#![allow(missing_debug_implementations, reason = "zero-size markers")]
#![allow(clippy::module_name_repetitions, reason = "name is descriptive")]

use ff::Field as _;
use pasta_curves::Fp;

use crate::Spec;

/// The Tachyon MiMC instantiation over the Pallas base field with 32 rounds.
///
/// Round constants are domain-separated under BLAKE2b personalization
/// `Tachyon-MiMC0032`, independent of the 64- and 8192-round instances.
pub struct TachyonP5R32;

impl TachyonP5R32 {
    /// The round-constant values.
    pub const CONSTANTS: &'static [Fp; Self::ROUNDS] =
        &pallas_bytes(include_bytes!("Tachyon-MiMC0032.bin"));
    /// The S-box exponent.
    pub const POW: u64 = 5;
    /// The number of rounds.
    pub const ROUNDS: usize = 32;
}

impl Spec<Fp, 5, 32> for TachyonP5R32 {
    type Field = Fp;

    const CONSTANTS: &'static [Fp; Self::ROUNDS] = Self::CONSTANTS;
}

/// The Tachyon MiMC instantiation over the Pallas base field with 64 rounds.
///
/// Round constants are domain-separated under BLAKE2b personalization
/// `Tachyon-MiMC0064`, independent of the 32- and 8192-round instances.
pub struct TachyonP5R64;

impl TachyonP5R64 {
    /// The round-constant values.
    pub const CONSTANTS: &'static [Fp; Self::ROUNDS] =
        &pallas_bytes(include_bytes!("Tachyon-MiMC0064.bin"));
    /// The S-box exponent.
    pub const POW: u64 = 5;
    /// The number of rounds.
    pub const ROUNDS: usize = 64;
}

impl Spec<Fp, 5, 64> for TachyonP5R64 {
    type Field = Fp;

    const CONSTANTS: &'static [Fp; Self::ROUNDS] = Self::CONSTANTS;
}

/// The Tachyon MiMC instantiation over the Pallas base field with 128 rounds.
///
/// Round constants are domain-separated under BLAKE2b personalization
/// `Tachyon-MiMC0128`, independent of the 32-, 64- and 8192-round instances.
pub struct TachyonP5R128;

impl TachyonP5R128 {
    /// The round-constant values.
    pub const CONSTANTS: &'static [Fp; Self::ROUNDS] =
        &pallas_bytes(include_bytes!("Tachyon-MiMC0128.bin"));
    /// The S-box exponent.
    pub const POW: u64 = 5;
    /// The number of rounds.
    pub const ROUNDS: usize = 128;
}

impl Spec<Fp, 5, 128> for TachyonP5R128 {
    type Field = Fp;

    const CONSTANTS: &'static [Fp; Self::ROUNDS] = Self::CONSTANTS;
}

/// The Tachyon MiMC instantiation over the Pallas base field with 8192 rounds.
///
/// Round constants are domain-separated under BLAKE2b personalization
/// `Tachyon-MiMC8192`, independent of the 32- and 64-round instances, so the
/// emitter cipher shares no round keys with the expansion ciphers.
pub struct TachyonP5R8192;

impl TachyonP5R8192 {
    /// The round-constant values.
    pub const CONSTANTS: &'static [Fp; Self::ROUNDS] =
        &pallas_bytes(include_bytes!("Tachyon-MiMC8192.bin"));
    /// The S-box exponent.
    pub const POW: u64 = 5;
    /// The number of rounds.
    pub const ROUNDS: usize = 8192;
}

impl Spec<Fp, 5, 8192> for TachyonP5R8192 {
    type Field = Fp;

    const CONSTANTS: &'static [Fp; Self::ROUNDS] = Self::CONSTANTS;
}

/// Convert a raw byte array into a static array of field elements.
const fn pallas_bytes<const B: usize, const R: usize>(bytes: &'static [u8; B]) -> [Fp; R] {
    assert!(B.is_multiple_of(R), "valid input dimensions");

    let (reprs, _extra_input) = bytes.as_chunks::<{ size_of::<Fp>() }>();
    assert!(reprs.len() >= R, "enough input material");

    let mut elements = [Fp::ZERO; R];
    let mut index = 0;
    while index < R {
        let (parts, extra_parts) = reprs[index].as_chunks::<8>();
        assert!(parts.len() == 4, "constant size");
        assert!(extra_parts.is_empty(), "constant size");

        elements[index] = Fp::from_raw([
            u64::from_le_bytes(parts[0]),
            u64::from_le_bytes(parts[1]),
            u64::from_le_bytes(parts[2]),
            u64::from_le_bytes(parts[3]),
        ]);

        index += 1;
    }

    elements
}
