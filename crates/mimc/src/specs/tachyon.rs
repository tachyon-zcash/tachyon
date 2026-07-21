//! The Tachyon MiMC instantiations over the Pallas base field.

#![allow(missing_debug_implementations, reason = "zero-size markers")]
#![allow(clippy::module_name_repetitions, reason = "name is descriptive")]

use pasta_curves::Fp;

use crate::Spec;

/// The Tachyon MiMC instantiation over the Pallas base field with 64 rounds.
pub struct TachyonP5R64;

impl TachyonP5R64 {
    /// The round-constant values.
    pub const CONSTANTS: &'static [Fp; 64] =
        &read_pallas_bytes(include_bytes!("Tachyon-MiMC0064.bin"));
    /// The S-box exponent.
    pub const POW: u64 = 5;
    /// The number of rounds.
    pub const ROUNDS: u64 = 64;
}

impl Spec<64> for TachyonP5R64 {
    type Field = Fp;

    const CONSTANTS: &'static [Fp; 64] = Self::CONSTANTS;
    const POW: u64 = Self::POW;
    const ROUNDS: u64 = Self::ROUNDS;
}

/// Convert a raw byte array into a static array of field elements.
const fn read_pallas_bytes<const B: usize, const R: usize>(bytes: &'static [u8; B]) -> [Fp; R] {
    use ff::Field as _;
    use ff::PrimeField;

    assert!(B.is_multiple_of(R), "valid input dimensions");

    let (reprs, _extra_input) = bytes.as_chunks::<{ size_of::<<Fp as PrimeField>::Repr>() }>();
    assert!(reprs.len() >= R, "enough input material");

    let mut elements = [Fp::ZERO; R];
    let mut index = 0;
    while index < R {
        let (limbs, extra_parts) = reprs[index].as_chunks::<8>();
        assert!(extra_parts.is_empty(), "constant size");
        assert!(limbs.len() == 4, "constant size");

        elements[index] = Fp::from_raw([
            u64::from_le_bytes(limbs[0]),
            u64::from_le_bytes(limbs[1]),
            u64::from_le_bytes(limbs[2]),
            u64::from_le_bytes(limbs[3]),
        ]);

        index += 1;
    }

    elements
}
