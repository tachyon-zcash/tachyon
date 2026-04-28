//! Bitcoin-style varint (`compactSize`) codec used by Zcash for transaction
//! vector lengths and similar counts.
//!
//! Vendored locally from `zcash_encoding::CompactSize` to keep tachyon free
//! of any librustzcash dependency. The encoding is spec-defined and won't
//! drift; if `zcash_encoding` is ever pulled into this workspace as a path
//! dep we can switch back.

use core::{num::TryFromIntError, ops::RangeInclusive};

use core2::io::{self, Read, Write};

#[derive(Debug)]
pub(crate) enum CompactSizeError {
    /// The value should be in a different encoding form.
    NonCanonical(CompactSize),
    /// The value exceeds the zcash consensus bound.
    ExceedsMaximum(CompactSize),
}

/// The maximum allowed value representable as a [`CompactSize`].
///
/// Inherited from Bitcoin's `MAX_SIZE` defensive read bound, which Zcash
/// adopts via its `compactSize` encoding (Zcash protocol spec §7.1). The
/// Zcash spec does not state this bound explicitly; specific consensus
/// rules (§7.1.2) impose tighter caps on individual fields (e.g.
/// `nSpendsSapling < 2^16`).
pub(crate) const MAX_COMPACT_SIZE: u32 = 0x0200_0000;

/// Largest value canonically encoded in the single-byte form.
const MAX_ONE_BYTE: u8 = 0xFC;

/// Flag byte preceding a 2-byte little-endian `u16` payload.
const FLAG_TWO_BYTES: u8 = MAX_ONE_BYTE + 1;
/// Flag byte preceding a 4-byte little-endian `u32` payload.
const FLAG_FOUR_BYTES: u8 = FLAG_TWO_BYTES + 1;
/// Flag byte preceding an 8-byte little-endian `u64` payload.
const FLAG_EIGHT_BYTES: u8 = FLAG_FOUR_BYTES + 1;

#[expect(clippy::as_conversions, reason = "widening")]
const VALID_ONE_BYTE: RangeInclusive<u64> = 0..=(MAX_ONE_BYTE as u64);
#[expect(clippy::as_conversions, reason = "widening")]
const VALID_TWO_BYTES: RangeInclusive<u64> = (MAX_ONE_BYTE as u64) + 1..=(u16::MAX as u64);
#[expect(clippy::as_conversions, reason = "widening")]
const VALID_FOUR_BYTES: RangeInclusive<u64> = (u16::MAX as u64) + 1..=(u32::MAX as u64);
#[expect(clippy::as_conversions, reason = "widening")]
const VALID_EIGHT_BYTES: RangeInclusive<u64> = (u32::MAX as u64) + 1..=u64::MAX;

/// A canonical CompactSize value, tagged by its encoding form.
///
/// Compact encoding of integers (Bitcoin-style varint), faithful to the
/// full `0..=u64::MAX` range. Used by Zcash for transaction-level vector
/// lengths and similar counts; see Zcash protocol spec §7.1 (Transaction
/// Encoding and Consensus, page 122) for the fields that use this type.
///
/// Constructors pick the smallest canonical variant for the value, and
/// [`Self::read`] rejects non-canonical encodings (over-long forms) per
/// Zcash protocol spec §7.1 (page 132): "Like other serialized fields of
/// type compactSize, ... MUST be encoded with the minimum number of bytes
/// ..., and other encodings MUST be rejected."
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompactSize {
    /// Single-byte form (no flag prefix), `0..=MAX_ONE_BYTE`.
    OneByte(u8),
    /// Flag-`FLAG_TWO_BYTES` form, `(MAX_ONE_BYTE + 1)..=u16::MAX`.
    TwoBytes(u16),
    /// Flag-`FLAG_FOUR_BYTES` form, `(u16::MAX + 1)..=u32::MAX`.
    FourBytes(u32),
    /// Flag-`FLAG_EIGHT_BYTES` form, `(u32::MAX + 1)..=u64::MAX`.
    ///
    /// Every value within [`MAX_COMPACT_SIZE`] fits in `u32`, so this variant
    /// should be unreachable in any consensus-validating Zcash context.
    EightBytes(u64),
}

impl CompactSize {
    pub(crate) fn one_byte(value: u8) -> Result<Self, CompactSizeError> {
        if !VALID_ONE_BYTE.contains(&value.into()) {
            return Err(CompactSizeError::NonCanonical(Self::from(value)));
        }
        Ok(Self::from(value))
    }

    pub(crate) fn two_bytes(value: u16) -> Result<Self, CompactSizeError> {
        if !VALID_TWO_BYTES.contains(&value.into()) {
            return Err(CompactSizeError::NonCanonical(Self::from(value)));
        }
        Ok(Self::from(value))
    }

    pub(crate) fn four_bytes(value: u32) -> Result<Self, CompactSizeError> {
        if !VALID_FOUR_BYTES.contains(&value.into()) {
            return Err(CompactSizeError::NonCanonical(Self::from(value)));
        }
        Ok(Self::from(value))
    }

    pub(crate) fn eight_bytes(value: u64) -> Result<Self, CompactSizeError> {
        if !VALID_EIGHT_BYTES.contains(&value) {
            return Err(CompactSizeError::NonCanonical(Self::from(value)));
        }
        Ok(Self::from(value))
    }

    pub(crate) fn enforce_canon(self) -> Result<Self, CompactSizeError> {
        match self {
            | Self::OneByte(inner_u8) => {
                if VALID_ONE_BYTE.contains(&inner_u8.into()) {
                    Ok(self)
                } else {
                    Err(CompactSizeError::NonCanonical(self))
                }
            },
            | Self::TwoBytes(inner_u16) => {
                if VALID_TWO_BYTES.contains(&inner_u16.into()) {
                    Ok(self)
                } else {
                    Err(CompactSizeError::NonCanonical(self))
                }
            },
            | Self::FourBytes(inner_u32) => {
                if VALID_FOUR_BYTES.contains(&inner_u32.into()) {
                    Ok(self)
                } else {
                    Err(CompactSizeError::NonCanonical(self))
                }
            },
            | Self::EightBytes(inner_u64) => {
                if VALID_EIGHT_BYTES.contains(&inner_u64) {
                    Ok(self)
                } else {
                    Err(CompactSizeError::NonCanonical(self))
                }
            },
        }
    }

    /// Reject values above the consensus bound [`MAX_COMPACT_SIZE`].
    pub(crate) fn enforce_max(self) -> Result<Self, CompactSizeError> {
        if u64::from(self) > u64::from(MAX_COMPACT_SIZE) {
            Err(CompactSizeError::ExceedsMaximum(self))
        } else {
            Ok(self)
        }
    }

    pub(crate) fn enforce_valid(self) -> Result<Self, CompactSizeError> {
        self.enforce_canon()?.enforce_max()
    }

    /// Parse a [`CompactSize`] from `reader`. Performs no canonical-form or
    /// consensus-bound checks — callers are responsible for invoking
    /// [`Self::enforce_canon`], [`Self::enforce_max`], or [`Self::enforce_valid`]
    /// as appropriate.
    pub(crate) fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut flag = [0u8; 1];
        reader.read_exact(&mut flag)?;

        Ok(match flag[0] {
            | 0..=MAX_ONE_BYTE => Self::OneByte(flag[0]),
            | FLAG_TWO_BYTES => {
                let mut bytes = [0u8; 2];
                reader.read_exact(&mut bytes)?;
                Self::TwoBytes(u16::from_le_bytes(bytes))
            },
            | FLAG_FOUR_BYTES => {
                let mut bytes = [0u8; 4];
                reader.read_exact(&mut bytes)?;
                Self::FourBytes(u32::from_le_bytes(bytes))
            },
            | FLAG_EIGHT_BYTES => {
                let mut bytes = [0u8; 8];
                reader.read_exact(&mut bytes)?;
                Self::EightBytes(u64::from_le_bytes(bytes))
            },
        })
    }

    /// Write this [`CompactSize`] to `writer`.
    pub(crate) fn write<W: Write>(self, mut writer: W) -> io::Result<()> {
        match self {
            | Self::OneByte(value) => writer.write_all(&[value]),
            | Self::TwoBytes(value) => {
                writer.write_all(&[FLAG_TWO_BYTES])?;
                writer.write_all(&value.to_le_bytes())
            },
            | Self::FourBytes(value) => {
                writer.write_all(&[FLAG_FOUR_BYTES])?;
                writer.write_all(&value.to_le_bytes())
            },
            | Self::EightBytes(value) => {
                writer.write_all(&[FLAG_EIGHT_BYTES])?;
                writer.write_all(&value.to_le_bytes())
            },
        }
    }
}

impl From<u8> for CompactSize {
    fn from(value: u8) -> Self {
        Self::from(u64::from(value))
    }
}

impl From<u16> for CompactSize {
    fn from(value: u16) -> Self {
        Self::from(u64::from(value))
    }
}

impl From<u32> for CompactSize {
    fn from(value: u32) -> Self {
        Self::from(u64::from(value))
    }
}

impl From<u64> for CompactSize {
    #[expect(clippy::expect_used, reason = "checked conversions")]
    #[expect(clippy::unreachable, reason = "exhaustive conditions")]
    fn from(value: u64) -> Self {
        if VALID_ONE_BYTE.contains(&value) {
            Self::OneByte(u8::try_from(value).expect("checked"))
        } else if VALID_TWO_BYTES.contains(&value) {
            Self::TwoBytes(u16::try_from(value).expect("checked"))
        } else if VALID_FOUR_BYTES.contains(&value) {
            Self::FourBytes(u32::try_from(value).expect("checked"))
        } else if VALID_EIGHT_BYTES.contains(&value) {
            Self::EightBytes(value)
        } else {
            unreachable!("impossible u64 value {}", value)
        }
    }
}

impl From<CompactSize> for u64 {
    fn from(csize: CompactSize) -> Self {
        match csize {
            | CompactSize::OneByte(inner_u8) => Self::from(inner_u8),
            | CompactSize::TwoBytes(inner_u16) => Self::from(inner_u16),
            | CompactSize::FourBytes(inner_u32) => Self::from(inner_u32),
            | CompactSize::EightBytes(inner_u64) => inner_u64,
        }
    }
}

impl TryFrom<usize> for CompactSize {
    type Error = TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        u64::try_from(value).map(Self::from)
    }
}

impl TryFrom<CompactSize> for usize {
    type Error = TryFromIntError;

    fn try_from(csize: CompactSize) -> Result<Self, Self::Error> {
        match csize {
            | CompactSize::OneByte(inner_u8) => Ok(Self::from(inner_u8)),
            | CompactSize::TwoBytes(inner_u16) => Ok(Self::from(inner_u16)),
            | CompactSize::FourBytes(inner_u32) => Self::try_from(inner_u32),
            | CompactSize::EightBytes(inner_u64) => Self::try_from(inner_u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    fn sized_value(value: &[u8]) -> Vec<u8> {
        let flag = match value.len() {
            | 2 => [FLAG_TWO_BYTES].as_slice(),
            | 4 => [FLAG_FOUR_BYTES].as_slice(),
            | 8 => [FLAG_EIGHT_BYTES].as_slice(),
            | _ => [].as_slice(),
        };
        [flag, value].concat()
    }

    /// Each form boundary: confirm `From<u64>` picks the right variant, the
    /// encoding matches the spec, and `read` round-trips back to the same variant.
    #[test]
    fn form_boundary_round_trips() {
        let cases = alloc::vec![
            (0, CompactSize::OneByte(0), [0x00].to_vec()),
            (
                u64::from(MAX_ONE_BYTE),
                CompactSize::OneByte(MAX_ONE_BYTE),
                [MAX_ONE_BYTE].to_vec()
            ),
            // 253 is both `FLAG_TWO_BYTES` and the smallest value that requires the TwoBytes form.
            (
                u64::from(FLAG_TWO_BYTES),
                CompactSize::TwoBytes(u16::from(FLAG_TWO_BYTES)),
                sized_value(&u16::from(FLAG_TWO_BYTES).to_le_bytes()),
            ),
            (
                u64::from(u16::MAX),
                CompactSize::TwoBytes(u16::MAX),
                sized_value(&u16::MAX.to_le_bytes()),
            ),
            (
                u64::from(u16::MAX) + 1,
                CompactSize::FourBytes(u32::from(u16::MAX) + 1),
                sized_value(&(u32::from(u16::MAX) + 1).to_le_bytes()),
            ),
            (
                u64::from(MAX_COMPACT_SIZE),
                CompactSize::FourBytes(MAX_COMPACT_SIZE),
                sized_value(&MAX_COMPACT_SIZE.to_le_bytes()),
            ),
        ];

        let mut buf = Vec::new();
        for (value, expected_variant, expected_bytes) in cases {
            let cs = CompactSize::from(value);
            assert_eq!(cs, expected_variant);
            cs.write(&mut buf).unwrap();
            assert_eq!(buf, expected_bytes);
            assert_eq!(CompactSize::read(buf.as_slice()).unwrap(), expected_variant);
            buf.clear();
        }
    }

    /// Form-checked constructors reject one-past the canonical edge in either direction.
    #[test]
    fn constructors_enforce_canonical_form() {
        CompactSize::one_byte(0).unwrap();
        CompactSize::one_byte(MAX_ONE_BYTE).unwrap();
        CompactSize::one_byte(FLAG_TWO_BYTES).unwrap_err();

        CompactSize::two_bytes(u16::from(MAX_ONE_BYTE)).unwrap_err();
        CompactSize::two_bytes(u16::from(FLAG_TWO_BYTES)).unwrap();
        CompactSize::two_bytes(u16::MAX).unwrap();

        CompactSize::four_bytes(u32::from(u16::MAX)).unwrap_err();
        CompactSize::four_bytes(u32::from(u16::MAX) + 1).unwrap();
        CompactSize::four_bytes(u32::MAX).unwrap();

        CompactSize::eight_bytes(u64::from(u32::MAX)).unwrap_err();
        CompactSize::eight_bytes(u64::from(u32::MAX) + 1).unwrap();
    }

    /// `enforce_max` rejects values above the consensus bound `MAX_COMPACT_SIZE`.
    #[test]
    fn enforce_max_rejects_above_consensus() {
        CompactSize::FourBytes(MAX_COMPACT_SIZE + 1).enforce_max().unwrap_err();
        CompactSize::FourBytes(u32::MAX).enforce_max().unwrap_err();
        CompactSize::EightBytes(u64::from(u32::MAX) + 1).enforce_max().unwrap_err();
        CompactSize::FourBytes(MAX_COMPACT_SIZE).enforce_max().unwrap();
    }

    /// `enforce_canon` rejects values stored in an over-long form per Zcash spec §7.1 p.132.
    #[test]
    fn enforce_canon_rejects_non_canonical() {
        CompactSize::TwoBytes(u16::from(MAX_ONE_BYTE)).enforce_canon().unwrap_err();
        CompactSize::FourBytes(u32::from(u16::MAX)).enforce_canon().unwrap_err();
        CompactSize::EightBytes(u64::from(u32::MAX)).enforce_canon().unwrap_err();
    }

    /// Truncated inputs: flag byte present but payload missing or short.
    #[test]
    fn read_rejects_truncated_input() {
        CompactSize::read([].as_slice()).unwrap_err();
        CompactSize::read([FLAG_TWO_BYTES].as_slice()).unwrap_err();
        CompactSize::read([FLAG_TWO_BYTES, 0x00].as_slice()).unwrap_err();
        CompactSize::read([FLAG_FOUR_BYTES, 0x00, 0x00, 0x00].as_slice()).unwrap_err();
        CompactSize::read([FLAG_EIGHT_BYTES, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00].as_slice())
            .unwrap_err();
    }

    /// Trailing bytes after a complete encoding are not consumed and not an error.
    #[test]
    fn read_ignores_trailing_bytes() {
        let one_byte_with_trailing = [0x00, 0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            CompactSize::read(one_byte_with_trailing.as_slice()).unwrap(),
            CompactSize::OneByte(0),
        );
        let two_byte_with_trailing = [
            sized_value(&u16::from(FLAG_TWO_BYTES).to_le_bytes()).as_slice(),
            [0xDE, 0xAD].as_slice(),
        ]
        .concat();
        assert_eq!(
            CompactSize::read(two_byte_with_trailing.as_slice()).unwrap(),
            CompactSize::TwoBytes(u16::from(FLAG_TWO_BYTES)),
        );
    }

    #[test]
    fn try_from_usize_round_trip() {
        for n in [
            0usize,
            usize::from(MAX_ONE_BYTE),
            usize::from(FLAG_TWO_BYTES),
            usize::from(u16::MAX) + 1,
        ] {
            let cs = CompactSize::try_from(n).unwrap();
            assert_eq!(usize::try_from(cs).unwrap(), n);
        }
    }
}
