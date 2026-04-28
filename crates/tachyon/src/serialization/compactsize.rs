//! Bitcoin-style varint (`compactSize`) codec used by Zcash for transaction
//! vector lengths and similar counts.
//!
//! Vendored locally from `zcash_encoding::CompactSize` to keep tachyon free
//! of any librustzcash dependency. The encoding is spec-defined and won't
//! drift; if `zcash_encoding` is ever pulled into this workspace as a path
//! dep we can switch back.

use core::{num::TryFromIntError, ops::RangeInclusive};

use core2::io::{self, Read, Write};

pub(crate) enum CompactSizeError {
    /// The value should be in a different encoding form.
    NonCanonical(CompactSize),
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

    pub(crate) fn enforce_valid(self) -> Result<Self, CompactSizeError> {
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

    /// Read a [`CompactSize`] from `reader`, validating canonical form and
    /// enforcing the consensus bound [`MAX_COMPACT_SIZE`].
    ///
    /// Non-canonical encodings (over-long forms) are rejected per Zcash
    /// protocol spec §7.1 (page 132).
    pub(crate) fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut flag = [0u8; 1];
        reader.read_exact(&mut flag)?;

        let csize = match flag[0] {
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
        }
        .enforce_valid();

        csize.map_err(|_err| io::Error::new(io::ErrorKind::InvalidData, "invalid compact size"))
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
