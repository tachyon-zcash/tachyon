//! Bitcoin-style varint (`compactSize`) codec used by Zcash for transaction
//! vector lengths and similar counts.
//!
//! Vendored locally from `zcash_encoding::CompactSize` to keep tachyon free
//! of any librustzcash dependency. The encoding is spec-defined and won't
//! drift; if `zcash_encoding` is ever pulled into this workspace as a path
//! dep we can switch back.

use core::{num::TryFromIntError, ops::RangeInclusive};

use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, PartialEq};

/// Canonicity errors for [`CompactSize`].
#[derive(Debug, Display, Error)]
pub enum CompactSizeError {
    /// The value should be in a different encoding form.
    #[display("value is not canonical: {}", _0)]
    NonCanonical(#[error(not(source))] CompactSize),
    /// The value exceeds the zcash consensus bound.
    #[display("value exceeds consensus bound: {}", _0)]
    ExceedsMaximum(#[error(not(source))] CompactSize),
}

/// The maximum allowed value representable as a [`CompactSize`].
///
/// Inherited from Bitcoin's `MAX_SIZE` defensive read bound, which Zcash
/// adopts via its `compactSize` encoding (Zcash protocol spec §7.1). The
/// Zcash spec does not state this bound explicitly; specific consensus
/// rules (§7.1.2) impose tighter caps on individual fields (e.g.
/// `nSpendsSapling < 2^16`).
const MAX_COMPACT_SIZE: u32 = 0x0200_0000;

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
#[derive(Clone, Copy, Debug, Display, PartialEq, TotalEq)]
pub enum CompactSize {
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
    /// Construct a canonical single-byte [`CompactSize`] value.
    ///
    /// # Errors
    ///
    /// Returns [`CompactSizeError::NonCanonical`] if the value belongs in a
    /// shorter or longer form.
    pub fn one_byte(value: u8) -> Result<Self, CompactSizeError> {
        if !VALID_ONE_BYTE.contains(&value.into()) {
            return Err(CompactSizeError::NonCanonical(Self::from(value)));
        }
        Ok(Self::from(value))
    }

    /// Construct a canonical two-byte [`CompactSize`] value.
    ///
    /// # Errors
    ///
    /// Returns [`CompactSizeError::NonCanonical`] if the value belongs in a
    /// shorter or longer form.
    pub fn two_bytes(value: u16) -> Result<Self, CompactSizeError> {
        if !VALID_TWO_BYTES.contains(&value.into()) {
            return Err(CompactSizeError::NonCanonical(Self::from(value)));
        }
        Ok(Self::from(value))
    }

    /// Construct a canonical four-byte [`CompactSize`] value.
    ///
    /// # Errors
    ///
    /// Returns [`CompactSizeError::NonCanonical`] if the value belongs in a
    /// shorter or longer form.
    pub fn four_bytes(value: u32) -> Result<Self, CompactSizeError> {
        if !VALID_FOUR_BYTES.contains(&value.into()) {
            return Err(CompactSizeError::NonCanonical(Self::from(value)));
        }
        Ok(Self::from(value))
    }

    /// Construct a canonical eight-byte [`CompactSize`] value.
    ///
    /// # Errors
    ///
    /// Returns [`CompactSizeError::NonCanonical`] if the value belongs in a
    /// shorter form.
    pub fn eight_bytes(value: u64) -> Result<Self, CompactSizeError> {
        if !VALID_EIGHT_BYTES.contains(&value) {
            return Err(CompactSizeError::NonCanonical(Self::from(value)));
        }
        Ok(Self::from(value))
    }

    /// Enforce canonical form.
    ///
    /// # Errors
    ///
    /// Returns [`CompactSizeError::NonCanonical`] if the value is not encoded
    /// in the shortest form that holds it.
    pub fn enforce_canon(self) -> Result<Self, CompactSizeError> {
        match self {
            Self::OneByte(inner_u8) => {
                if VALID_ONE_BYTE.contains(&inner_u8.into()) {
                    Ok(self)
                } else {
                    Err(CompactSizeError::NonCanonical(self))
                }
            },
            Self::TwoBytes(inner_u16) => {
                if VALID_TWO_BYTES.contains(&inner_u16.into()) {
                    Ok(self)
                } else {
                    Err(CompactSizeError::NonCanonical(self))
                }
            },
            Self::FourBytes(inner_u32) => {
                if VALID_FOUR_BYTES.contains(&inner_u32.into()) {
                    Ok(self)
                } else {
                    Err(CompactSizeError::NonCanonical(self))
                }
            },
            Self::EightBytes(inner_u64) => {
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

    /// Enforce canonical form and consensus bound.
    ///
    /// # Errors
    ///
    /// Returns [`CompactSizeError::NonCanonical`] if the form is not the
    /// shortest that holds the value, or [`CompactSizeError::ExceedsMaximum`]
    /// if it is above [`MAX_COMPACT_SIZE`].
    pub fn enforce_valid(self) -> Result<Self, CompactSizeError> {
        self.enforce_canon()?.enforce_max()
    }

    /// Parse a [`CompactSize`] from `reader`. Performs no canonical-form or
    /// consensus-bound checks; callers are responsible for invoking
    /// [`Self::enforce_canon`], [`Self::enforce_max`], or
    /// [`Self::enforce_valid`] as appropriate.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails, including a flag byte whose
    /// payload is short.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut flag = [0u8; 1];
        reader.read_exact(&mut flag)?;

        Ok(match flag[0] {
            0..=MAX_ONE_BYTE => Self::OneByte(flag[0]),
            FLAG_TWO_BYTES => {
                let mut bytes = [0u8; 2];
                reader.read_exact(&mut bytes)?;
                Self::TwoBytes(u16::from_le_bytes(bytes))
            },
            FLAG_FOUR_BYTES => {
                let mut bytes = [0u8; 4];
                reader.read_exact(&mut bytes)?;
                Self::FourBytes(u32::from_le_bytes(bytes))
            },
            FLAG_EIGHT_BYTES => {
                let mut bytes = [0u8; 8];
                reader.read_exact(&mut bytes)?;
                Self::EightBytes(u64::from_le_bytes(bytes))
            },
        })
    }

    /// Write this [`CompactSize`] to `writer`.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(self, mut writer: W) -> io::Result<()> {
        match self {
            Self::OneByte(value) => writer.write_all(&[value]),
            Self::TwoBytes(value) => {
                writer.write_all(&[FLAG_TWO_BYTES])?;
                writer.write_all(&value.to_le_bytes())
            },
            Self::FourBytes(value) => {
                writer.write_all(&[FLAG_FOUR_BYTES])?;
                writer.write_all(&value.to_le_bytes())
            },
            Self::EightBytes(value) => {
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
    fn from(value: u64) -> Self {
        #[expect(clippy::expect_used, reason = "checked conversions")]
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
            CompactSize::OneByte(inner_u8) => Self::from(inner_u8),
            CompactSize::TwoBytes(inner_u16) => Self::from(inner_u16),
            CompactSize::FourBytes(inner_u32) => Self::from(inner_u32),
            CompactSize::EightBytes(inner_u64) => inner_u64,
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
            CompactSize::OneByte(inner_u8) => Ok(Self::from(inner_u8)),
            CompactSize::TwoBytes(inner_u16) => Ok(Self::from(inner_u16)),
            CompactSize::FourBytes(inner_u32) => Self::try_from(inner_u32),
            CompactSize::EightBytes(inner_u64) => Self::try_from(inner_u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use proptest::{
        collection::vec,
        prelude::*,
        sample::{Index, select},
    };

    use super::*;
    use crate::testing::check;

    /// A value from any of the four forms, weighted towards each form's
    /// edges and the consensus bound.
    fn any_size() -> impl Strategy<Value = u64> {
        prop_oneof![
            VALID_ONE_BYTE,
            VALID_TWO_BYTES,
            VALID_FOUR_BYTES,
            VALID_EIGHT_BYTES,
            select(
                [
                    *VALID_ONE_BYTE.start(),
                    *VALID_ONE_BYTE.end(),
                    *VALID_TWO_BYTES.start(),
                    *VALID_TWO_BYTES.end(),
                    *VALID_FOUR_BYTES.start(),
                    *VALID_FOUR_BYTES.end(),
                    *VALID_EIGHT_BYTES.start(),
                    *VALID_EIGHT_BYTES.end(),
                    u64::from(MAX_COMPACT_SIZE),
                    u64::from(MAX_COMPACT_SIZE) + 1,
                ]
                .to_vec()
            ),
        ]
    }

    fn encoding(size: CompactSize) -> Vec<u8> {
        let mut buf = Vec::new();
        size.write(&mut buf).unwrap();
        buf
    }

    /// `From<u64>` picks the shortest form, written as its flag and a
    /// little-endian payload, `read` returns the same form, and the value
    /// passes `enforce_valid` iff it is within the consensus bound.
    #[test]
    fn a_value_takes_its_shortest_form() {
        check(256, any_size(), |value| {
            let size = CompactSize::from(value);
            let buf = encoding(size);
            let expected = if VALID_ONE_BYTE.contains(&value) {
                [u8::try_from(value).unwrap()].to_vec()
            } else if VALID_TWO_BYTES.contains(&value) {
                let payload = u16::try_from(value).unwrap().to_le_bytes();
                [[FLAG_TWO_BYTES].as_slice(), &payload].concat()
            } else if VALID_FOUR_BYTES.contains(&value) {
                let payload = u32::try_from(value).unwrap().to_le_bytes();
                [[FLAG_FOUR_BYTES].as_slice(), &payload].concat()
            } else {
                [[FLAG_EIGHT_BYTES].as_slice(), &value.to_le_bytes()].concat()
            };
            prop_assert_eq!(&buf, &expected);
            prop_assert_eq!(u64::from(size), value);
            prop_assert_eq!(CompactSize::read(buf.as_slice()).unwrap(), size);
            prop_assert!(size.enforce_canon().is_ok());
            prop_assert_eq!(
                size.enforce_valid().is_ok(),
                value <= u64::from(MAX_COMPACT_SIZE)
            );
            Ok(())
        });
    }

    /// The form-checked constructors, and `enforce_canon` on a form read off
    /// the wire, accept exactly the values the form is the shortest for.
    #[test]
    fn a_form_holds_exactly_its_range() {
        let strategy = (any::<u8>(), any::<u16>(), any::<u32>(), any::<u64>());
        check(256, strategy, |(one, two, four, eight)| {
            let in_one = VALID_ONE_BYTE.contains(&u64::from(one));
            let in_two = VALID_TWO_BYTES.contains(&u64::from(two));
            let in_four = VALID_FOUR_BYTES.contains(&u64::from(four));
            let in_eight = VALID_EIGHT_BYTES.contains(&eight);
            for (constructed, canonical) in [
                (CompactSize::one_byte(one).ok(), in_one),
                (CompactSize::two_bytes(two).ok(), in_two),
                (CompactSize::four_bytes(four).ok(), in_four),
                (CompactSize::eight_bytes(eight).ok(), in_eight),
            ] {
                prop_assert_eq!(constructed.is_some(), canonical);
            }
            for (size, canonical) in [
                (CompactSize::OneByte(one), in_one),
                (CompactSize::TwoBytes(two), in_two),
                (CompactSize::FourBytes(four), in_four),
                (CompactSize::EightBytes(eight), in_eight),
            ] {
                prop_assert_eq!(size.enforce_canon().is_ok(), canonical);
                prop_assert_eq!(
                    size.enforce_max().is_ok(),
                    u64::from(size) <= u64::from(MAX_COMPACT_SIZE)
                );
            }
            Ok(())
        });
    }

    /// Every strict prefix of an encoding is a short read, and bytes after a
    /// whole encoding are left unread.
    #[test]
    fn read_takes_exactly_one_encoding() {
        let strategy = (any_size(), any::<Index>(), vec(any::<u8>(), 0..=8));
        check(256, strategy, |(value, cut, trailing)| {
            let buf = encoding(CompactSize::from(value));
            let mut reader = [buf.as_slice(), &trailing].concat();
            let mut rest = reader.as_slice();
            prop_assert_eq!(
                CompactSize::read(&mut rest).unwrap(),
                CompactSize::from(value)
            );
            prop_assert_eq!(rest, trailing.as_slice());

            reader.truncate(cut.index(buf.len()));
            prop_assert!(CompactSize::read(reader.as_slice()).is_err());
            Ok(())
        });
    }
}
