//! Internal serialization helpers for read/write encoding.
//!
//! Provides shared read/write functions for the three field types used
//! throughout Tachyon: Pallas base field (`Fp`), Pallas scalar field
//! (`Fq`), and Pallas affine curve points (`EpAffine`).

use corez::io::{self, Read, Write};
use ff::PrimeField as _;
use pasta_curves::group::GroupEncoding as _;
use pasta_curves::{EpAffine, EqAffine, Fp};

use crate::serialization::compact_size::{CompactSize, CompactSizeError};

pub(crate) fn read_compactsize<R: Read>(mut reader: R) -> io::Result<u64> {
    let compact_size =
        CompactSize::read(&mut reader)?
            .enforce_valid()
            .map_err(|err| match err {
                CompactSizeError::NonCanonical(_) => {
                    io::Error::new(io::ErrorKind::InvalidData, "non-canonical compact size")
                },
                CompactSizeError::ExceedsMaximum(_) => io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compact size exceeds consensus maximum",
                ),
            })?;
    Ok(compact_size.into())
}

pub(crate) fn write_compactsize<W: Write>(mut writer: W, value: u64) -> io::Result<()> {
    let compact_size = CompactSize::from(value);
    compact_size.write(&mut writer)?;
    Ok(())
}

/// Read a Pallas base field element (`Fp`) from 32 bytes.
pub(crate) fn read_fp<R: Read>(mut reader: R) -> io::Result<Fp> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(Fp::from_repr(bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Fp encoding"))
}

/// Write a Pallas base field element (`Fp`) as 32 bytes.
pub(crate) fn write_fp<W: Write>(mut writer: W, fp: &Fp) -> io::Result<()> {
    writer.write_all(&fp.to_repr())
}

/// Read a Pallas affine curve point (`EpAffine`) from 32 compressed bytes.
pub(crate) fn read_ep_affine<R: Read>(mut reader: R) -> io::Result<EpAffine> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(EpAffine::from_bytes(&bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid curve point encoding"))
}

/// Write a Pallas affine curve point (`EpAffine`) as 32 compressed bytes.
pub(crate) fn write_ep_affine<W: Write>(mut writer: W, point: &EpAffine) -> io::Result<()> {
    writer.write_all(&point.to_bytes())
}

/// Read a Vesta affine curve point (`EqAffine`) from 32 compressed bytes.
pub(crate) fn read_eq_affine<R: Read>(mut reader: R) -> io::Result<EqAffine> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(EqAffine::from_bytes(&bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid curve point encoding"))
}

/// Write a Vesta affine curve point (`EqAffine`) as 32 compressed bytes.
pub(crate) fn write_eq_affine<W: Write>(mut writer: W, point: &EqAffine) -> io::Result<()> {
    writer.write_all(&point.to_bytes())
}
