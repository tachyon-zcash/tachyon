//! Internal serialization helpers for read/write encoding.
//!
//! Provides shared read/write functions for the three field types used
//! throughout Tachyon: Pallas base field (`Fp`), Pallas scalar field
//! (`Fq`), and Pallas affine curve points (`EpAffine`).

#![allow(dead_code, reason = "may not be used")]

use alloc::vec::Vec;

use core2::io::{self, Read, Write};
use ff::PrimeField as _;
use pasta_curves::{EpAffine, Fp, Fq, group::GroupEncoding as _};

use crate::reddsa;

/// The maximum allowed value representable as a [`CompactSize`].
pub(crate) const MAX_COMPACT_SIZE: u32 = 0x0200_0000;

/// Flag byte preceding a 2-byte little-endian `u16` payload.
const FLAG_U16: u8 = 253;
/// Flag byte preceding a 4-byte little-endian `u32` payload.
const FLAG_U32: u8 = 254;
/// Flag byte preceding an 8-byte little-endian `u64` payload.
const FLAG_U64: u8 = 255;

/// Largest value encodable in the single-byte form (no flag prefix); `FLAG_U16 - 1`.
const MAX_SINGLE_BYTE: u64 = 0xFC;
/// Largest value encodable in the 2-byte `u16` form; `u16::MAX`.
const MAX_U16_PAYLOAD: u64 = 0xFFFF;
/// Largest value encodable in the 4-byte `u32` form; `u32::MAX`.
const MAX_U32_PAYLOAD: u64 = 0xFFFF_FFFF;

/// Namespace for functions for compact encoding of integers (Bitcoin-style
/// varint), with the Zcash consensus restriction `0..=0x02000000`.
///
/// Vendored locally from `zcash_encoding::CompactSize` to keep tachyon free
/// of any librustzcash dependency. The encoding is spec-defined and won't
/// drift; if `zcash_encoding` ever lands in this workspace we can switch back.
pub(crate) struct CompactSize;

impl CompactSize {
    /// Reads an integer encoded in compact form.
    pub(crate) fn read<R: Read>(mut reader: R) -> io::Result<u64> {
        let mut flag_bytes = [0; 1];
        reader.read_exact(&mut flag_bytes)?;
        let flag = flag_bytes[0];

        let result = if flag < FLAG_U16 {
            Ok(u64::from(flag))
        } else if flag == FLAG_U16 {
            let mut bytes = [0; 2];
            reader.read_exact(&mut bytes)?;
            match u64::from(u16::from_le_bytes(bytes)) {
                | n if n <= MAX_SINGLE_BYTE => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "non-canonical CompactSize",
                )),
                | n => Ok(n),
            }
        } else if flag == FLAG_U32 {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes)?;
            match u64::from(u32::from_le_bytes(bytes)) {
                | n if n <= MAX_U16_PAYLOAD => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "non-canonical CompactSize",
                )),
                | n => Ok(n),
            }
        } else {
            let mut bytes = [0; 8];
            reader.read_exact(&mut bytes)?;
            match u64::from_le_bytes(bytes) {
                | n if n <= MAX_U32_PAYLOAD => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "non-canonical CompactSize",
                )),
                | n => Ok(n),
            }
        }?;

        match result {
            | value if value > u64::from(MAX_COMPACT_SIZE) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CompactSize too large",
            )),
            | value => Ok(value),
        }
    }

    /// Reads an integer encoded in compact form and performs checked
    /// conversion to the target type.
    pub(crate) fn read_t<R: Read, T: TryFrom<u64>>(mut reader: R) -> io::Result<T> {
        let n = Self::read(&mut reader)?;
        T::try_from(n).map_err(|_err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "CompactSize value exceeds range of target type.",
            )
        })
    }

    /// Writes the provided `usize` value to the provided writer in compact form.
    pub(crate) fn write<W: Write>(mut writer: W, size: usize) -> io::Result<()> {
        u64::try_from(size)
            .and_then(|wide| match wide {
                | small if small <= MAX_SINGLE_BYTE => {
                    u8::try_from(small).map(|byte| writer.write_all(&[byte]))
                }
                | short if short <= MAX_U16_PAYLOAD => u16::try_from(short).map(|value| {
                    writer.write_all(&[FLAG_U16])?;
                    writer.write_all(&value.to_le_bytes())
                }),
                | word if word <= MAX_U32_PAYLOAD => u32::try_from(word).map(|value| {
                    writer.write_all(&[FLAG_U32])?;
                    writer.write_all(&value.to_le_bytes())
                }),
                | long => Ok(writer
                    .write_all(&[FLAG_U64])
                    .and_then(|()| writer.write_all(&long.to_le_bytes()))),
            })
            .map_err(|_err| io::Error::other("CompactSize encoding overflow"))?
    }
}

/// Read a Pallas base field element (`Fp`) from 32 bytes.
pub(crate) fn read_fp<R: Read>(mut reader: R) -> io::Result<Fp> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(Fp::from_repr(bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Fp encoding"))
}

pub(crate) fn read_fp_list<R: Read>(mut reader: R) -> io::Result<Vec<Fp>> {
    let n = CompactSize::read_t::<_, usize>(&mut reader)?;
    let mut fp_list = Vec::with_capacity(n);
    for _ in 0..n {
        let fp = read_fp(&mut reader)?;
        fp_list.push(fp);
    }
    Ok(fp_list)
}

pub(crate) fn write_fp_list<W: Write>(mut writer: W, fp_list: &[Fp]) -> io::Result<()> {
    CompactSize::write(&mut writer, fp_list.len())?;
    for fp in fp_list {
        write_fp(&mut writer, fp)?;
    }
    Ok(())
}

/// Write a Pallas base field element (`Fp`) as 32 bytes.
pub(crate) fn write_fp<W: Write>(mut writer: W, fp: &Fp) -> io::Result<()> {
    writer.write_all(&fp.to_repr())
}

/// Read a Pallas scalar field element (`Fq`) from 32 bytes.
pub(crate) fn read_fq<R: Read>(mut reader: R) -> io::Result<Fq> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(Fq::from_repr(bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Fq encoding"))
}

/// Write a Pallas scalar field element (`Fq`) as 32 bytes.
pub(crate) fn write_fq<W: Write>(mut writer: W, fq: &Fq) -> io::Result<()> {
    writer.write_all(&fq.to_repr())
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

/// Read a RedPallas action verification key from 32 bytes.
pub(crate) fn read_action_vk<R: Read>(
    mut reader: R,
) -> io::Result<reddsa::VerificationKey<reddsa::ActionAuth>> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    reddsa::VerificationKey::<reddsa::ActionAuth>::try_from(bytes).map_err(|_err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid action verification key",
        )
    })
}

/// Write a RedPallas action verification key as 32 bytes.
pub(crate) fn write_action_vk<W: Write>(
    mut writer: W,
    key: &reddsa::VerificationKey<reddsa::ActionAuth>,
) -> io::Result<()> {
    let bytes: [u8; 32] = (*key).into();
    writer.write_all(&bytes)
}

/// Read a RedPallas action signature from 64 bytes.
pub(crate) fn read_action_sig<R: Read>(
    mut reader: R,
) -> io::Result<reddsa::Signature<reddsa::ActionAuth>> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(reddsa::Signature::<reddsa::ActionAuth>::from(bytes))
}

/// Write a RedPallas action signature as 64 bytes.
pub(crate) fn write_action_sig<W: Write>(
    mut writer: W,
    sig: &reddsa::Signature<reddsa::ActionAuth>,
) -> io::Result<()> {
    let bytes: [u8; 64] = (*sig).into();
    writer.write_all(&bytes)
}

pub(crate) fn read_binding_sig<R: Read>(
    mut reader: R,
) -> io::Result<reddsa::Signature<reddsa::BindingAuth>> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(reddsa::Signature::<reddsa::BindingAuth>::from(bytes))
}

pub(crate) fn write_binding_sig<W: Write>(
    mut writer: W,
    sig: &reddsa::Signature<reddsa::BindingAuth>,
) -> io::Result<()> {
    let bytes: [u8; 64] = (*sig).into();
    writer.write_all(&bytes)
}
