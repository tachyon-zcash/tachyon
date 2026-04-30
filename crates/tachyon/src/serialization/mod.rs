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

pub(crate) mod compactsize;

use crate::{reddsa, serialization::compactsize::CompactSize};

pub(crate) fn read_compactsize<R: Read>(mut reader: R) -> io::Result<u64> {
    let compact_size = CompactSize::read(&mut reader)?
        .enforce_valid()
        .map_err(|err| {
            match err {
                | compactsize::CompactSizeError::NonCanonical(_) => {
                    io::Error::new(io::ErrorKind::InvalidData, "non-canonical compact size")
                },
                | compactsize::CompactSizeError::ExceedsMaximum(_) => {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "compact size exceeds consensus maximum",
                    )
                },
            }
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

pub(crate) fn read_fp_list<R: Read>(mut reader: R) -> io::Result<Vec<Fp>> {
    let n = usize::try_from(read_compactsize(&mut reader)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fp_list length exceeds usize"))?;
    let mut fp_list = Vec::with_capacity(n);
    for _ in 0..n {
        let fp = read_fp(&mut reader)?;
        fp_list.push(fp);
    }
    Ok(fp_list)
}

pub(crate) fn write_fp_list<W: Write>(mut writer: W, fp_list: &[Fp]) -> io::Result<()> {
    write_compactsize(
        &mut writer,
        u64::try_from(fp_list.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fp_list.len() exceeds u64"))?,
    )?;
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
