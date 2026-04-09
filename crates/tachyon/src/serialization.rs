//! Internal serialization helpers for read/write encoding.
//!
//! Provides shared read/write functions for the three field types used
//! throughout Tachyon: Pallas base field (`Fp`), Pallas scalar field
//! (`Fq`), and Pallas affine curve points (`EpAffine`).

#![allow(dead_code, reason = "may not be used")]

use core2::io::{self, Read, Write};
use ff::PrimeField as _;
use pasta_curves::{EpAffine, EqAffine, Fp, Fq, group::GroupEncoding as _};

use crate::reddsa;

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

/// Read a Vesta affine curve point (`EqAffine`) from 32 compressed bytes.
pub(crate) fn read_eq_affine<R: Read>(mut reader: R) -> io::Result<EqAffine> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(EqAffine::from_bytes(&bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Vesta point encoding"))
}

/// Write a Vesta affine curve point (`EqAffine`) as 32 compressed bytes.
pub(crate) fn write_eq_affine<W: Write>(mut writer: W, point: &EqAffine) -> io::Result<()> {
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
