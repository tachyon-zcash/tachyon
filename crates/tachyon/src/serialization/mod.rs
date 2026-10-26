//! Internal serialization helpers for read/write encoding.
//!
//! Provides shared read/write functions for the three field types used
//! throughout Tachyon: Pallas base field (`Fp`), Pallas scalar field
//! (`Fq`), and Pallas affine curve points (`EpAffine`).

use corez::io::{self, Read, Write};
use ragu::pasta::{EpAffine, EqAffine, Fp};
use udon::{curve::Affine as _, field::Field as _};

pub(crate) mod compactsize;

use crate::{reddsa, serialization::compactsize::CompactSize};

pub(crate) fn read_compactsize<R: Read>(mut reader: R) -> io::Result<u64> {
    let compact_size =
        CompactSize::read(&mut reader)?
            .enforce_valid()
            .map_err(|err| match err {
                compactsize::CompactSizeError::NonCanonical(_) => {
                    io::Error::new(io::ErrorKind::InvalidData, "non-canonical compact size")
                },
                compactsize::CompactSizeError::ExceedsMaximum(_) => io::Error::new(
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
    Fp::from_bytes(bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Fp encoding"))
}

/// Write a Pallas base field element (`Fp`) as 32 bytes.
pub(crate) fn write_fp<W: Write>(mut writer: W, fp: &Fp) -> io::Result<()> {
    writer.write_all(&fp.to_bytes())
}

/// Read a Pallas affine curve point (`EpAffine`) from 32 compressed bytes.
pub(crate) fn read_ep_affine<R: Read>(mut reader: R) -> io::Result<EpAffine> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    EpAffine::from_bytes(bytes)
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
    EqAffine::from_bytes(bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid curve point encoding"))
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

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ff::PrimeField as _;
    use group::{Curve as _, Group as _, GroupEncoding as _};
    use pasta_curves::{
        EpAffine as LegacyEpAffine, EqAffine as LegacyEqAffine, Fp as LegacyFp, pallas, vesta,
    };

    use super::*;

    #[test]
    fn field_and_compressed_point_bytes_match_the_legacy_boundaries() {
        let legacy_field = LegacyFp::from(0x1234_5678u64);
        let legacy_field_bytes = legacy_field.to_repr();
        let current_field = Fp::from_bytes(legacy_field_bytes)
            .expect("legacy canonical field bytes decode in Udon");
        assert_eq!(current_field.to_bytes(), legacy_field_bytes);
        assert_eq!(read_fp(&legacy_field_bytes[..]).unwrap(), current_field);
        let mut written_field = Vec::new();
        write_fp(&mut written_field, &current_field).unwrap();
        assert_eq!(written_field, legacy_field_bytes.as_ref());
        assert!(LegacyFp::from_repr([0xff; 32]).into_option().is_none());
        assert_eq!(
            read_fp(&[0xff; 32][..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let pallas_generator = pallas::Point::generator();
        let pallas_points = [
            pallas_generator.to_affine(),
            (-pallas_generator).to_affine(),
        ];
        let mut saw_pallas_sign = false;
        for legacy_point in pallas_points {
            let bytes = legacy_point.to_bytes();
            saw_pallas_sign |= bytes.last().is_some_and(|last| last & 0x80 != 0);
            let legacy_round_trip = LegacyEpAffine::from_bytes(&bytes)
                .into_option()
                .expect("legacy compressed Pallas point round-trips");
            assert_eq!(legacy_round_trip.to_bytes(), bytes);
            let current_point = read_ep_affine(&bytes[..]).unwrap();
            assert_eq!(current_point.to_bytes(), bytes);
            let mut written_point = Vec::new();
            write_ep_affine(&mut written_point, &current_point).unwrap();
            assert_eq!(written_point, bytes.as_ref());
        }
        assert!(saw_pallas_sign, "the point fixtures exercise the sign bit");
        assert!(
            LegacyEpAffine::from_bytes(&[0xff; 32])
                .into_option()
                .is_none()
        );
        assert_eq!(
            read_ep_affine(&[0xff; 32][..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let vesta_generator = vesta::Point::generator();
        let vesta_points = [vesta_generator.to_affine(), (-vesta_generator).to_affine()];
        let mut saw_vesta_sign = false;
        for legacy_point in vesta_points {
            let bytes = legacy_point.to_bytes();
            saw_vesta_sign |= bytes.last().is_some_and(|last| last & 0x80 != 0);
            let legacy_round_trip = LegacyEqAffine::from_bytes(&bytes)
                .into_option()
                .expect("legacy compressed Vesta point round-trips");
            assert_eq!(legacy_round_trip.to_bytes(), bytes);
            let current_point = read_eq_affine(&bytes[..]).unwrap();
            assert_eq!(current_point.to_bytes(), bytes);
            let mut written_point = Vec::new();
            write_eq_affine(&mut written_point, &current_point).unwrap();
            assert_eq!(written_point, bytes.as_ref());
        }
        assert!(saw_vesta_sign, "the point fixtures exercise the sign bit");
        assert!(
            LegacyEqAffine::from_bytes(&[0xff; 32])
                .into_option()
                .is_none()
        );
        assert_eq!(
            read_eq_affine(&[0xff; 32][..]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
