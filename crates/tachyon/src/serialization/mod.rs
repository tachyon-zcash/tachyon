//! Internal serialization helpers for read/write encoding.
//!
//! Provides shared read/write functions for the three field types used
//! throughout Tachyon: Pallas base field (`Fp`), Pallas scalar field
//! (`Fq`), and Pallas affine curve points (`EpAffine`).

use corez::io::{self, Read, Write};
use ff::PrimeField as _;
use pasta_curves::{EpAffine, EqAffine, Fp, group::GroupEncoding as _};

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

    use ff::{Field as _, FromUniformBytes as _};
    use group::{Curve as _, CurveAffine as _};
    use pasta_curves::Fq;
    use proptest::{collection, prelude::*};

    use super::*;
    use crate::testing::arb_fp;

    fn arb_fq() -> impl Strategy<Value = Fq> {
        prop_oneof![
            1 => Just(Fq::ZERO),
            1 => Just(Fq::ONE),
            6 => any::<[u8; 64]>().prop_map(|bytes| Fq::from_uniform_bytes(&bytes)),
        ]
    }

    fn encoded(write: impl FnOnce(&mut Vec<u8>) -> io::Result<()>) -> Vec<u8> {
        let mut buf = Vec::new();
        write(&mut buf).unwrap();
        buf
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn compactsizes_round_trip_within_the_bound(value in prop_oneof![0u64..1 << 26, any::<u64>()]) {
            let bytes = encoded(|buf| write_compactsize(buf, value));
            let result = read_compactsize(bytes.as_slice());
            if CompactSize::from(value).enforce_valid().is_ok() {
                prop_assert_eq!(result.unwrap(), value);
            } else {
                prop_assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            }
        }

        #[test]
        fn read_compactsize_rejects_exactly_the_invalid(
            bytes in collection::vec(any::<u8>(), 1..=9),
        ) {
            if let Ok(parsed) = CompactSize::read(bytes.as_slice()) {
                let result = read_compactsize(bytes.as_slice());
                if let Ok(valid) = parsed.enforce_valid() {
                    prop_assert_eq!(result.unwrap(), u64::from(valid));
                } else {
                    prop_assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
                }
            }
        }

        #[test]
        fn base_field_elements_round_trip(fp in arb_fp()) {
            let bytes = encoded(|buf| write_fp(buf, &fp));
            prop_assert_eq!(read_fp(bytes.as_slice()).unwrap(), fp);
        }

        #[test]
        fn base_field_decoding_is_canonical(bytes in any::<[u8; 32]>()) {
            let decoded = read_fp(bytes.as_slice());
            prop_assert_eq!(decoded.is_ok(), bool::from(Fp::from_repr(bytes).is_some()));
            if let Ok(fp) = decoded {
                prop_assert_eq!(encoded(|buf| write_fp(buf, &fp)), bytes.to_vec());
            }
        }

        #[test]
        fn pallas_points_round_trip(scalar in arb_fq()) {
            let point = (EpAffine::generator() * scalar).to_affine();
            let bytes = encoded(|buf| write_ep_affine(buf, &point));
            prop_assert_eq!(read_ep_affine(bytes.as_slice()).unwrap(), point);
        }

        #[test]
        fn pallas_decoding_is_canonical(bytes in any::<[u8; 32]>()) {
            if let Ok(point) = read_ep_affine(bytes.as_slice()) {
                prop_assert_eq!(encoded(|buf| write_ep_affine(buf, &point)), bytes.to_vec());
            }
        }

        #[test]
        fn vesta_points_round_trip(scalar in arb_fp()) {
            let point = (EqAffine::generator() * scalar).to_affine();
            let bytes = encoded(|buf| write_eq_affine(buf, &point));
            prop_assert_eq!(read_eq_affine(bytes.as_slice()).unwrap(), point);
        }

        #[test]
        fn vesta_decoding_is_canonical(bytes in any::<[u8; 32]>()) {
            if let Ok(point) = read_eq_affine(bytes.as_slice()) {
                prop_assert_eq!(encoded(|buf| write_eq_affine(buf, &point)), bytes.to_vec());
            }
        }

        #[test]
        fn action_key_decoding_is_canonical(bytes in any::<[u8; 32]>()) {
            if let Ok(key) = read_action_vk(bytes.as_slice()) {
                prop_assert_eq!(encoded(|buf| write_action_vk(buf, &key)), bytes.to_vec());
            }
        }

        #[test]
        fn signatures_round_trip(bytes in any::<[u8; 64]>()) {
            let action = read_action_sig(bytes.as_slice()).unwrap();
            prop_assert_eq!(encoded(|buf| write_action_sig(buf, &action)), bytes.to_vec());
            let binding = read_binding_sig(bytes.as_slice()).unwrap();
            prop_assert_eq!(encoded(|buf| write_binding_sig(buf, &binding)), bytes.to_vec());
        }

        #[test]
        fn truncated_fixed_width_encodings_are_rejected(
            bytes in any::<[u8; 64]>(),
            len in 0..32usize,
        ) {
            let prefix = &bytes[..len];
            prop_assert!(read_fp(prefix).is_err());
            prop_assert!(read_ep_affine(prefix).is_err());
            prop_assert!(read_eq_affine(prefix).is_err());
            prop_assert!(read_action_vk(prefix).is_err());
            prop_assert!(read_action_sig(&bytes[..len + 32]).is_err());
            prop_assert!(read_binding_sig(&bytes[..len + 32]).is_err());
        }
    }
}
