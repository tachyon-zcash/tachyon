//! Shared serde visitors for field and curve point deserialization.

use core::fmt;

use ff::PrimeField as _;
use pasta_curves::{EpAffine, Fp, Fq};
use serde::de;

/// Visitor that deserializes 32 bytes into an `Fp` field element.
pub(crate) struct FpVisitor;

impl de::Visitor<'_> for FpVisitor {
    type Value = Fp;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("32 bytes encoding an Fp field element")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() != 32 {
            return Err(E::invalid_length(v.len(), &self));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(v);
        Fp::from_repr(bytes)
            .into_option()
            .ok_or_else(|| de::Error::custom("invalid field element"))
    }
}

/// Visitor that deserializes 32 bytes into an `Fq` field element.
pub(crate) struct FqVisitor;

impl de::Visitor<'_> for FqVisitor {
    type Value = Fq;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("32 bytes encoding an Fq field element")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() != 32 {
            return Err(E::invalid_length(v.len(), &self));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(v);
        Fq::from_repr(bytes)
            .into_option()
            .ok_or_else(|| de::Error::custom("invalid field element"))
    }
}

/// Visitor that deserializes 32 bytes into an `EpAffine` curve point.
pub(crate) struct EpAffineVisitor;

impl de::Visitor<'_> for EpAffineVisitor {
    type Value = EpAffine;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("32 bytes encoding a Pallas curve point")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        use group::GroupEncoding as _;

        if v.len() != 32 {
            return Err(E::invalid_length(v.len(), &self));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(v);
        EpAffine::from_bytes(&bytes)
            .into_option()
            .ok_or_else(|| de::Error::custom("invalid curve point"))
    }
}
