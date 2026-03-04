use pasta_curves::Fp;

/// A tachygram is a field element ($\mathbb{F}_p$) representing either a
/// note commitment or a nullifier in the Tachyon polynomial accumulator.
///
/// The accumulator does not distinguish between commitments and nullifiers.
/// This unified approach simplifies the proof system and enables efficient
/// batch operations.
///
/// The number of tachygrams in a stamp need not equal the number of
/// actions. The invariant is consistency between the listed tachygrams
/// and the proof's `tachygram_acc`, not a fixed ratio to actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Tachygram(Fp);

impl From<Fp> for Tachygram {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<Tachygram> for Fp {
    fn from(tg: Tachygram) -> Self {
        tg.0
    }
}

// Custom serde implementation for Tachygram
#[cfg(feature = "serde")]
impl serde::Serialize for Tachygram {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use ff::PrimeField;
        let bytes = self.0.to_repr();
        serializer.serialize_bytes(&bytes)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Tachygram {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use ff::PrimeField;
        
        struct ByteArrayVisitor;
        
        impl<'de> serde::de::Visitor<'de> for ByteArrayVisitor {
            type Value = [u8; 32];
            
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("32 bytes")
            }
            
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() == 32 {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(v);
                    Ok(bytes)
                } else {
                    Err(E::invalid_length(v.len(), &self))
                }
            }
        }
        
        let bytes = deserializer.deserialize_bytes(ByteArrayVisitor)?;
        let fp_option = Fp::from_repr(bytes);
        if fp_option.is_some().into() {
            Ok(Self(fp_option.unwrap()))
        } else {
            Err(serde::de::Error::custom("invalid field element"))
        }
    }
}
