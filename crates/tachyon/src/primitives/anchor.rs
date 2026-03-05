use pasta_curves::Fp;

/// A reference to a specific tachyon accumulator state.
///
/// The tachyon accumulator is append-only: the state at epoch N is a
/// subset of the state at epoch M for M > N. This means membership
/// proofs valid at an earlier state remain valid at all later states.
///
/// When stamps are merged during aggregation, the later anchor
/// subsumes the earlier — "analogous to the max of all aggregated
/// anchors" (the most recent state covers everything the earlier
/// states covered).
///
/// Range validation (checking that the anchor falls within the valid
/// epoch window for the landing block) is performed by the consensus
/// layer outside the circuit.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Anchor(Fp);

impl From<Fp> for Anchor {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

impl From<Anchor> for Fp {
    fn from(an: Anchor) -> Self {
        an.0
    }
}

// Custom serde implementation for Anchor
#[cfg(feature = "serde")]
impl serde::Serialize for Anchor {
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
impl<'de> serde::Deserialize<'de> for Anchor {
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
