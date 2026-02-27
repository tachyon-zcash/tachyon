use pasta_curves::Fp;
use serde::{Deserialize, Serialize};

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
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Tachygram(#[serde(with = "fp_serde")] Fp);

mod fp_serde {
    use pasta_curves::Fp;
    use group::ff::PrimeField;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(fp: &Fp, serializer: S) -> Result<S::Ok, S::Error> {
        fp.to_repr().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Fp, D::Error> {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Option::from(Fp::from_repr(bytes))
            .ok_or_else(|| serde::de::Error::custom("invalid field element"))
    }
}

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
