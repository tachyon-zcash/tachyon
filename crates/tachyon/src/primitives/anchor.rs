use pasta_curves::Fp;
use serde::{Deserialize, Serialize};

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
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub struct Anchor(#[serde(with = "fp_serde")] Fp);

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
