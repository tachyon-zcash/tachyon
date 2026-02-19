use ff::PrimeField as _;
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(into = "[u8; 32]", try_from = "[u8; 32]"))]
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

impl From<Anchor> for [u8; 32] {
    fn from(an: Anchor) -> Self {
        an.0.to_repr()
    }
}

impl TryFrom<[u8; 32]> for Anchor {
    type Error = &'static str;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        Option::from(Fp::from_repr(bytes))
            .map(Self)
            .ok_or("invalid field element")
    }
}
