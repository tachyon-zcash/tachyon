use core2::io::{self, Read, Write};
use ff::PrimeField as _;
use pasta_curves::Fp;

use crate::serialization;

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

impl Anchor {
    /// Attempt to parse an anchor from 32 bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Option<Self> {
        Fp::from_repr(bytes).into_option().map(Self)
    }

    /// Read an anchor from 32 bytes.
    pub fn read<R: Read>(reader: R) -> io::Result<Self> {
        serialization::read_fp(reader).map(Self)
    }

    /// Write an anchor as 32 bytes.
    pub fn write<W: Write>(&self, writer: W) -> io::Result<()> {
        serialization::write_fp(writer, &self.0)
    }
}
