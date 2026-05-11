use corez::io::{self, Read, Write};
use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;

use super::EpochIndex;
use crate::{SubBlock, digest::poseidon};

/// Chain anchor.
///
/// A running Poseidon hash chain. Intra-epoch links absorb only the
/// `(prev_anchor, block_state)` pair via [`Anchor::next_block`];
/// epoch transitions are domain-separated boundary links of the form
/// `(prev_anchor, new_epoch)` via [`Anchor::next_epoch`] (performed by
/// `SpendableRollover`). Opening a chain reveals which links cross epoch
/// boundaries by their domain.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Anchor(pub Fp);

impl Anchor {
    /// Advance the anchor by one intra-epoch block.
    #[must_use]
    pub fn next_block(self, block_state: SubBlock) -> Self {
        Self(poseidon::anchor_block_step(self.0, block_state.0))
    }

    /// Lift the anchor across an epoch boundary into the new epoch's
    /// initial chain state.
    #[must_use]
    pub fn next_epoch(self, new_epoch: EpochIndex) -> Self {
        Self(poseidon::anchor_epoch_step(self.0, new_epoch.0))
    }

    /// Read a 32-byte anchor.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        Option::from(Fp::from_repr(bytes))
            .map(Self)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "anchor not in Fp"))
    }

    /// Write a 32-byte anchor.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.0.to_repr())
    }
}

impl Default for Anchor {
    /// The genesis epoch boundary.
    fn default() -> Self {
        Self(Fp::ZERO).next_epoch(EpochIndex(0))
    }
}

impl From<Fp> for Anchor {
    fn from(fp: Fp) -> Self {
        Self(fp)
    }
}

/// Anchor's underlying `Fp` — the value used as a Poseidon input or as a
/// polynomial root in the per-epoch blocks set.
impl From<Anchor> for Fp {
    fn from(anchor: Anchor) -> Self {
        anchor.0
    }
}

impl PartialEq<Self> for Anchor {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
