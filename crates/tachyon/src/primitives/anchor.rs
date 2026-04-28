use core2::io::{self, Read, Write};

use super::PoolChain;

/// Pool state at a specific block. Wire format is 32 bytes.
///
/// `Anchor` is just the per-block hash chain `chain_n =
/// prev_chain.advance(&block_commit)`. The chain advance is collision-
/// resistant in the prior chain hash and the latest `BlockCommit`, so the
/// chain alone is sufficient to identify a unique position. Where a verifier
/// or step needs the prior chain or block commitment separately, those
/// values are witnessed alongside the anchor (see `SpendableLift`,
/// `SpendStamp`, etc.).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Anchor(pub PoolChain);

impl Anchor {
    /// Read a 32-byte anchor.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut chain_bytes = [0u8; 32];
        reader.read_exact(&mut chain_bytes)?;
        let chain = PoolChain::try_from(&chain_bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        Ok(Self(chain))
    }

    /// Write a 32-byte anchor.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let chain_bytes: [u8; 32] = self.0.into();
        writer.write_all(&chain_bytes)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ff::Field as _;
    use mock_ragu::Polynomial;
    use pasta_curves::Fp;

    use super::{Anchor, PoolChain};
    use crate::primitives::{BlockCommit, BlockHeight};

    #[test]
    fn anchor_wire_is_32_bytes_round_trip() {
        let block_commit = BlockCommit(Polynomial::default().commit(Fp::ZERO));
        let chain = PoolChain::genesis().advance(BlockHeight(0), &block_commit);
        let anchor = Anchor(chain);
        let mut bytes = Vec::new();
        anchor.write(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 32, "anchor wire must be 32 bytes");
        let decoded = Anchor::read(bytes.as_slice()).unwrap();
        assert_eq!(decoded, anchor);
    }
}
