use core2::io::{self, Read, Write};
use mock_ragu::Commitment;

use super::{BlockCommit, PoolChain};

/// Pool state at a specific block. Wire format is 64 bytes.
///
/// `Anchor(block_commit, chain)` exposes the per-block hash chain
/// `chain_n = prev_chain.advance(&block_commit)` along with the latest
/// block's Pedersen commitment. Block height is no longer carried here —
/// circuits prove it by witnessing the height and asserting membership of
/// `BlockHeight::tachygram()` in the latest block's set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Anchor(pub BlockCommit, pub PoolChain);

impl Anchor {
    /// Read a 64-byte anchor.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut commit_bytes = [0u8; 32];
        reader.read_exact(&mut commit_bytes)?;
        let commit = BlockCommit(
            Commitment::try_from(&commit_bytes)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
        );

        let mut chain_bytes = [0u8; 32];
        reader.read_exact(&mut chain_bytes)?;
        let chain = PoolChain::try_from(&chain_bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        Ok(Self(commit, chain))
    }

    /// Write a 64-byte anchor.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        let commit_bytes: [u8; 32] = self.0.0.into();
        writer.write_all(&commit_bytes)?;
        let chain_bytes: [u8; 32] = self.1.into();
        writer.write_all(&chain_bytes)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ff::Field as _;
    use mock_ragu::Polynomial;
    use pasta_curves::Fp;

    use super::{Anchor, BlockCommit, PoolChain};

    #[test]
    fn anchor_wire_is_64_bytes_round_trip() {
        let block_commit = BlockCommit(Polynomial::default().commit(Fp::ZERO));
        let chain = PoolChain::genesis().advance(&block_commit);
        let anchor = Anchor(block_commit, chain);
        let mut bytes = Vec::new();
        anchor.write(&mut bytes).unwrap();
        assert_eq!(bytes.len(), 64, "anchor wire must be 64 bytes");
        let decoded = Anchor::read(bytes.as_slice()).unwrap();
        assert_eq!(decoded, anchor);
    }
}
