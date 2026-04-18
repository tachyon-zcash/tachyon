use core2::io::{self, Read, Write};
use ff::Field as _;
use pasta_curves::Fp;

use super::{BlockChainHash, BlockCommit, BlockHeight, EpochChainHash, PoolCommit};
use crate::serialization;

/// Pool state at a specific block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Anchor {
    /// Block height in the pool chain.
    pub block_height: BlockHeight,
    /// Per-block tachygram set commitment.
    pub block_commit: BlockCommit,
    /// Cumulative epoch tachygram commitment.
    pub pool_commit: PoolCommit,
    /// Running block chain hash.
    pub block_chain: BlockChainHash,
    /// Running epoch chain hash.
    pub epoch_chain: EpochChainHash,
}

impl Anchor {
    /// Genesis anchor from the activation height.
    #[must_use]
    pub fn genesis(activation_height: BlockHeight) -> Self {
        Self {
            block_height: activation_height,
            block_commit: BlockCommit::from(Fp::ZERO),
            pool_commit: PoolCommit::from(Fp::ZERO),
            block_chain: BlockChainHash::genesis(activation_height),
            epoch_chain: EpochChainHash::genesis(activation_height),
        }
    }

    /// Read an anchor from the wire format.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut height_bytes = [0u8; 4];
        reader.read_exact(&mut height_bytes)?;
        #[expect(clippy::little_endian_bytes, reason = "specified wire format")]
        let block_height = BlockHeight(u32::from_le_bytes(height_bytes));

        let block_commit = serialization::read_fp(&mut reader)?.into();
        let pool_commit = serialization::read_fp(&mut reader)?.into();
        let block_chain = serialization::read_fp(&mut reader)?.into();
        let epoch_chain = serialization::read_fp(&mut reader)?.into();

        Ok(Self {
            block_height,
            block_commit,
            pool_commit,
            block_chain,
            epoch_chain,
        })
    }

    /// Write an anchor in the wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        #[expect(clippy::little_endian_bytes, reason = "specified wire format")]
        writer.write_all(&u32::from(self.block_height).to_le_bytes())?;
        serialization::write_fp(&mut writer, &self.block_commit.into())?;
        serialization::write_fp(&mut writer, &self.pool_commit.into())?;
        serialization::write_fp(&mut writer, &self.block_chain.into())?;
        serialization::write_fp(&mut writer, &self.epoch_chain.into())?;
        Ok(())
    }
}
