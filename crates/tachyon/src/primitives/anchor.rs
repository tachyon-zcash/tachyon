extern crate alloc;

use alloc::vec::Vec;

use core2::io::{self, Read, Write};
use pasta_curves::EqAffine;

use super::{BlockChainHash, BlockCommit, BlockHeight, EpochChainHash, PoolCommit, SetCommit};
use crate::serialization;

/// Pool state at a specific block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Anchor {
    /// Block height in the pool chain.
    pub block_height: BlockHeight,
    /// Per-block polynomial commitment (Vesta point).
    pub block_commit: BlockCommit,
    /// Cumulative epoch polynomial commitment (Vesta point).
    pub pool_commit: PoolCommit,
    /// Running block chain hash (Fq).
    pub block_chain: BlockChainHash,
    /// Running epoch chain hash (Fq).
    pub epoch_chain: EpochChainHash,
}

impl Anchor {
    /// Genesis anchor from the activation height.
    #[must_use]
    pub fn genesis(activation_height: BlockHeight) -> Self {
        Self {
            block_height: activation_height,
            block_commit: BlockCommit(SetCommit::identity()),
            pool_commit: PoolCommit(SetCommit::identity()),
            block_chain: BlockChainHash::genesis(activation_height),
            epoch_chain: EpochChainHash::genesis(activation_height),
        }
    }

    /// Encode an anchor for PCD header encoding.
    #[must_use]
    pub fn encode_for_header(&self) -> Vec<u8> {
        use ff::PrimeField as _;
        use pasta_curves::{Fq, group::GroupEncoding as _};
        let mut out = Vec::with_capacity(4 + 32 * 4);
        #[expect(clippy::little_endian_bytes, reason = "specified encoding")]
        out.extend_from_slice(&u32::from(self.block_height).to_le_bytes());
        out.extend_from_slice(&EqAffine::from(self.block_commit.0).to_bytes());
        out.extend_from_slice(&EqAffine::from(self.pool_commit.0).to_bytes());
        out.extend_from_slice(&Fq::from(self.block_chain).to_repr());
        out.extend_from_slice(&Fq::from(self.epoch_chain).to_repr());
        out
    }

    /// Read an anchor from the wire format.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut height_bytes = [0u8; 4];
        reader.read_exact(&mut height_bytes)?;
        #[expect(clippy::little_endian_bytes, reason = "specified wire format")]
        let block_height = BlockHeight(u32::from_le_bytes(height_bytes));

        let block_commit = BlockCommit(serialization::read_eq_affine(&mut reader)?.into());
        let pool_commit = PoolCommit(serialization::read_eq_affine(&mut reader)?.into());
        let block_chain = serialization::read_fq(&mut reader)?.into();
        let epoch_chain = serialization::read_fq(&mut reader)?.into();

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
        serialization::write_eq_affine(&mut writer, &EqAffine::from(self.block_commit.0))?;
        serialization::write_eq_affine(&mut writer, &EqAffine::from(self.pool_commit.0))?;
        serialization::write_fq(&mut writer, &self.block_chain.into())?;
        serialization::write_fq(&mut writer, &self.epoch_chain.into())?;
        Ok(())
    }
}
