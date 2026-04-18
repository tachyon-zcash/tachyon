use core::marker::PhantomData;

use ff::{Field as _, PrimeField as _};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

use super::{BlockCommit, BlockHeight, PoolCommit};
use crate::constants::{BLOCK_CHAIN_HASH_DOMAIN, EPOCH_CHAIN_HASH_DOMAIN};

mod sealed {
    pub trait Sealed {}
}

/// Domain for a chain hash. Sealed — only `BlockChain` and `EpochChain`.
pub trait ChainDomain: sealed::Sealed {
    /// Poseidon domain tag.
    const TAG: &'static [u8; 16];
    /// Type of value chained at each step.
    type Value: Into<Fp> + Copy;
}

/// Block-level chain: `H(prev, block_commit)` every block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockChain;
impl sealed::Sealed for BlockChain {}
impl ChainDomain for BlockChain {
    type Value = BlockCommit;

    const TAG: &'static [u8; 16] = BLOCK_CHAIN_HASH_DOMAIN;
}

/// Epoch-level chain: `H(prev, pool_commit)` at epoch boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochChain;
impl sealed::Sealed for EpochChain {}
impl ChainDomain for EpochChain {
    type Value = PoolCommit;

    const TAG: &'static [u8; 16] = EPOCH_CHAIN_HASH_DOMAIN;
}

/// Running chain hash parameterized by domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainHash<D: ChainDomain>(Fp, PhantomData<D>);

impl<D: ChainDomain> ChainHash<D> {
    /// Genesis chain hash from the activation height.
    #[must_use]
    pub fn genesis(activation_height: BlockHeight) -> Self {
        #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
        let domain = Fp::from_u128(u128::from_le_bytes(*D::TAG));
        let height = Fp::from(u64::from(u32::from(activation_height)));
        Self(
            Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([domain, Fp::ZERO, height]),
            PhantomData,
        )
    }

    /// Compute the next chain hash: `H(self, value)`.
    #[must_use]
    pub fn chain(self, value: D::Value) -> Self {
        #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
        let domain = Fp::from_u128(u128::from_le_bytes(*D::TAG));
        Self(
            Hash::<_, P128Pow5T3, ConstantLength<3>, 3, 2>::init().hash([
                domain,
                self.0,
                value.into(),
            ]),
            PhantomData,
        )
    }
}

impl<D: ChainDomain> From<ChainHash<D>> for Fp {
    fn from(ch: ChainHash<D>) -> Self {
        ch.0
    }
}

impl<D: ChainDomain> From<Fp> for ChainHash<D> {
    fn from(fp: Fp) -> Self {
        Self(fp, PhantomData::<D>)
    }
}

/// Block chain hash: `ChainHash<BlockChain>`.
pub type BlockChainHash = ChainHash<BlockChain>;

/// Epoch chain hash: `ChainHash<EpochChain>`.
pub type EpochChainHash = ChainHash<EpochChain>;
