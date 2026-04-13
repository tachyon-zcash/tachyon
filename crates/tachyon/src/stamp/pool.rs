//! Pool chain header and steps.

extern crate alloc;

use alloc::vec::Vec;

use mock_ragu::{Header, Index, Step, Suffix};

use crate::primitives::{Anchor, BlockCommit, BlockHeight, PoolCommit};

/// Marker type for PCD headers carrying pool state.
#[derive(Debug)]
pub struct PoolHeader;

impl Header for PoolHeader {
    type Data<'source> = Anchor;

    const SUFFIX: Suffix = Suffix::new(2);

    fn encode(data: &Self::Data<'_>) -> Vec<u8> {
        data.encode_for_header()
    }
}

/// One-time pool chain genesis.
#[derive(Debug)]
pub struct PoolSeed;

impl Step for PoolSeed {
    type Aux<'source> = ();
    type Left = ();
    type Output = PoolHeader;
    type Right = ();
    type Witness<'source> = BlockHeight;

    const INDEX: Index = Index::new(5);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        Ok((Anchor::genesis(witness), ()))
    }
}

/// Advances pool state by one block.
#[derive(Debug)]
pub struct PoolStep;

impl Step for PoolStep {
    type Aux<'source> = ();
    type Left = PoolHeader;
    type Output = PoolHeader;
    type Right = ();
    type Witness<'source> = (BlockCommit, PoolCommit);

    const INDEX: Index = Index::new(9);

    fn witness<'source>(
        &self,
        (block_commit, pool_commit): Self::Witness<'source>,
        left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let new_height = left.block_height.next();

        let new_block_chain = left.block_chain.chain(left.block_commit);

        // epoch_chain absorbs the old epoch's final pool_commit at boundary
        let new_epoch_chain = if new_height.is_epoch_boundary() {
            left.epoch_chain.chain(left.pool_commit)
        } else {
            left.epoch_chain
        };

        // pool_commit resets at epoch boundaries
        let expected_pool = if new_height.is_epoch_boundary() {
            PoolCommit(block_commit.0)
        } else {
            PoolCommit(left.pool_commit.0 + block_commit.0)
        };
        if pool_commit != expected_pool {
            return Err(mock_ragu::Error);
        }

        Ok((
            Anchor {
                block_height: new_height,
                block_commit,
                pool_commit,
                block_chain: new_block_chain,
                epoch_chain: new_epoch_chain,
            },
            (),
        ))
    }
}
