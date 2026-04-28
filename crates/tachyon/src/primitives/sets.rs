extern crate alloc;

use alloc::vec::Vec;

use mock_ragu::{Commitment, Multiset, Polynomial};
use pasta_curves::Fp;

use super::{ActionDigest, PoolChain, Tachygram};

/// 32-byte Pedersen commitment for the pool state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PoolCommit(pub Commitment);

/// 32-byte Pedersen commitment for a block's tachygram set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockCommit(pub Commitment);

/// 32-byte Pedersen commitment for a stamp's action-digest set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionCommit(pub Commitment);

/// 32-byte Pedersen commitment for a stamp's tachygram set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TachygramCommit(pub Commitment);

/// Pool-state set: per-block hash chain over completed history plus the
/// latest block's tachygram multiset.
///
/// `prev_chain` is the chain through the prior block; the anchor's chain is
/// `prev_chain.advance(&block.commit())`. `block.query(x)` proves what's in
/// the latest block, while the chain hash binds everything that came before.
///
/// `T = Polynomial` for external state (see [`PoolAcc`]); `T = Multiset`
/// for the gadget form handed to a step as witness.
#[derive(Clone, Debug)]
pub struct PoolSet<T> {
    /// Hash chain over the pool's history *prior to* the latest block.
    pub prev_chain: PoolChain,
    /// Tachygram set of the latest block.
    pub block: BlockSet<T>,
}

/// Block set. `T = Polynomial` for external state (see [`BlockAcc`]);
/// `T = Multiset` for the gadget form handed to a step as witness.
#[derive(Clone, Debug)]
pub struct BlockSet<T>(pub T);

/// Action-digest set. See [`ActionAcc`].
#[derive(Clone, Debug)]
pub struct ActionSet<T>(pub T);

/// Tachygram set carried by a stamp. See [`TachygramAcc`].
#[derive(Clone, Debug)]
pub struct TachygramSet<T>(pub T);

/// Polynomial-form pool set — external prover state between steps.
pub type PoolAcc = PoolSet<Polynomial>;

/// Polynomial-form block set — external prover state between steps.
pub type BlockAcc = BlockSet<Polynomial>;

/// Polynomial-form action set — external prover state between steps.
pub type ActionAcc = ActionSet<Polynomial>;

/// Polynomial-form tachygram set — external prover state between steps.
pub type TachygramAcc = TachygramSet<Polynomial>;

impl From<&[ActionDigest]> for ActionAcc {
    fn from(ads: &[ActionDigest]) -> Self {
        let roots: Vec<Fp> = ads.iter().map(Fp::from).collect();
        Self(Polynomial::from_roots(&roots))
    }
}

impl From<&[Tachygram]> for TachygramAcc {
    fn from(tgs: &[Tachygram]) -> Self {
        let roots: Vec<Fp> = tgs.iter().map(Fp::from).collect();
        Self(Polynomial::from_roots(&roots))
    }
}

impl From<&[Tachygram]> for BlockAcc {
    fn from(tgs: &[Tachygram]) -> Self {
        let roots: Vec<Fp> = tgs.iter().map(Fp::from).collect();
        Self(Polynomial::from_roots(&roots))
    }
}

impl From<PoolSet<Polynomial>> for PoolSet<Multiset> {
    fn from(poly: PoolSet<Polynomial>) -> Self {
        Self {
            prev_chain: poly.prev_chain,
            block: poly.block.into(),
        }
    }
}

impl From<BlockSet<Polynomial>> for BlockSet<Multiset> {
    fn from(poly: BlockSet<Polynomial>) -> Self {
        Self(Multiset::new(poly.0))
    }
}

impl From<ActionSet<Polynomial>> for ActionSet<Multiset> {
    fn from(poly: ActionSet<Polynomial>) -> Self {
        Self(Multiset::new(poly.0))
    }
}

impl From<TachygramSet<Polynomial>> for TachygramSet<Multiset> {
    fn from(poly: TachygramSet<Polynomial>) -> Self {
        Self(Multiset::new(poly.0))
    }
}
