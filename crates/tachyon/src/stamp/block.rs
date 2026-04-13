//! Block-level PCD: decomposed block commit + pool-bound block header.
//!
//! A block's `block_commit` is defined as the sum of per-sub-block Pedersen
//! commitments (`SetCommit` is additively homomorphic). These steps build up
//! that sum as a PCD tree:
//!
//! - [`BlockSubsetLeaf<N>`] commits one sub-block of `N` tachygrams.
//! - [`BlockSubsetFuse`] sums two `BlockSubsetHeader`s with matching height.
//! - [`BlockBindPool`] verifies the fully-merged sub-commit matches the pool
//!   chain's attested `block_commit`, producing a [`BlockHeader`] that
//!   downstream steps (e.g. [`SpendableInit`](super::spendable::SpendableInit))
//!   consume in place of [`PoolHeader`](super::pool::PoolHeader).

extern crate alloc;

use alloc::vec::Vec;

use mock_ragu::{Header, Index, Step, Suffix};
use pasta_curves::{EqAffine, Fp};

use super::pool::PoolHeader;
use crate::{
    SetCommit,
    primitives::{Anchor, BlockHeight, Tachygram, polynomial},
};

// ---------------------------------------------------------------------------
// BlockSubsetHeader — partial or fully-merged commit to a block's tachygrams
// ---------------------------------------------------------------------------

/// A partial or fully-merged polynomial commitment to a block's tachygrams.
///
/// `sub_commit` is a `SetCommit` over the coefficients of the polynomial built
/// from the covered sub-block(s). A fully-merged header (covering every
/// sub-block at `block_height`) has `sub_commit == block_commit` for that
/// block.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct BlockSubsetHeader;

impl Header for BlockSubsetHeader {
    /// `(sub_commit, block_height)`
    type Data<'source> = (SetCommit, BlockHeight);

    const SUFFIX: Suffix = Suffix::new(15);

    fn encode(&(sub_commit, block_height): &Self::Data<'_>) -> Vec<u8> {
        use pasta_curves::group::GroupEncoding as _;
        let mut out = Vec::with_capacity(32 + 4);
        out.extend_from_slice(&EqAffine::from(sub_commit).to_bytes());
        #[expect(clippy::little_endian_bytes, reason = "specified encoding")]
        out.extend_from_slice(&u32::from(block_height).to_le_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// BlockHeader — pool-attested block-level anchor
// ---------------------------------------------------------------------------

/// A block's pool-chain anchor alongside the attested sum of all *non-cm*
/// sub-blocks' commits.
///
/// Produced by [`BlockBindPool`] from a merge-tree-fused `BlockSubsetHeader`
/// and a `PoolHeader`. Consumed by
/// [`SpendableInit`](super::spendable::SpendableInit), which closes the
/// decomposition loop by verifying that its witnessed cm sub-block's commit
/// plus `sum_others` equals `anchor.block_commit`. Because `sum_others` is
/// PCD-attested (not a free witness), the equation binds uniquely via
/// Pedersen — the prover cannot fabricate a sub-block that matches.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct BlockHeader;

impl Header for BlockHeader {
    /// `(sum_others, anchor)` — `sum_others` is the Pedersen-committed sum
    /// of every sub-block *except* the cm's, and `anchor` is pool-attested.
    type Data<'source> = (SetCommit, Anchor);

    const SUFFIX: Suffix = Suffix::new(16);

    fn encode(&(sum_others, anchor): &Self::Data<'_>) -> Vec<u8> {
        use pasta_curves::group::GroupEncoding as _;
        let mut out = Vec::with_capacity(32 + 4 + 32 * 4);
        out.extend_from_slice(&EqAffine::from(sum_others).to_bytes());
        out.extend_from_slice(&anchor.encode_for_header());
        out
    }
}

// ---------------------------------------------------------------------------
// BlockSubsetLeaf<N> — seed a sub-block commit
// ---------------------------------------------------------------------------

/// Commits one sub-block of up to `N` tachygrams.
///
/// Witness: `(block_height, [Tachygram; N])`. Computes
/// `pedersen_commit(poly_from_roots(tachygrams))` and outputs it alongside
/// `block_height`. Prover-padded slots use `Fp::ZERO` (consistent with
/// consensus-level block-commit computation).
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct BlockSubsetLeaf<const N: usize>;

impl<const N: usize> Step for BlockSubsetLeaf<N> {
    type Aux<'source> = ();
    type Left = ();
    type Output = BlockSubsetHeader;
    type Right = ();
    type Witness<'source> = (BlockHeight, &'source [Tachygram; N]);

    const INDEX: Index = Index::new(29);

    fn witness<'source>(
        &self,
        (block_height, tachygrams): Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let roots: Vec<Fp> = tachygrams.iter().map(|tg| Fp::from(*tg)).collect();
        let coeffs = polynomial::poly_from_roots(&roots);
        let sub_commit = SetCommit::from(polynomial::pedersen_commit(&coeffs));
        Ok(((sub_commit, block_height), ()))
    }
}

// ---------------------------------------------------------------------------
// BlockSubsetEmpty — seed the empty-siblings case
// ---------------------------------------------------------------------------

/// Seeds a `BlockSubsetHeader` carrying the identity commit.
///
/// Used when the block consists of a single sub-block — the one containing
/// cm that [`SpendableInit`](super::spendable::SpendableInit) owns — so the
/// merge tree of "other" sub-blocks is empty and its sum is the identity
/// point. Analogous to the multiplicative identity in a merge tree whose
/// binary op is `SetCommit::+`.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct BlockSubsetEmpty;

impl Step for BlockSubsetEmpty {
    type Aux<'source> = ();
    type Left = ();
    type Output = BlockSubsetHeader;
    type Right = ();
    type Witness<'source> = BlockHeight;

    const INDEX: Index = Index::new(32);

    fn witness<'source>(
        &self,
        witness: Self::Witness<'source>,
        _left: <Self::Left as Header>::Data<'source>,
        _right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        let block_height = witness;
        Ok(((SetCommit::identity(), block_height), ()))
    }
}

// ---------------------------------------------------------------------------
// BlockSubsetFuse — merge two sub-block commits
// ---------------------------------------------------------------------------

/// Sums two `BlockSubsetHeader`s at the same `block_height`.
///
/// Witness-free. `SetCommit` is additively homomorphic over coefficient
/// vectors, so summed sub-commits reconstruct the block-level commit.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct BlockSubsetFuse;

impl Step for BlockSubsetFuse {
    type Aux<'source> = ();
    type Left = BlockSubsetHeader;
    type Output = BlockSubsetHeader;
    type Right = BlockSubsetHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(30);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (left_commit, left_height): <Self::Left as Header>::Data<'source>,
        (right_commit, right_height): <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_height != right_height {
            return Err(mock_ragu::Error);
        }
        Ok(((left_commit + right_commit, left_height), ()))
    }
}

// ---------------------------------------------------------------------------
// BlockBindPool — bind a decomposed block commit to the pool chain
// ---------------------------------------------------------------------------

/// Binds a (partial) merge-tree `BlockSubsetHeader` to the pool chain.
///
/// Witness-free. Verifies that the sub-commit's height matches the
/// `PoolHeader`'s `block_commit` height. **Does not** check full-commit
/// equality — `left.sub_commit` represents the sum of sub-blocks *other than
/// the cm's*, and the full check is closed by
/// [`SpendableInit`](super::spendable::SpendableInit) which adds the cm
/// sub-block's commit.
///
/// Output: `(sum_others, anchor)` carried through as a `BlockHeader`.
#[derive(Debug)]
#[expect(clippy::module_name_repetitions, reason = "meaningful name")]
pub struct BlockBindPool;

impl Step for BlockBindPool {
    type Aux<'source> = ();
    type Left = BlockSubsetHeader;
    type Output = BlockHeader;
    type Right = PoolHeader;
    type Witness<'source> = ();

    const INDEX: Index = Index::new(31);

    fn witness<'source>(
        &self,
        _witness: Self::Witness<'source>,
        (sum_others, left_height): <Self::Left as Header>::Data<'source>,
        right: <Self::Right as Header>::Data<'source>,
    ) -> mock_ragu::Result<(<Self::Output as Header>::Data<'source>, Self::Aux<'source>)> {
        if left_height != right.block_height {
            return Err(mock_ragu::Error);
        }
        Ok(((sum_others, right), ()))
    }
}
