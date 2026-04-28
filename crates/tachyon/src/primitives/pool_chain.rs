use ff::PrimeField as _;
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{Fp, arithmetic::CurveAffine as _};

use super::{BlockCommit, BlockHeight};
use crate::constants::POOL_CHAIN_DOMAIN;

/// Per-block hash chain over completed pool history.
///
/// $$\mathsf{chain}_n =
/// \text{Poseidon}_\text{Tachyon-PoolChn}(\mathsf{chain}_{n-1} \|
/// n \| x(\mathsf{block\_commit}_n) \| y(\mathsf{block\_commit}_n))$$
///
/// Anchors expose `chain_n` so any verifier with a known prior `chain_{n-1}`
/// can reach the same value, and so two proofs at the same anchor are
/// bound to the same per-block history. Each advance binds the height into
/// the hash so a chain "at height N" can only be reached by advancing
/// through every height `0..=N`.
///
/// In-memory, a chain produced via [`Self::genesis`] / [`Self::advance`]
/// tracks its tip height so [`Self::advance`] can assert that callers
/// advance one block at a time. Chains reconstructed from bytes (e.g. an
/// `Anchor` decoded from the wire) carry no tip, and advancing from such a
/// chain panics.
#[derive(Clone, Copy, Debug)]
pub struct PoolChain {
    hash: Fp,
    /// `None` for the genesis chain (pre-block-0) and for chains
    /// reconstructed from wire bytes; `Some(h)` after advancing through
    /// height `h`.
    tip: Option<BlockHeight>,
}

impl PoolChain {
    /// Initial chain value before any block has been mined.
    #[must_use]
    pub fn genesis() -> Self {
        let domain = Fp::from_u128(u128::from_le_bytes(*POOL_CHAIN_DOMAIN));
        let hash = Hash::<_, P128Pow5T3, ConstantLength<4>, 3, 2>::init().hash([
            domain,
            Fp::from(0u64),
            Fp::from(0u64),
            Fp::from(0u64),
        ]);
        Self {
            hash,
            tip: Some(BlockHeight(u32::MAX)),
        }
    }

    /// Advance the chain by exactly one block.
    ///
    /// `expected_next_height` must equal `self.tip.0 + 1` (or `0` from
    /// genesis). The height is also folded into the chain hash so that any
    /// chain at height `n` cryptographically binds the entire ordered
    /// sequence of heights `0..=n`.
    ///
    /// Panics if the prior tip is unknown (e.g. the chain was reconstructed
    /// from wire bytes) or if the expected height doesn't follow the prior
    /// tip by one — chains must be advanced one block at a time.
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "advancing from an unknown tip is a programmer error"
    )]
    pub fn advance(self, expected_next_height: BlockHeight, block_commit: &BlockCommit) -> Self {
        let tip = self.tip.expect("advance from a chain with unknown tip");
        let next_expected = BlockHeight(tip.0.wrapping_add(1));
        assert_eq!(
            expected_next_height, next_expected,
            "PoolChain must advance exactly one block at a time",
        );

        let domain = Fp::from_u128(u128::from_le_bytes(*POOL_CHAIN_DOMAIN));
        let point = block_commit.0.inner();
        let coords = point
            .coordinates()
            .expect("block commit should be a valid curve point");
        let (x, y) = (
            Fp::from_repr(coords.x().to_repr()).expect("interpret as Fp"),
            Fp::from_repr(coords.y().to_repr()).expect("interpret as Fp"),
        );
        let hash = Hash::<_, P128Pow5T3, ConstantLength<5>, 3, 2>::init().hash([
            domain,
            self.hash,
            Fp::from(u64::from(expected_next_height.0)),
            x,
            y,
        ]);
        Self {
            hash,
            tip: Some(expected_next_height),
        }
    }
}

impl PartialEq for PoolChain {
    fn eq(&self, other: &Self) -> bool {
        // The cryptographic identity is the hash; tips track only prover
        // hygiene and aren't part of the wire / verifier view.
        self.hash == other.hash
    }
}

impl Eq for PoolChain {}

impl From<&PoolChain> for Fp {
    fn from(chain: &PoolChain) -> Self {
        chain.hash
    }
}

impl From<PoolChain> for [u8; 32] {
    fn from(chain: PoolChain) -> Self {
        chain.hash.to_repr()
    }
}

impl TryFrom<&[u8; 32]> for PoolChain {
    type Error = &'static str;

    fn try_from(bytes: &[u8; 32]) -> Result<Self, Self::Error> {
        let hash: Fp = Option::from(Fp::from_repr(*bytes)).ok_or("invalid field element")?;
        Ok(Self { hash, tip: None })
    }
}
