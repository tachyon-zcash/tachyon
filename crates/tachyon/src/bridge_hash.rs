//! The wallet-basis bridge hash of a set commitment, computed natively.
//!
//! `Anchor::next_stamp` is reached from step code and needs the bridge hash
//! without an application. Ragu's `bridge_hash::digest` computes it from the
//! commitment, the rank and the nested generators; the pinning test compares
//! the result with `Application::bridge_hash`.

use ragu::{AcceleratedProver, Cycle as _, WalletRank, pasta::Pasta, pcd::bridge_hash};

use crate::pasta::{self, EpAffine, EqAffine};

/// Computes the bridge hash of a wallet-rank set commitment.
///
/// # Panics
///
/// Panics if `commitment` is the identity.
pub(crate) fn bridge_hash(commitment: EqAffine) -> EpAffine {
    #[expect(
        clippy::expect_used,
        reason = "no set polynomial commits to the identity, and the bridge stage fits WalletRank"
    )]
    bridge_hash::digest::<AcceleratedProver, _, _, WalletRank, _>(
        commitment,
        Pasta::nested_generators(pasta::baked()),
    )
    .expect("set commitment is not the identity")
}

#[cfg(test)]
mod tests;
