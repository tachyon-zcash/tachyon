extern crate alloc;
use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::{Fp, arithmetic::CurveAffine as _};

use super::TachygramSetCommit;
use crate::{Tachygram, digest::poseidon};

/// Running hash of the block-state chain: absorbs each stamp commit in landing
/// order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubBlock(pub Fp);

impl SubBlock {
    /// Advance the block-state by absorbing one stamp commit.
    ///
    /// # Panics
    ///
    /// Panics if `stamp_commit` is the identity point.
    #[must_use]
    pub fn next(self, stamp_commit: &TachygramSetCommit) -> Self {
        let point = stamp_commit.0.inner();

        let coords = point
            .coordinates()
            .expect("must not be identity commitment");

        Self(poseidon::subblock_step(self.0, coords))
    }
}

impl Default for SubBlock {
    fn default() -> Self {
        Self(Fp::ZERO)
    }
}

impl From<&[TachygramSetCommit]> for SubBlock {
    fn from(stamps: &[TachygramSetCommit]) -> Self {
        let mut state = Self::default();
        for stamp in stamps {
            state = state.next(stamp);
        }
        state
    }
}

impl From<&Vec<Vec<Tachygram>>> for SubBlock {
    fn from(stamps: &Vec<Vec<Tachygram>>) -> Self {
        let mut state = Self::default();
        for stamp_tgs in stamps {
            state = state.next(&TachygramSetCommit::from(stamp_tgs.as_slice()));
        }
        state
    }
}

#[cfg(test)]
mod tests {
    use mock_ragu::{Multiset, Polynomial};

    use super::*;

    fn commit_of(roots: &[u64]) -> TachygramSetCommit {
        let fps: Vec<Fp> = roots.iter().copied().map(Fp::from).collect();
        TachygramSetCommit(Multiset::new(Polynomial::from_roots(&fps)).commit())
    }

    /// Folding the same stamps in the same order yields the same state.
    #[test]
    fn next_is_deterministic() {
        let first = commit_of(&[1, 2, 3]);
        let second = commit_of(&[4, 5, 6]);

        let run_one = SubBlock::default().next(&first).next(&second);
        let run_two = SubBlock::default().next(&first).next(&second);
        assert_eq!(run_one, run_two);
    }

    /// Two distinct stamp commits absorb to distinct block states.
    #[test]
    fn distinct_stamps_distinct_states() {
        let first = commit_of(&[1, 2, 3]);
        let second = commit_of(&[4, 5, 6]);

        assert_ne!(
            SubBlock::default().next(&first),
            SubBlock::default().next(&second),
        );
    }

    /// Order matters: absorbing the same stamps in different orders diverges.
    #[test]
    fn order_matters() {
        let first = commit_of(&[1, 2, 3]);
        let second = commit_of(&[4, 5, 6]);

        let forward = SubBlock::default().next(&first).next(&second);
        let reverse = SubBlock::default().next(&second).next(&first);
        assert_ne!(forward, reverse);
    }
}
