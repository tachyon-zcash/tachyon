use corez::io::{self, Read, Write};
use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use group::Curve as _;
use pasta_curves::{Eq, Fp};

use super::{EpochIndex, TachygramSetCommit};
use crate::{digest::poseidon, serialization};

/// Running anchor over the consensus state.
///
/// A Poseidon hash sequence with two domain-separated link types:
///
/// - [`Anchor::next_stamp`] (`Tachyon-StampFld`) absorbs one stamp's epoch and
///   tachygram-set commitment.
/// - [`Anchor::next_epoch`] (`Tachyon-EpochStp`) lifts across an epoch
///   boundary. `EndEpochUnspentSeed` is the only step that folds it, from a
///   predecessor it does not constrain to be the epoch's terminal anchor.
///
/// A block that publishes no stamp contributes no link, so the anchor is
/// constant across a stampless span.
///
/// Opening reveals each link's role by its domain.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct Anchor(pub Fp);

impl Anchor {
    /// Advance the anchor by absorbing one stamp's commit, bound to the epoch
    /// of the block containing it.
    ///
    /// # Panics
    ///
    /// Panics if `stamp_commit` is the identity point.
    #[must_use]
    pub fn next_stamp(self, epoch: EpochIndex, stamp_commit: &TachygramSetCommit) -> Self {
        Self(poseidon::anchor_stamp_step(
            self.0,
            epoch,
            Eq::from(*stamp_commit).to_affine(),
        ))
    }

    /// Lift the anchor across an epoch boundary into the new epoch's
    /// initial state.
    #[must_use]
    pub fn next_epoch(self, new_epoch: EpochIndex) -> Self {
        Self(poseidon::anchor_epoch_step(self.0, new_epoch))
    }

    /// Read a 32-byte anchor.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        serialization::read_fp(&mut reader).map(Self)
    }

    /// Write a 32-byte anchor.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_fp(&mut writer, &self.0)
    }
}

impl Default for Anchor {
    /// The genesis epoch boundary.
    fn default() -> Self {
        Self(Fp::ZERO).next_epoch(EpochIndex(0))
    }
}

#[cfg(test)]
mod tests {
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{Tachygram, TachygramSetPoly};

    const EPOCH: EpochIndex = EpochIndex(7);

    /// Folding the same stamps in the same order yields the same anchor.
    #[test]
    fn next_stamp_is_deterministic() {
        let rng = &mut StdRng::seed_from_u64(0);
        let first = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
        let second = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();

        let run_one = Anchor::default()
            .next_stamp(EPOCH, &first)
            .next_stamp(EPOCH, &second);
        let run_two = Anchor::default()
            .next_stamp(EPOCH, &first)
            .next_stamp(EPOCH, &second);
        assert_eq!(run_one, run_two);
    }

    /// Two distinct stamp commits absorb to distinct anchors.
    #[test]
    fn distinct_stamps_distinct_anchors() {
        let rng = &mut StdRng::seed_from_u64(0);
        let first = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
        let second = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();

        assert_ne!(
            Anchor::default().next_stamp(EPOCH, &first),
            Anchor::default().next_stamp(EPOCH, &second),
        );
    }

    /// Order matters: absorbing the same stamps in different orders diverges.
    #[test]
    fn order_matters() {
        let rng = &mut StdRng::seed_from_u64(0);
        let first = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
        let second = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();

        let forward = Anchor::default()
            .next_stamp(EPOCH, &first)
            .next_stamp(EPOCH, &second);
        let reverse = Anchor::default()
            .next_stamp(EPOCH, &second)
            .next_stamp(EPOCH, &first);
        assert_ne!(forward, reverse);
    }

    /// Every link binds its epoch: the same tick in two epochs diverges.
    #[test]
    fn epoch_distinguishes_ticks() {
        let rng = &mut StdRng::seed_from_u64(0);
        let stamp = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
        let start = Anchor::default();

        assert_ne!(
            start.next_stamp(EpochIndex(1), &stamp),
            start.next_stamp(EpochIndex(2), &stamp),
        );
        assert_ne!(
            start.next_epoch(EpochIndex(1)),
            start.next_epoch(EpochIndex(2))
        );
    }

    /// The boundary lift is domain-separated from stamp absorption, so a
    /// boundary anchor is unreachable by any chain link.
    #[test]
    fn next_epoch_distinct_from_next_stamp() {
        let rng = &mut StdRng::seed_from_u64(0);
        let stamp = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
        let via_epoch = Anchor::default().next_epoch(EPOCH);
        let via_stamp = Anchor::default().next_stamp(EPOCH, &stamp);
        assert_ne!(via_epoch, via_stamp);
    }
}
