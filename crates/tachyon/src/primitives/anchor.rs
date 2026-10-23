use corez::io::{self, Read, Write};
use derive_more::{Debug, Display, Eq as TotalEq, Error, From, Into, PartialEq};
use ff::Field as _;
use group::{Curve as _, Group as _};
use lazy_static::lazy_static;
use pasta_curves::{Eq, Fp};

use super::{EpochIndex, TachygramSetCommit};
use crate::{digest::poseidon, serialization};

lazy_static! {
    static ref ANCHOR_GENESIS: Fp = poseidon::anchor_next_epoch(Fp::ZERO, Fp::ZERO);
}

/// Errors that can occur when advancing an anchor.
#[derive(Debug, Display, Error, PartialEq, TotalEq)]
pub enum AnchorError {
    /// The provided tachygram set is the identity point.
    #[display("next stamp cannot be the identity point")]
    NextStampZero,
    /// The provided tachygram set is empty.
    #[display("next stamp cannot be empty")]
    NextStampEmpty,
    /// The provided epoch index is zero.
    #[display("next epoch cannot be zero")]
    NextEpochZero,
}

/// Running anchor over the consensus state.
#[derive(Clone, Copy, Debug, From, Into, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct Anchor(pub Fp);

impl Anchor {
    /// Advance the anchor by absorbing one stamp and the epoch of the block
    /// that contains it.
    ///
    /// The containing epoch index may be zero, within the genesis epoch.
    ///
    /// # Errors
    ///
    /// Fails if `stamp_commit` is the identity point or a commitment to an
    /// empty set.
    pub fn next_stamp(
        self,
        epoch: EpochIndex,
        &stamp_commit: &TachygramSetCommit,
    ) -> Result<Self, AnchorError> {
        if *stamp_commit.as_ref() == Eq::identity() {
            Err(AnchorError::NextStampZero)
        } else if stamp_commit == TachygramSetCommit::default() {
            Err(AnchorError::NextStampEmpty)
        } else {
            Ok(Self(poseidon::anchor_next_stamp(
                self.0,
                epoch.into(),
                stamp_commit.as_ref().to_affine(),
            )))
        }
    }

    /// Advance the anchor into `epoch` with a boundary digest.
    ///
    /// # Errors
    ///
    /// Fails if `epoch` is zero.
    pub fn next_epoch(self, epoch: EpochIndex) -> Result<Self, AnchorError> {
        if epoch == EpochIndex::new(0) {
            Err(AnchorError::NextEpochZero)
        } else {
            Ok(Self(poseidon::anchor_next_epoch(self.0, epoch.into())))
        }
    }

    /// Read a 32-byte anchor.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or the bytes are not a canonical
    /// field element.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        serialization::read_fp(&mut reader).map(Self)
    }

    /// Write a 32-byte anchor.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_fp(&mut writer, &self.0)
    }
}

impl Default for Anchor {
    /// The entry anchor of epoch zero is `H_epoch(0, 0)`. Its fold input is
    /// zero, which is no chain vertex; [`Anchor::next_epoch`] rejects index
    /// zero, so no crossing produces it.
    fn default() -> Self {
        Self(*ANCHOR_GENESIS)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::iter;

    use pasta_curves::Eq;
    use proptest::prelude::*;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{Tachygram, TachygramSetPoly, constants::EPOCH_MAX, testing::check};

    /// A stamp fold binds the order of the stamps and the epoch each was
    /// folded at.
    #[test]
    fn a_stamp_fold_binds_order_and_epoch() {
        let strategy = (
            any::<u64>(),
            0..=EPOCH_MAX,
            0..=EPOCH_MAX,
            [1usize..=4, 1usize..=4],
        );
        check(256, strategy, |(seed, epoch_index, other_index, sizes)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let anchor = Anchor(Fp::random(&mut *rng));
            let [first, second] = sizes.map(|size| {
                iter::repeat_with(|| Tachygram::random(&mut *rng))
                    .take(size)
                    .collect::<TachygramSetPoly>()
                    .commit()
            });
            let (epoch, other_epoch) = (EpochIndex::new(epoch_index), EpochIndex::new(other_index));
            let fold = |commits: [&TachygramSetCommit; 2], at: EpochIndex| {
                commits
                    .iter()
                    .try_fold(anchor, |acc, commit| acc.next_stamp(at, commit))
                    .unwrap()
            };

            prop_assert_ne!(
                fold([&first, &second], epoch),
                fold([&second, &first], epoch)
            );
            prop_assert_eq!(
                fold([&first, &second], epoch) == fold([&first, &second], other_epoch),
                epoch == other_epoch
            );
            Ok(())
        });
    }

    /// A fold refuses the identity point and the empty set's commitment, at
    /// any anchor and epoch.
    #[test]
    fn a_stamp_fold_refuses_degenerate_sets() {
        check(256, (any::<u64>(), 0..=EPOCH_MAX), |(seed, epoch_index)| {
            let anchor = Anchor(Fp::random(&mut StdRng::seed_from_u64(seed)));
            let epoch = EpochIndex::new(epoch_index);
            let identity = TachygramSetCommit::from(Eq::identity());
            let Err(AnchorError::NextStampZero) = anchor.next_stamp(epoch, &identity) else {
                panic!("the identity point is not a stamp");
            };
            let empty = Vec::<Tachygram>::new()
                .into_iter()
                .collect::<TachygramSetPoly>()
                .commit();
            prop_assert_eq!(empty, TachygramSetCommit::default());
            let Err(AnchorError::NextStampEmpty) = anchor.next_stamp(epoch, &empty) else {
                panic!("the empty set is not a stamp");
            };
            Ok(())
        });
    }

    /// A crossing goes into any epoch but zero, and binds which.
    #[test]
    fn a_crossing_enters_any_epoch_but_zero() {
        let strategy = (any::<u64>(), 1..=EPOCH_MAX, 1..=EPOCH_MAX);
        check(256, strategy, |(seed, epoch, other)| {
            let anchor = Anchor(Fp::random(&mut StdRng::seed_from_u64(seed)));
            let Err(AnchorError::NextEpochZero) = anchor.next_epoch(EpochIndex::new(0)) else {
                panic!("no crossing enters epoch zero");
            };
            let [entered, other_entered] =
                [epoch, other].map(|index| anchor.next_epoch(EpochIndex::new(index)).unwrap());
            prop_assert_eq!(entered == other_entered, epoch == other);
            Ok(())
        });
    }
}
