use alloc::vec::Vec;
use core::iter;

use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{Tachygram, TachygramSetPoly, constants::EPOCH_MAX, pasta::Eq};

#[test]
fn a_stamp_fold_binds_order_and_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (sizes, epoch_index, other_index) in [
        ([1, 1], 0, EPOCH_MAX),
        ([1, 4], 96, 97),
        ([4, 2], EPOCH_MAX, EPOCH_MAX),
    ] {
        let anchor = Anchor::random(rng);
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

        assert_ne!(
            fold([&first, &second], epoch),
            fold([&second, &first], epoch),
            "sizes {sizes:?} at {epoch_index}: the order"
        );
        assert_eq!(
            fold([&first, &second], epoch) == fold([&first, &second], other_epoch),
            epoch == other_epoch,
            "sizes {sizes:?}: epochs {epoch_index} and {other_index}"
        );
    }
}

#[test]
fn a_stamp_fold_refuses_degenerate_sets() {
    let anchor = Anchor::random(&mut StdRng::seed_from_u64(0));
    let empty = Vec::<Tachygram>::new()
        .into_iter()
        .collect::<TachygramSetPoly>()
        .commit();
    assert_eq!(empty, TachygramSetCommit::default());
    let identity = TachygramSetCommit::from(Eq::identity());
    for epoch_index in [0, EPOCH_MAX] {
        let epoch = EpochIndex::new(epoch_index);
        let Err(AnchorError::NextStampZero) = anchor.next_stamp(epoch, &identity) else {
            panic!("epoch {epoch_index}: the identity point is not a stamp");
        };
        let Err(AnchorError::NextStampEmpty) = anchor.next_stamp(epoch, &empty) else {
            panic!("epoch {epoch_index}: the empty set is not a stamp");
        };
    }
}

#[test]
fn a_crossing_enters_any_epoch_but_zero() {
    let anchor = Anchor::random(&mut StdRng::seed_from_u64(0));
    let Err(AnchorError::NextEpochZero) = anchor.next_epoch(EpochIndex::new(0)) else {
        panic!("no crossing enters epoch zero");
    };
    for (epoch, other) in [(1, 1), (1, 2), (1, EPOCH_MAX), (EPOCH_MAX, EPOCH_MAX)] {
        let [entered, other_entered] =
            [epoch, other].map(|index| anchor.next_epoch(EpochIndex::new(index)).unwrap());
        assert_eq!(
            entered == other_entered,
            epoch == other,
            "epochs {epoch} and {other}"
        );
    }
}
