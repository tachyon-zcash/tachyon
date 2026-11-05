use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{Tachygram, TachygramSetPoly, pasta::Eq};

#[test]
fn next_stamp_binds_the_order_and_the_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let first = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
    let second = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();

    let forward = Anchor::default()
        .next_stamp(EpochIndex::new(7), &first)
        .unwrap();
    assert_ne!(
        forward,
        Anchor::default()
            .next_stamp(EpochIndex::new(8), &first)
            .unwrap()
    );
    assert_ne!(
        forward.next_stamp(EpochIndex::new(7), &second).unwrap(),
        Anchor::default()
            .next_stamp(EpochIndex::new(7), &second)
            .unwrap()
            .next_stamp(EpochIndex::new(7), &first)
            .unwrap()
    );
}

#[test]
fn anchor_steps_reject_degenerate_inputs() {
    let anchor = Anchor::random(&mut StdRng::seed_from_u64(0));
    let zero_set = TachygramSetCommit::from(Eq::identity());
    let Err(AnchorError::NextStampZero) = anchor.next_stamp(EpochIndex::new(7), &zero_set) else {
        panic!();
    };
    let Err(AnchorError::NextEpochZero) = anchor.next_epoch(EpochIndex::new(0)) else {
        panic!();
    };
}
