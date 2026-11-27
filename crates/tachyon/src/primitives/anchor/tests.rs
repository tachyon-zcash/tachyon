use core::assert_matches;

use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{Tachygram, TachygramSetCommit, TachygramSetPoly, pasta::EqAffine};

#[test]
fn next_stamp_binds_the_order_and_the_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let first = TachygramSetPoly::try_from_roots([Tachygram::random(&mut *rng)])
        .unwrap()
        .commit();
    let second = TachygramSetPoly::try_from_roots([Tachygram::random(&mut *rng)])
        .unwrap()
        .commit();

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
    assert_matches!(
        anchor.next_stamp(
            EpochIndex::new(7),
            &TachygramSetCommit::from(EqAffine::identity())
        ),
        Err(AnchorError::NextStampZero)
    );
    assert_matches!(
        anchor.next_stamp(EpochIndex::new(7), &TachygramSetCommit::default()),
        Err(AnchorError::NextStampEmpty)
    );
    assert_matches!(
        anchor.next_epoch(EpochIndex::new(0)),
        Err(AnchorError::NextEpochZero)
    );
}
