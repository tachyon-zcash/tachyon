use core::assert_matches;

use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{Tachygram, TachygramSetCommit, TachygramSetPoly};

#[test]
fn next_stamp_binds_the_order_and_the_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let first = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
    let second = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
    let first_hash = first.bridge().unwrap();
    let second_hash = second.bridge().unwrap();
    let empty_hash = TachygramSetCommit::default().bridge().unwrap();

    let forward = Anchor::default()
        .next_stamp(EpochIndex::new(7), first_hash, empty_hash)
        .unwrap();
    assert_ne!(
        forward,
        Anchor::default()
            .next_stamp(EpochIndex::new(8), first_hash, empty_hash)
            .unwrap()
    );
    assert_ne!(
        forward
            .next_stamp(EpochIndex::new(7), second_hash, empty_hash)
            .unwrap(),
        Anchor::default()
            .next_stamp(EpochIndex::new(7), second_hash, empty_hash)
            .unwrap()
            .next_stamp(EpochIndex::new(7), first_hash, empty_hash)
            .unwrap()
    );
}

#[test]
fn anchor_steps_reject_degenerate_inputs() {
    let anchor = Anchor::random(&mut StdRng::seed_from_u64(0));
    let empty_hash = TachygramSetCommit::default().bridge().unwrap();
    assert_matches!(
        anchor.next_stamp(EpochIndex::new(7), empty_hash, empty_hash),
        Err(AnchorError::NextStampEmpty)
    );
    assert_matches!(
        anchor.next_epoch(EpochIndex::new(0)),
        Err(AnchorError::NextEpochZero)
    );
}
