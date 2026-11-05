use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{Tachygram, TachygramSetPoly, pasta::Eq};

#[test]
fn order_matters() {
    let rng = &mut StdRng::seed_from_u64(0);
    let first = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();
    let second = TachygramSetPoly::from_iter([Tachygram::random(&mut *rng)]).commit();

    let forward = Anchor::default()
        .next_stamp(EpochIndex::new(7), &first)
        .unwrap()
        .next_stamp(EpochIndex::new(7), &second)
        .unwrap();

    let reverse = Anchor::default()
        .next_stamp(EpochIndex::new(7), &second)
        .unwrap()
        .next_stamp(EpochIndex::new(7), &first)
        .unwrap();

    assert_ne!(forward, reverse);
}

#[test]
fn next_stamp_rejects_the_identity_set() {
    let anchor = Anchor::random(&mut StdRng::seed_from_u64(0));
    let zero_set = TachygramSetCommit::from(Eq::identity());
    let Err(AnchorError::NextStampZero) = anchor.next_stamp(EpochIndex::new(7), &zero_set) else {
        panic!();
    };
}

#[test]
fn next_stamp_rejects_the_empty_set() {
    let anchor = Anchor::random(&mut StdRng::seed_from_u64(0));
    let one_set = TachygramSetCommit::default();
    let Err(AnchorError::NextStampEmpty) = anchor.next_stamp(EpochIndex::new(1), &one_set) else {
        panic!();
    };
}

#[test]
fn next_epoch_rejects_epoch_zero() {
    let anchor = Anchor::random(&mut StdRng::seed_from_u64(0));
    let Err(AnchorError::NextEpochZero) = anchor.next_epoch(EpochIndex::new(0)) else {
        panic!();
    };
}
