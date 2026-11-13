use super::*;
use crate::primitives::TachygramSetCommit;

#[test]
fn empty_stamp_bridge_hash_matches_application() {
    let expected = pasta::EpAffine::from(TachygramSetCommit::default().bridge().unwrap())
        .coordinates()
        .unwrap();
    assert_eq!(*EMPTY_STAMP_BRIDGE_HASH, <[pasta::Fp; 2]>::from(expected));
}
