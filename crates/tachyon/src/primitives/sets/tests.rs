use alloc::vec::Vec;

use rand::{SeedableRng as _, rngs::StdRng};

use super::*;

#[test]
fn singleton_commits_to_the_one_member_set() {
    let anchor = Anchor::random(&mut StdRng::seed_from_u64(0));
    assert_eq!(
        AnchorSetCommit::singleton(anchor),
        AnchorSetPoly::from_iter([anchor]).commit()
    );
}

#[test]
fn tachygrams_and_their_set_commitments_round_trip() {
    let tachygram = Tachygram::random(&mut StdRng::seed_from_u64(0));
    let commit = TachygramSetPoly::from_iter([tachygram]).commit();
    let mut wire = Vec::new();
    tachygram.write(&mut wire).unwrap();
    commit.write(&mut wire).unwrap();
    let mut reader = wire.as_slice();
    assert_eq!(
        Tachygram::read(&mut reader).unwrap(),
        tachygram,
        "tachygram"
    );
    assert_eq!(
        TachygramSetCommit::read(&mut reader).unwrap(),
        commit,
        "set commitment"
    );
    assert!(reader.is_empty(), "nothing left unread");
}
