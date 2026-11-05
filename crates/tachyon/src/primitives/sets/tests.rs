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
