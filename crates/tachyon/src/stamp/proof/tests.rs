use ragu_core::pasta::Pasta;
use ragu_pcd::profile::{Profile, ProfiledCycle};
use udon::curve::Projective as _;

use super::bridge_hash;
use crate::{
    pasta::{Eq, Fp},
    primitives::{Tachygram, TachygramSetCommit, TachygramSetPoly},
    stamp::proof::new_application,
};

#[test]
fn application_profile_excludes_decompression() {
    // Ragu registers Decompress exactly when this statement circuit exists.
    // Its constant-one output slots do not preserve our non-membership checks.
    assert!(
        <<Pasta as ProfiledCycle>::Profile as Profile>::native_extension()
            .statement
            .is_none(),
        "Tachyon requires a profile without Decompress; statement support needs a slot-preservation audit",
    );
}

#[test]
fn bridge_hash_matches_application() {
    let app = new_application().unwrap();
    for commitment in [
        TachygramSetCommit::default(),
        TachygramSetPoly::from_iter([Tachygram::from(Fp::from(7))]).commit(),
        TachygramSetPoly::from_iter([Tachygram::from(Fp::from(3)), Tachygram::from(Fp::from(19))])
            .commit(),
    ] {
        let point = commitment.as_ref().to_affine();
        assert_eq!(bridge_hash(point), app.bridge_hash(point).unwrap());
    }
}

#[test]
#[should_panic(expected = "tachygram set commitment is not the identity")]
fn bridge_hash_panics_on_the_identity() {
    let _bridge = bridge_hash(Eq::identity().to_affine());
}
