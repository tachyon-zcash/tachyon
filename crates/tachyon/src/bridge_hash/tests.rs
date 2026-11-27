use ragu::udon::curve::Affine as _;

use super::bridge_hash;
use crate::{
    pasta::{EqAffine, Fp},
    primitives::{Tachygram, TachygramSetCommit, TachygramSetPoly},
    stamp::proof::new_application,
};

#[test]
fn bridge_hash_matches_application() {
    let app = new_application().unwrap();
    for commitment in [
        TachygramSetCommit::default(),
        TachygramSetPoly::try_from_roots([Tachygram::from(Fp::from(7))])
            .unwrap()
            .commit(),
        TachygramSetPoly::try_from_roots([
            Tachygram::from(Fp::from(3)),
            Tachygram::from(Fp::from(19)),
        ])
        .unwrap()
        .commit(),
    ] {
        let point = commitment.into();
        assert_eq!(bridge_hash(point), app.bridge_hash(point).unwrap());
    }
}

#[test]
#[should_panic(expected = "tachygram set commitment is not the identity")]
fn bridge_hash_panics_on_the_identity() {
    let _bridge = bridge_hash(EqAffine::identity());
}
