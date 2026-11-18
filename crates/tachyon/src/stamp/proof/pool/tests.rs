use alloc::{string::ToString as _, vec};
use core::assert_matches;

use ragu::Polynomial;
use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{stamp::proof::new_application, witness};

#[test]
fn anchor_span_seed_proves_a_stamp_and_refuses_an_empty_one() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let epoch = EpochIndex::new(3);
    let stamp = witness::anchor_span_seed(((), ()), anchor, epoch, &[Tachygram::random(rng)]);

    let (span, ()) = app.seed(rng, AnchorSpanSeed, stamp).unwrap();
    assert!(app.verify_uncompressed(&span, &mut *rng).unwrap());

    assert_matches!(
        app.seed(
            rng,
            AnchorSpanSeed,
            witness::anchor_span_seed(((), ()), anchor, epoch, &[]),
        )
        .err(),
        Some(ragu::Error::InvalidWitness(err)) if err.to_string() == "division by zero"
    );
}

#[test]
#[should_panic(expected = "tachygram set commitment is not the identity")]
fn anchor_span_seed_panics_on_an_identity_commitment() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let stamp = TachygramSetPoly::arbitrary(Polynomial::from_coeffs(vec![Fp::ZERO]));
    let _span = app.seed(rng, AnchorSpanSeed, (anchor, EpochIndex::new(3), stamp));
}
