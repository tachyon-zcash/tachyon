use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{stamp::proof::new_application, witness};

#[test]
fn anchor_span_seed_proves_a_stamp() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let epoch = EpochIndex::new(3);
    let stamp = witness::anchor_span_seed(((), ()), anchor, epoch, &[Tachygram::random(rng)]);

    let (span, ()) = app.seed(rng, AnchorSpanSeed, stamp).unwrap();
    assert!(app.verify_uncompressed(&span, &mut *rng).unwrap());
}

#[test]
fn anchor_span_seed_refuses_an_empty_stamp() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let stamp = witness::anchor_span_seed(((), ()), Anchor::random(rng), EpochIndex::new(3), &[]);

    assert!(app.seed(rng, AnchorSpanSeed, stamp).is_err());
}
