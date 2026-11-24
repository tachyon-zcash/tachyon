use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    stamp::proof::{historical::new_application as historical_application, new_application},
    witness,
};

#[test]
fn anchor_span_seed_proves_a_stamp() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let epoch = EpochIndex::new(3);
    let unit = app.commit(&[Fp::ONE]).unwrap();
    for _ in 0..2 {
        let stamp = witness::anchor_span_seed(((), ()), anchor, epoch, &[Tachygram::random(rng)]);
        let commitment = stamp.2.commit();
        let end = anchor.next_stamp(epoch, &commitment).unwrap();
        let (span, ()) = app.seed(rng, AnchorSpanSeed, stamp).unwrap();
        assert_eq!(
            span.data(),
            &(anchor, end, app.bridge_hash(unit).unwrap().into())
        );
        assert_eq!(span.commitments()[1], commitment.into());
        assert!(app.verify_uncompressed(&span, &mut *rng).unwrap());
    }
}

#[test]
fn historical_span_cannot_be_relabelled_for_dehydration() {
    let old = historical_application().unwrap();
    let current = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(14);
    let start = Anchor::random(rng);
    let stamp = witness::anchor_span_seed(
        ((), ()),
        start,
        EpochIndex::new(0),
        &[Tachygram::random(rng)],
    );
    let (span, ()) = old.seed(rng, historical::AnchorSpanSeed, stamp).unwrap();
    let proof = old.compress(&span, &mut *rng).unwrap();
    assert!(old.verify_compressed(&proof).unwrap());
    let (frame, (previous, end)) = proof.into_parts();
    let unit = current.commit(&[Fp::ONE]).unwrap();
    let fields = (previous, end, current.bridge_hash(unit).unwrap().into());
    assert!(
        !current
            .verify_compressed(&frame.clone().carry::<AnchorSpan>(fields))
            .unwrap()
    );
    assert!(
        !current
            .verify_compressed(&frame.carry::<PublicAnchorSpan>(fields))
            .unwrap()
    );
}

#[test]
fn anchor_span_seed_refuses_an_empty_stamp() {
    let app = new_application().unwrap();
    let rng = &mut StdRng::seed_from_u64(0);
    let stamp = witness::anchor_span_seed(((), ()), Anchor::random(rng), EpochIndex::new(3), &[]);

    assert!(app.seed(rng, AnchorSpanSeed, stamp).is_err());
}
