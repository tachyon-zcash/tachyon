extern crate alloc;

use alloc::string::ToString as _;
use core::{array, assert_matches};

use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, EpochIndex, Tachygram, TachygramSetPoly, pasta::EqAffine, stamp::proof::summary,
    witness,
};

use super::fixtures::application;

#[test]
fn summary_advance_folds_stamp_into_accumulator_and_anchor() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let stamp_a: [Tachygram; 3] = array::from_fn(|_| Tachygram::random(rng));
    let stamp_b: [Tachygram; 2] = array::from_fn(|_| Tachygram::random(rng));

    let (seeded, ()) = app
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &stamp_a).unwrap(),
        )
        .unwrap();
    let commit_a = TachygramSetPoly::try_from_roots(stamp_a.iter().copied())
        .unwrap()
        .commit();
    assert_eq!(
        *seeded.data(),
        (epoch, start, start.next_stamp(epoch, &commit_a).unwrap())
    );
    assert_eq!(seeded.commitments()[0], EqAffine::from(commit_a));

    let foreign: [Tachygram; 3] = array::from_fn(|_| Tachygram::random(rng));
    for (advance_witness, expected) in [
        (
            witness::summary_advance((*seeded.data(), ()), &foreign, &stamp_b).unwrap(),
            "an accumulator over foreign tachygrams",
        ),
        (
            {
                let mut witness =
                    witness::summary_advance((*seeded.data(), ()), &stamp_a, &stamp_b).unwrap();
                witness.0 = TachygramSetPoly::try_from_roots(stamp_a).unwrap();
                witness
            },
            "an accumulator that omits the stamp",
        ),
    ] {
        let (forged, ()) = app
            .fuse(
                rng,
                summary::SummaryAdvance,
                advance_witness,
                seeded.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
            "{expected}",
        );
    }

    let (advanced, ()) = app
        .fuse(
            rng,
            summary::SummaryAdvance,
            witness::summary_advance((*seeded.data(), ()), &stamp_a, &stamp_b).unwrap(),
            seeded,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();

    let commit_b = TachygramSetPoly::try_from_roots(stamp_b.iter().copied())
        .unwrap()
        .commit();
    let union = TachygramSetPoly::try_from_roots(stamp_a.iter().chain(stamp_b.iter()).copied())
        .unwrap()
        .commit();
    let expected_end = start
        .next_stamp(epoch, &commit_a)
        .unwrap()
        .next_stamp(epoch, &commit_b)
        .unwrap();
    assert_eq!(*advanced.data(), (epoch, start, expected_end));
    assert_eq!(advanced.commitments()[0], EqAffine::from(union));
    assert!(app.verify_uncompressed(&advanced, rng).unwrap());
}

#[test]
fn summary_seed_rejects_empty_stamp() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let start = Anchor::random(rng);

    assert_matches!(
        app
            .seed(
                rng,
                summary::SummarySeed,
                witness::summary_seed(((), ()), start, EpochIndex::new(3), &[]).unwrap(),
            )
            .err(),
        Some(ragu::Error::InvalidWitness(err)) if err.to_string() == "division by zero"
    );
}
