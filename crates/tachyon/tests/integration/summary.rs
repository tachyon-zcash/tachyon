extern crate alloc;

use alloc::string::ToString as _;
use core::{array, assert_matches};

use rand::{SeedableRng as _, rngs::StdRng};
use udon::curve::Projective as _;
use zcash_tachyon::{
    Anchor, EpochIndex, Tachygram, TachygramSetPoly,
    pasta::Eq,
    stamp::proof::{PROOF_SYSTEM, summary},
    witness,
};

#[test]
fn summary_advance_folds_stamp_into_accumulator_and_anchor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let stamp_a: [Tachygram; 3] = array::from_fn(|_| Tachygram::random(rng));
    let stamp_b: [Tachygram; 2] = array::from_fn(|_| Tachygram::random(rng));

    let (seeded, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &stamp_a),
        )
        .unwrap();
    let commit_a = stamp_a
        .iter()
        .copied()
        .collect::<TachygramSetPoly>()
        .commit();
    assert_eq!(
        *seeded.data(),
        (epoch, start, start.next_stamp(epoch, &commit_a).unwrap())
    );
    assert_eq!(seeded.commitments()[0], Eq::from(commit_a).to_affine());

    let foreign: [Tachygram; 3] = array::from_fn(|_| Tachygram::random(rng));
    for (advance_witness, expected) in [
        (
            witness::summary_advance((*seeded.data(), ()), &foreign, &stamp_b),
            "SummaryAdvance: extended accumulator must fold the stamp",
        ),
        (
            {
                let mut witness =
                    witness::summary_advance((*seeded.data(), ()), &stamp_a, &stamp_b);
                witness.0 = stamp_a.iter().copied().collect();
                witness
            },
            "SummaryAdvance: extended accumulator must fold the stamp",
        ),
    ] {
        assert_matches!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    summary::SummaryAdvance,
                    advance_witness,
                    seeded.clone(),
                    PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
    }

    let (advanced, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            summary::SummaryAdvance,
            witness::summary_advance((*seeded.data(), ()), &stamp_a, &stamp_b),
            seeded,
            PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();

    let commit_b = stamp_b
        .iter()
        .copied()
        .collect::<TachygramSetPoly>()
        .commit();
    let union = stamp_a
        .iter()
        .chain(stamp_b.iter())
        .copied()
        .collect::<TachygramSetPoly>()
        .commit();
    let expected_end = start
        .next_stamp(epoch, &commit_a)
        .unwrap()
        .next_stamp(epoch, &commit_b)
        .unwrap();
    assert_eq!(*advanced.data(), (epoch, start, expected_end));
    assert_eq!(advanced.commitments()[0], Eq::from(union).to_affine());
}

#[test]
fn summary_seed_rejects_empty_stamp() {
    let rng = &mut StdRng::seed_from_u64(0);
    let start = Anchor::random(rng);

    assert_matches!(
        PROOF_SYSTEM
            .seed(
                rng,
                summary::SummarySeed,
                witness::summary_seed(((), ()), start, EpochIndex::new(3), &[]),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == "invalid anchor step"
    );
}
