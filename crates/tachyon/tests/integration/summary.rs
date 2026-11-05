extern crate alloc;

use alloc::string::ToString as _;
use core::array;

use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, Tachygram, TachygramSetPoly,
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, summary},
    witness,
};

use crate::fixtures::{PoolSim, build_summary_pcd, random_block};

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
        (
            epoch,
            start,
            start.next_stamp(epoch, &commit_a).unwrap(),
            commit_a
        )
    );

    let (advanced, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            summary::SummaryAdvance,
            witness::summary_advance((*seeded.data(), ()), &stamp_a, &stamp_b),
            seeded,
            Proof::bootstrap().carry::<()>(()),
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
    assert_eq!(*advanced.data(), (epoch, start, expected_end, union));
}

#[test]
fn summary_over_an_anchor_span_matches_the_pool() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));

    let (pcd, members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    let (epoch, anchor_prev, anchor_end, acc_commit) = *pcd.data();

    assert_eq!(epoch, EpochIndex::new(0));
    assert_eq!(anchor_prev, Anchor::default());
    assert_eq!(anchor_end, pool.anchor());

    let acc = members.iter().copied().collect::<TachygramSetPoly>();
    assert_eq!(members.len(), 12);
    assert_eq!(acc_commit, acc.commit());
    for &tg in &members {
        assert_eq!(acc.eval(Fp::from(tg)), Fp::ZERO);
    }
}

#[test]
fn summary_seed_rejects_empty_stamp() {
    let rng = &mut StdRng::seed_from_u64(0);
    let start = Anchor::random(rng);

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.seed(
        rng,
        summary::SummarySeed,
        witness::summary_seed(((), ()), start, EpochIndex::new(3), &[]),
    ) {
        assert_eq!(err.to_string(), "invalid anchor step");
    } else {
        panic!();
    }
}

#[test]
fn summary_advance_rejects_wrong_accumulator() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let stamp_a = [Tachygram::random(rng)];
    let stamp_b = [Tachygram::random(rng)];
    let foreign = [Tachygram::random(rng)];

    let (seeded, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &stamp_a),
        )
        .unwrap();

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        summary::SummaryAdvance,
        witness::summary_advance((*seeded.data(), ()), &foreign, &stamp_b),
        seeded,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "SummaryAdvance: accumulator does not match header"
        );
    } else {
        panic!();
    }
}

#[test]
fn summary_advance_rejects_forged_extension() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let stamp_a = [Tachygram::random(rng)];
    let stamp_b = [Tachygram::random(rng)];

    let (seeded, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &stamp_a),
        )
        .unwrap();

    let (acc, _extended, stamp) =
        witness::summary_advance((*seeded.data(), ()), &stamp_a, &stamp_b);
    let forged = stamp_a.iter().copied().collect::<TachygramSetPoly>();

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        summary::SummaryAdvance,
        (acc, forged, stamp),
        seeded,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "SummaryAdvance: extended accumulator must fold the stamp"
        );
    } else {
        panic!();
    }
}

#[test]
fn summary_seed_on_a_foreign_epoch_leaves_the_chain() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    let first = pool.block(BlockHeight(0));

    let (seeded, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), first.prev, EpochIndex::new(1), &first.stamps[0].1),
        )
        .unwrap();
    let (_, _, anchor_end, _) = *seeded.data();

    for height in 0..=pool.height().0 {
        let block = pool.block(BlockHeight(height));
        assert_ne!(anchor_end, block.prev);
        for &(_, _, _, anchor) in &block.stamps {
            assert_ne!(anchor_end, anchor);
        }
    }
}
