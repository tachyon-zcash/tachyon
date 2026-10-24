//! `SummarySeed` and `SummaryAdvance`: a run of stamps in one polynomial.

extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::Fp;
use proptest::{collection::vec, prelude::*};
use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, Tachygram, TachygramSetPoly,
    stamp::proof::{PROOF_SYSTEM, summary},
    witness,
};

use crate::{
    fixtures::PoolSim,
    strategies::{assert_rejections, check, epoch, tachygrams},
};

/// A summary seeded at any anchor and epoch, then advanced over a run of
/// nonempty stamps, holds their union as one set polynomial and ends at the
/// anchor their folds reach.
#[test]
fn summary_accumulates_its_run() {
    let strategy = (any::<u64>(), epoch(), vec(1usize..=4, 1..=4));
    check(16, strategy, |(seed, epoch, sizes)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let start = Anchor::from(Fp::random(&mut *rng));
        let stamps: Vec<Vec<Tachygram>> = sizes.iter().map(|&size| tachygrams(rng, size)).collect();

        let (first, rest) = stamps.split_first().expect("a nonempty run");
        let (mut pcd, ()) = PROOF_SYSTEM
            .seed(
                rng,
                summary::SummarySeed,
                witness::summary_seed(((), ()), start, epoch, first),
            )
            .expect("SummarySeed");
        let mut acc = first.clone();
        for stamp in rest {
            let (advanced, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    summary::SummaryAdvance,
                    witness::summary_advance((*pcd.data(), ()), &acc, stamp),
                    pcd,
                    Proof::trivial().carry::<()>(()),
                )
                .expect("SummaryAdvance");
            acc.extend(stamp.iter().copied());
            pcd = advanced;
        }

        let end = stamps.iter().fold(start, |anchor, stamp| {
            let commit = stamp.iter().copied().collect::<TachygramSetPoly>().commit();
            anchor
                .next_stamp(epoch, &commit)
                .expect("a nonempty stamp folds")
        });
        let union = acc.iter().copied().collect::<TachygramSetPoly>();
        prop_assert_eq!(*pcd.data(), (epoch, start, end, union.commit()));
        for &member in &acc {
            prop_assert_eq!(union.eval(Fp::from(member)), Fp::ZERO);
        }
        Ok(())
    });
}

/// An empty stamp does not seed, and an advance whose accumulator is not the
/// header's, or whose extension drops the stamp, is refused.
#[test]
fn summary_steps_reject_corruptions() {
    let strategy = (any::<u64>(), epoch(), 1usize..=4, 1usize..=4);
    check(16, strategy, |(seed, epoch, size_a, size_b)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let start = Anchor::from(Fp::random(&mut *rng));
        let (stamp_a, stamp_b) = (tachygrams(rng, size_a), tachygrams(rng, size_b));
        let foreign = tachygrams(rng, size_a);

        let (seeded, ()) = PROOF_SYSTEM
            .seed(
                rng,
                summary::SummarySeed,
                witness::summary_seed(((), ()), start, epoch, &stamp_a),
            )
            .expect("SummarySeed");
        let advance = |advance_rng: &mut StdRng, advance_witness| {
            PROOF_SYSTEM
                .fuse(
                    advance_rng,
                    summary::SummaryAdvance,
                    advance_witness,
                    seeded.clone(),
                    Proof::trivial().carry::<()>(()),
                )
                .map(drop)
        };
        let (acc, _extended, stamp) =
            witness::summary_advance((*seeded.data(), ()), &stamp_a, &stamp_b);
        let dropped = stamp_a.iter().copied().collect::<TachygramSetPoly>();
        let foreign_witness = witness::summary_advance((*seeded.data(), ()), &foreign, &stamp_b);
        let empty_seed = PROOF_SYSTEM.seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &[]),
        );

        assert_rejections([
            ("empty stamp", empty_seed.map(drop), "invalid anchor step"),
            (
                "foreign accumulator",
                advance(rng, foreign_witness),
                "SummaryAdvance: accumulator does not match header",
            ),
            (
                "extension drops the stamp",
                advance(rng, (acc, dropped, stamp)),
                "SummaryAdvance: extended accumulator must fold the stamp",
            ),
        ]);
        Ok(())
    });
}

/// The seed folds the epoch it is given and checks it against nothing, so a
/// summary seeded at another epoch than the stamp's block leaves the
/// published chain.
#[test]
fn summary_seed_epoch_binds_the_chain() {
    check(16, (any::<u64>(), 1u32..=8), |(seed, offset)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let mut pool = PoolSim::genesis_with([tachygrams(rng, 2), tachygrams(rng, 2)].to_vec());
        pool.mine([tachygrams(rng, 2), tachygrams(rng, 2)].to_vec());
        let first = pool.block(BlockHeight(0));

        let (seeded, ()) = PROOF_SYSTEM
            .seed(
                rng,
                summary::SummarySeed,
                witness::summary_seed(
                    ((), ()),
                    first.prev,
                    EpochIndex::new(offset),
                    &first.stamps[0].1,
                ),
            )
            .expect("SummarySeed");
        let (_, _, anchor_end, _) = *seeded.data();

        for height in 0..=pool.height().0 {
            let block = pool.block(BlockHeight(height));
            prop_assert_ne!(anchor_end, block.prev);
            for &(_, _, _, anchor) in &block.stamps {
                prop_assert_ne!(anchor_end, anchor);
            }
        }
        Ok(())
    });
}
