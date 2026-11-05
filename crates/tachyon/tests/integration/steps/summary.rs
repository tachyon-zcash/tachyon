extern crate alloc;

use alloc::vec::Vec;
use core::iter;

use ragu::Proof;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, EpochIndex, Tachygram, TachygramSetPoly,
    constants::EPOCH_MAX,
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, summary},
    witness,
};

#[test]
fn summary_accumulates_its_run() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (epoch_index, sizes) in [
        (0, &[1][..]),
        (EPOCH_MAX, &[4, 4, 4, 4][..]),
        (EPOCH_MAX / 2, &[2, 1, 3][..]),
    ] {
        let epoch = EpochIndex::new(epoch_index);
        let start = Anchor::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
        let stamps: Vec<Vec<Tachygram>> = sizes
            .iter()
            .map(|&size| {
                iter::repeat_with(|| Tachygram::random(rng))
                    .take(size)
                    .collect()
            })
            .collect();

        let (first, rest) = stamps.split_first().unwrap();
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
                    Proof::bootstrap().carry::<()>(()),
                )
                .expect("SummaryAdvance");
            acc.extend(stamp.iter().copied());
            pcd = advanced;
        }

        let end = stamps.iter().fold(start, |anchor, stamp| {
            let commit = stamp.iter().copied().collect::<TachygramSetPoly>().commit();
            anchor.next_stamp(epoch, &commit).unwrap()
        });
        let union = acc.iter().copied().collect::<TachygramSetPoly>();
        assert_eq!(
            *pcd.data(),
            (epoch, start, end, union.commit()),
            "stamps of {sizes:?} at epoch {epoch:?}"
        );
    }
}

#[test]
fn summary_steps_reject_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(EPOCH_MAX / 2);
    let start = Anchor::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let (stamp_a, stamp_b) = (
        iter::repeat_with(|| Tachygram::random(rng))
            .take(2)
            .collect::<Vec<_>>(),
        iter::repeat_with(|| Tachygram::random(rng))
            .take(3)
            .collect::<Vec<_>>(),
    );
    let foreign = iter::repeat_with(|| Tachygram::random(rng))
        .take(2)
        .collect::<Vec<_>>();

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
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
    };
    let (acc, _extended, stamp) =
        witness::summary_advance((*seeded.data(), ()), &stamp_a, &stamp_b);
    let dropped = stamp_a.iter().copied().collect::<TachygramSetPoly>();

    assert_eq!(
        PROOF_SYSTEM
            .seed(
                rng,
                summary::SummarySeed,
                witness::summary_seed(((), ()), start, epoch, &[]),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: invalid anchor step",
    );
    assert_eq!(
        advance(
            rng,
            witness::summary_advance((*seeded.data(), ()), &stamp_a, &[]),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: invalid anchor step",
    );
    assert_eq!(
        advance(
            rng,
            witness::summary_advance((*seeded.data(), ()), &foreign, &stamp_b),
        )
        .unwrap_err()
        .to_string(),
        "invalid witness: SummaryAdvance: accumulator does not match header",
    );
    assert_eq!(
        advance(rng, (acc, dropped, stamp)).unwrap_err().to_string(),
        "invalid witness: SummaryAdvance: extended accumulator must fold the stamp",
    );
}
