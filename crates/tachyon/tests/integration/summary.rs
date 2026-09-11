//! The `Summary` accumulator over a run of stamps, and the lineages that start
//! from one.

extern crate alloc;

use alloc::{string::ToString as _, vec};
use core::array;

use ff::Field as _;
use pasta_curves::Fp;
use ragu::Proof;
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, FactoredPoly as _, NfSeqPoly, Tachygram, TachygramSetPoly,
    nullifier::Nullifier,
    stamp::proof::{PROOF_SYSTEM, pool, spendable, summary},
    witness,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_summary_pcd, build_unspent_seed_pcd, random_block, shared_sk,
};

#[test]
fn summary_advance_folds_stamp_into_accumulator_and_anchor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let stamp_a: [Tachygram; 3] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));
    let stamp_b: [Tachygram; 2] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (seeded, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &stamp_a),
        )
        .expect("SummarySeed");
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
        ),
        "the seed's accumulator is the stamp's own commitment"
    );

    let (advanced, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            summary::SummaryAdvance,
            witness::summary_advance((*seeded.data(), ()), &stamp_a, &stamp_b),
            seeded,
            Proof::trivial().carry::<()>(()),
        )
        .expect("SummaryAdvance");

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
    let expected_last = start
        .next_stamp(epoch, &commit_a)
        .unwrap()
        .next_stamp(epoch, &commit_b)
        .unwrap();
    assert_eq!(
        *advanced.data(),
        (epoch, start, expected_last, union),
        "the product accumulator is the union's root polynomial"
    );
}

#[test]
fn summary_over_an_anchor_span_matches_the_pool() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));

    let (pcd, members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    let (epoch, anchor_prev, anchor_last, acc_commit) = *pcd.data();

    assert_eq!(epoch, EpochIndex::new(0));
    assert_eq!(
        anchor_prev,
        Anchor::default(),
        "the summary opens at the span's start anchor"
    );
    assert_eq!(
        anchor_last,
        pool.anchor(),
        "the summary closes at the span's end anchor"
    );

    let acc = members.iter().copied().collect::<TachygramSetPoly>();
    assert_eq!(members.len(), 12, "every published tachygram accumulates");
    assert_eq!(acc_commit, acc.commit());
    for &tg in &members {
        assert_eq!(
            acc.eval(Fp::from(tg)),
            Fp::ZERO,
            "each member is a root of the accumulator"
        );
    }
}

#[test]
fn summary_seed_rejects_empty_stamp() {
    let rng = &mut StdRng::seed_from_u64(0);
    let start = Anchor::from(Fp::random(&mut *rng));

    let err = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, EpochIndex::new(3), &[]),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "invalid anchor step");
}

#[test]
fn summary_advance_rejects_wrong_accumulator() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let stamp_a = [Tachygram::from(Fp::random(&mut *rng))];
    let stamp_b = [Tachygram::from(Fp::random(&mut *rng))];
    let foreign = [Tachygram::from(Fp::random(&mut *rng))];

    let (seeded, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &stamp_a),
        )
        .expect("SummarySeed");

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            summary::SummaryAdvance,
            witness::summary_advance((*seeded.data(), ()), &foreign, &stamp_b),
            seeded,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SummaryAdvance: accumulator does not match header"
    );
}

#[test]
fn summary_advance_rejects_forged_extension() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let stamp_a = [Tachygram::from(Fp::random(&mut *rng))];
    let stamp_b = [Tachygram::from(Fp::random(&mut *rng))];

    let (seeded, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &stamp_a),
        )
        .expect("SummarySeed");

    // The stamp is folded into the anchor but dropped from the accumulator.
    let (acc, _extended, stamp) =
        witness::summary_advance((*seeded.data(), ()), &stamp_a, &stamp_b);
    let forged = stamp_a.iter().copied().collect::<TachygramSetPoly>();

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            summary::SummaryAdvance,
            (acc, forged, stamp),
            seeded,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SummaryAdvance: extended accumulator must fold the stamp"
    );
}

/// A wrong seed epoch is not detected in-step; it lands off the published
/// chain.
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
        .expect("SummarySeed");
    let (_, _, anchor_last, _) = *seeded.data();

    for height in 0..=pool.height().0 {
        let block = pool.block(BlockHeight(height));
        assert_ne!(anchor_last, block.prev);
        for &(_, _, _, anchor) in &block.stamps {
            assert_ne!(anchor_last, anchor, "the fold left the published chain");
        }
    }
}

#[test]
fn summary_unspent_init_clears_the_whole_run() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    let (pcd, members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    let (epoch, anchor_prev, anchor_last, _) = *pcd.data();
    let nf = Nullifier::from(Fp::random(&mut *rng));

    let (unspent, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::SummaryUnspentInit,
            witness::summary_unspent_init((*pcd.data(), ()), &members, nf),
            pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("SummaryUnspentInit");

    assert_eq!(
        *unspent.data(),
        (
            anchor_prev,
            (epoch, nf),
            NfSeqPoly::new(epoch, &[nf]).commit(),
            (epoch, nf),
            anchor_last
        ),
        "one query spans the summary's whole bracket"
    );
}

#[test]
fn summary_unspent_init_rejects_a_published_nullifier() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    let (pcd, members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    // A tachygram from a stamp in the middle of the run, not the seed's.
    let nf = Nullifier::from(Fp::from(members[7]));

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::SummaryUnspentInit,
            witness::summary_unspent_init((*pcd.data(), ()), &members, nf),
            pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SummaryUnspentInit: found nullifier in summary"
    );
}

#[test]
fn summary_unspent_init_rejects_a_foreign_accumulator() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    let (pcd, _members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    let nf = Nullifier::from(Fp::random(&mut *rng));
    let foreign: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            pool::SummaryUnspentInit,
            witness::summary_unspent_init((*pcd.data(), ()), &foreign, nf),
            pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SummaryUnspentInit: accumulator does not match header"
    );
}

#[test]
fn summary_unspent_init_fuses_with_a_per_stamp_segment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    let end = pool.block(pool.height().prev().unwrap()).anchor();
    let (pcd, members) = build_summary_pcd(rng, &pool, (Anchor::default(), end));
    let (epoch, anchor_prev, anchor_last, _) = *pcd.data();
    let nf = Nullifier::from(Fp::random(&mut *rng));

    let (started, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::SummaryUnspentInit,
            witness::summary_unspent_init((*pcd.data(), ()), &members, nf),
            pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("SummaryUnspentInit");

    let next = &pool.block(pool.height()).stamps[0];
    assert_eq!(
        anchor_last, next.0,
        "the next stamp opens where the summary closed"
    );
    let per_stamp = build_unspent_seed_pcd(rng, next.0, epoch, &next.1, nf);

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            pool::UnspentFuse,
            witness::unspent_fuse((*started.data(), *per_stamp.data()), &[nf], &[nf]),
            started,
            per_stamp,
        )
        .expect("UnspentFuse");

    assert_eq!(
        *fused.data(),
        (
            anchor_prev,
            (epoch, nf),
            NfSeqPoly::new(epoch, &[nf]).commit(),
            (epoch, nf),
            next.3
        ),
        "the composed segment spans the summary and the extra stamp"
    );
}

#[test]
fn summary_spendable_init_starts_a_spendable_from_a_summary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.mine(random_block(rng, 2, 2));
    let (summary_pcd, members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    let (epoch, _, anchor_last, _) = *summary_pcd.data();
    let deriv = user.derivation_pcd(rng, note, epoch, epoch);

    let (spendable, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SummarySpendableInit,
            witness::summary_spendable_init(
                (*deriv.data(), *summary_pcd.data()),
                &members,
                epoch,
                &user.covering_window(&note, &deriv),
            ),
            deriv,
            summary_pcd,
        )
        .expect("SummarySpendableInit");

    assert_eq!(
        *spendable.data(),
        (
            note.commitment(),
            (epoch, user.nf_at(&note, epoch)),
            anchor_last
        ),
        "the spendable rests at the summary's terminal anchor"
    );
    assert_ne!(
        anchor_last,
        pool.block(BlockHeight(0)).stamps[0].3,
        "the summary's terminal anchor lies past the creating stamp"
    );
}

#[test]
fn summary_spendable_init_rejects_a_foreign_covering_sequence() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let other = user.random_note(700);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.mine(random_block(rng, 2, 2));
    let (summary_pcd, members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    let (epoch, ..) = *summary_pcd.data();
    let deriv = user.derivation_pcd(rng, note, epoch, epoch);
    let foreign_deriv = user.derivation_pcd(rng, other, epoch, epoch);
    let witness = witness::summary_spendable_init(
        (*deriv.data(), *summary_pcd.data()),
        &members,
        epoch,
        &user.covering_window(&note, &deriv),
    );

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SummarySpendableInit,
            witness,
            foreign_deriv,
            summary_pcd,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SummarySpendableInit: covering sequence does not match header"
    );
}

#[test]
fn summary_spendable_init_rejects_a_foreign_accumulator() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.mine(random_block(rng, 2, 2));
    let (summary_pcd, _members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    let (epoch, ..) = *summary_pcd.data();
    let deriv = user.derivation_pcd(rng, note, epoch, epoch);
    let foreign: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SummarySpendableInit,
            witness::summary_spendable_init(
                (*deriv.data(), *summary_pcd.data()),
                &foreign,
                epoch,
                &user.covering_window(&note, &deriv),
            ),
            deriv,
            summary_pcd,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SummarySpendableInit: accumulator does not match header"
    );
}

#[test]
fn summary_spendable_init_rejects_an_epoch_mismatch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.mine(random_block(rng, 2, 2));
    let (summary_pcd, members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    let (epoch, ..) = *summary_pcd.data();
    let claimed = epoch.next().unwrap();
    let deriv = user.derivation_pcd(rng, note, epoch, EpochIndex::new(u32::from(epoch) + 1));

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SummarySpendableInit,
            witness::summary_spendable_init(
                (*deriv.data(), *summary_pcd.data()),
                &members,
                claimed,
                &user.covering_window(&note, &deriv),
            ),
            deriv,
            summary_pcd,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SummarySpendableInit: summary epoch must match the creation epoch"
    );
}

#[test]
fn summary_spendable_init_rejects_a_forged_nullifier() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.mine(random_block(rng, 2, 2));
    let (summary_pcd, members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    let (epoch, ..) = *summary_pcd.data();
    let deriv = user.derivation_pcd(rng, note, epoch, epoch);
    let (creation_epoch, _genuine, nf_seq, complement_seq, summary_set) =
        witness::summary_spendable_init(
            (*deriv.data(), *summary_pcd.data()),
            &members,
            epoch,
            &user.covering_window(&note, &deriv),
        );
    let forged = Nullifier::from(Fp::random(&mut *rng));

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SummarySpendableInit,
            (creation_epoch, forged, nf_seq, complement_seq, summary_set),
            deriv,
            summary_pcd,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SummarySpendableInit: nullifier does not match the derivation"
    );
}

#[test]
fn summary_spendable_init_rejects_an_absent_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 2));
    pool.mine(random_block(rng, 2, 2));
    let (summary_pcd, members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    let (epoch, ..) = *summary_pcd.data();
    let deriv = user.derivation_pcd(rng, note, epoch, epoch);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SummarySpendableInit,
            witness::summary_spendable_init(
                (*deriv.data(), *summary_pcd.data()),
                &members,
                epoch,
                &user.covering_window(&note, &deriv),
            ),
            deriv,
            summary_pcd,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SummarySpendableInit: commitment not in summary"
    );
}

#[test]
fn summary_spendable_init_rejects_a_published_nullifier() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let spent = Tachygram::from(user.nf_at(&note, EpochIndex::new(0)));
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.mine(vec![vec![spent]]);
    pool.mine(random_block(rng, 2, 2));
    let (summary_pcd, members) = build_summary_pcd(rng, &pool, (Anchor::default(), pool.anchor()));
    let (epoch, ..) = *summary_pcd.data();
    let deriv = user.derivation_pcd(rng, note, epoch, epoch);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::SummarySpendableInit,
            witness::summary_spendable_init(
                (*deriv.data(), *summary_pcd.data()),
                &members,
                epoch,
                &user.covering_window(&note, &deriv),
            ),
            deriv,
            summary_pcd,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "SummarySpendableInit: found nullifier in summary"
    );
}
