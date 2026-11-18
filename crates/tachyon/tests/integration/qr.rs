extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::{array, assert_matches, iter, mem, slice};

use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::{curve::Projective as _, field::Field as _};
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetBridge, TachygramSetPoly,
    constants::EPOCH_MAX,
    nullifier::Nullifier,
    pasta::{Eq, Fp},
    stamp::proof::{
        pool::{UnspentFuse, UnspentLift},
        qr, spend, spendable,
    },
    value, witness,
};

use super::fixtures::application;
use crate::fixtures::{
    pool::PoolSim,
    qr::{
        EvidenceTreeEntry, QR_DEPTHS, QrIntakeEntry, qr_profile_of, qr_profile_triplet,
        scaled_qr_contents, shared_discriminant,
    },
    wallet::{WalletSim, shared_sk},
};

#[test]
fn qr_summary_intake_starts_a_root_from_a_summary() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let summary = pool.summary(app, span0);
    let (_, _, anchor_end) = *summary.data();
    let acc_commit = summary.commitments()[0];
    let root = pool.qr_root(app, span0, disc);

    assert_eq!(
        *root.pcd.data(),
        (epoch0, Anchor::default(), anchor_end, disc, QrProfile::ROOT)
    );
    assert_eq!(root.pcd.commitments()[1], acc_commit);
    assert!(app.verify_uncompressed(&root.pcd, &mut *rng).unwrap());
}

#[test]
fn qr_stamp_intake_seed_rejects_an_empty_stamp() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor_prev = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    assert_matches!(
        app
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(
                    ((), ()),
                    anchor_prev,
                    EpochIndex::new(3),
                    discriminant,
                    &[],
                ),
            )
            .err(),
        Some(ragu::Error::InvalidWitness(err)) if err.to_string() == "division by zero"
    );
}

#[test]
fn qr_intake_split_partitions_the_contents_by_class() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let root = pool.qr_root(app, span0, disc);
    let members = root.members;

    let (residue, non_residue): (Vec<Tachygram>, Vec<Tachygram>) = members
        .iter()
        .copied()
        .partition(|&member| qr::classify(Fp::from(member), Fp::from(disc)).0);
    assert!(!residue.is_empty() && !non_residue.is_empty());

    let split = pool.qr_split(app, span0, disc, Fp::ZERO, 0);

    let non_residue_commit = non_residue
        .iter()
        .copied()
        .collect::<TachygramSetPoly>()
        .commit();
    let non_residue_hash = TachygramSetBridge::from(
        app.bridge_hash(non_residue_commit.as_ref().to_affine())
            .unwrap(),
    );
    assert_eq!(
        *split.data(),
        (
            epoch0,
            Anchor::default(),
            span0.1,
            disc,
            QrProfile::ROOT,
            non_residue_hash,
        )
    );
    assert_eq!(
        split.commitments()[..2],
        [
            Eq::from(
                residue
                    .iter()
                    .copied()
                    .collect::<TachygramSetPoly>()
                    .commit()
            )
            .to_affine(),
            Eq::from(
                non_residue
                    .iter()
                    .copied()
                    .collect::<TachygramSetPoly>()
                    .commit()
            )
            .to_affine(),
        ]
    );
    assert!(app.verify_uncompressed(&split, &mut *rng).unwrap());
}

#[test]
fn qr_intake_split_rejects_a_forged_partition() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let root = pool.qr_root(app, span0, disc);
    let members = root.members;

    let mut split_witness = witness::qr_intake_split((*root.pcd.data(), ()), &members);
    split_witness.1 = split_witness.0.clone();
    let (forged, ()) = app
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            root.pcd,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
}

#[test]
fn qr_intake_split_rejects_an_empty_intake() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch3 = EpochIndex::new(3);
    let intake = QrIntakeEntry::empty(
        app,
        pool.entry_anchor(epoch3),
        epoch3,
        pool.epoch_discriminant(epoch3),
    );

    assert_matches!(
        app
            .fuse(
                rng,
                qr::QrIntakeSplit,
                witness::qr_intake_split((*intake.pcd.data(), ()), &[]),
                intake.pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .err(),
        Some(ragu::Error::InvalidWitness(err))
            if err.to_string() == "division by zero"
    );
}

#[test]
fn qr_side_descend_rejects_a_split_into_the_same_set() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let member = Tachygram::random(rng);
    let side = qr::classify(Fp::from(member), discriminant.at(0)).0;

    let (root, ()) = app
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &[member, member]),
        )
        .unwrap();
    let half = TachygramSetPoly::from_iter([member]);
    let (sides, ()) = app
        .fuse(
            rng,
            qr::QrIntakeSplit,
            (half.clone(), half),
            root,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();

    let (selection, ()) = app
        .fuse(
            rng,
            qr::QrSideSelect,
            witness::qr_side_select((*sides.data(), ()), &[member, member], side),
            sides.clone(),
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(app.verify_uncompressed(&sides, &mut *rng).unwrap());
    assert!(app.verify_uncompressed(&selection, &mut *rng).unwrap());

    assert_matches!(
        app
            .fuse(
                rng,
                qr::QrSideDescend,
                witness::qr_side_descend((*sides.data(), *selection.data()), side),
                sides,
                selection,
            )
            .err(),
        Some(ragu::Error::InvalidWitness(err))
            if err.to_string() == "division by zero"
    );
}

// Scaled-split characterization: book/src/proof-tree.md,
// "Scaled splits: observed behavior and limits". Acceptance here is pinned, not
// endorsed.

#[test]
fn scaled_qr_splits_accept_equal_roots_and_rootless_children() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(278);
    let zero = Anchor::from(Fp::ZERO);
    let disc = QrDiscriminant::random(rng);
    let member = Tachygram::random(rng);
    let side = qr::classify(Fp::from(member), disc.at(0)).0;
    let scale = Fp::from(7u64);
    let inverse = scale.invert().unwrap();
    let duplicate = PoolSim::genesis_with(vec![vec![member, member]]);
    let span = (Anchor::default(), duplicate.anchor());
    let root = duplicate.qr_intakes(app, span, disc, 0).pop().unwrap();
    let factors = [(vec![member], scale), (vec![member], inverse)];
    let [child] = root.split_with_factors(rng, app, [!side], &factors);
    assert!(app.verify_differential(&child.pcd, &mut *rng).unwrap());
    assert_eq!(child.members, [member]);
    assert_eq!(child.pcd.data().4, QrProfile::ROOT.descend(!side));

    let single = PoolSim::genesis_with(vec![vec![member]]);
    let single_span = (Anchor::default(), single.anchor());
    let root_single = single.qr_intakes(app, single_span, disc, 0).pop().unwrap();
    let occupied = (vec![member], scale);
    let empty = (Vec::new(), inverse);
    let split = if side {
        [empty, occupied]
    } else {
        [occupied, empty]
    };
    let [rootless] = root_single.split_with_factors(rng, app, [!side], &split);
    assert!(app.verify_differential(&rootless.pcd, &mut *rng).unwrap());
    assert_ne!(
        rootless.pcd.commitments()[1],
        Eq::from(scaled_qr_contents(&[], Fp::ONE).commit()).to_affine()
    );
    let deep = Fp::from(11u64);
    let factors_deep = [
        (Vec::new(), deep),
        (Vec::new(), (scale * deep).invert().unwrap()),
    ];
    let [deeper] = rootless.split_with_factors(rng, app, [false], &factors_deep);
    let sealed = deeper.seal(rng, app, zero);
    assert!(app.verify_differential(&sealed.pcd, &mut *rng).unwrap());
    assert_eq!(
        sealed.pcd.data().4,
        QrProfile::ROOT.descend(!side).descend(false)
    );
}

#[test]
fn scaled_qr_buckets_answer_as_honest_buckets() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(279);
    let user = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(700);
    let epoch = EpochIndex::new(0);
    let cm = Tachygram::from(note.commitment());
    let nf = user
        .pak
        .nk
        .derive_note_private(note.psi)
        .derive_nullifier(epoch);
    let disc = iter::repeat_with(|| QrDiscriminant::random(rng))
        .find(|&candidate| {
            qr_profile_of(Fp::from(cm), candidate, 1) == qr_profile_of(Fp::from(nf), candidate, 1)
        })
        .unwrap();
    let side = qr::classify(Fp::from(cm), disc.at(0)).0;
    let other = iter::repeat_with(|| user.random_note(400))
        .find(|candidate| {
            let value = user
                .pak
                .nk
                .derive_note_private(candidate.psi)
                .derive_nullifier(epoch);
            qr::classify(Fp::from(value), disc.at(0)).0 != side
        })
        .unwrap();
    let other_nf = user
        .pak
        .nk
        .derive_note_private(other.psi)
        .derive_nullifier(epoch);
    let deep_bit = qr::classify(Fp::from(other_nf), disc.at(1)).0;
    let zero = Anchor::from(Fp::ZERO);
    let scale = Fp::from(7u64);
    let inverse = scale.invert().unwrap();
    let pool = PoolSim::genesis_with(vec![vec![cm]]);
    let span = (Anchor::default(), pool.anchor());
    let root = pool.qr_intakes(app, span, disc, 0).pop().unwrap();
    let [honest_non_residue, honest_residue] = root.clone().split(rng, app, [false, true]);
    let honest = if side {
        [honest_residue, honest_non_residue]
    } else {
        [honest_non_residue, honest_residue]
    };
    let factors = if side {
        [(vec![], inverse), (vec![cm], scale)]
    } else {
        [(vec![cm], scale), (vec![], inverse)]
    };
    let scaled = root.split_with_factors(rng, app, [side, !side], &factors);
    let deep = Fp::from(11u64);
    let factors_deep = [(vec![], deep), (vec![], (scale * deep).invert().unwrap())];
    let [deep_intake] = scaled[1]
        .clone()
        .split_with_factors(rng, app, [deep_bit], &factors_deep);
    let deep_bucket = deep_intake.seal(rng, app, zero);
    let [honest_held, honest_empty] = honest.map(|entry| entry.seal(rng, app, zero));
    let [scaled_held, scaled_empty] = scaled.map(|entry| entry.seal(rng, app, zero));
    for (left, right) in [(&honest_held, &scaled_held), (&honest_empty, &scaled_empty)] {
        assert_eq!(left.pcd.data().4, right.pcd.data().4);
        assert_ne!(left.pcd.data().5, right.pcd.data().5);
        assert_eq!(left.pcd.data().2, right.pcd.data().2);
    }
    let tree = EvidenceTreeEntry::build_with_scales(
        rng,
        app,
        &vec![
            scaled_held.clone(),
            scaled_empty.clone(),
            honest_held.clone(),
            honest_empty.clone(),
        ]
        .into_boxed_slice(),
        vec![scale, inverse, Fp::ONE, Fp::ONE],
    );
    let [opened_scaled, opened_honest] =
        [0, 2].map(|index| tree.open(rng, app, &tree.leaves[index]).unwrap());
    assert_eq!(opened_scaled.pcd.data(), scaled_held.pcd.data());
    assert_eq!(opened_honest.pcd.data(), honest_held.pcd.data());
    for (index, wrong_scale) in [(0, Fp::ONE), (2, scale)] {
        let mut leaf = tree.leaves[index].clone();
        leaf.contents = scaled_qr_contents(&leaf.members, wrong_scale);
        let forged = tree.open(rng, app, &leaf).unwrap();
        assert!(!app.verify_uncompressed(&forged.pcd, &mut *rng).unwrap());
    }
    let rcv = value::Trapdoor::random(rng);
    let mut spends = Vec::new();
    for bucket in [&opened_honest, &opened_scaled] {
        let unspent = user.bucket_unspent(rng, app, bucket, &note);
        let (spendable, ()) = app
            .fuse(
                rng,
                spendable::QrSpendableInit,
                (),
                unspent.clone(),
                bucket.pcd.clone(),
            )
            .unwrap();
        assert_eq!(
            *spendable.data(),
            (
                note.commitment(),
                epoch.next().unwrap(),
                bucket.pcd.data().2
            )
        );
        let secret = user.note_secret(app, note);
        let bind_witness = witness::spend_bind((*spendable.data(), *secret.data()), rcv);
        let (bind, ()) = app
            .fuse(rng, spend::SpendBind, bind_witness, spendable, secret)
            .unwrap();
        assert!(app.verify_differential(&bind, &mut *rng).unwrap());
        let (bound_cm, current, next, anchor, pk, _) = *bind.data();
        spends.push((bound_cm, current, next, anchor, Fp::from(pk)));
        for empty in [&honest_empty, &scaled_empty, &deep_bucket] {
            let (forged, ()) = app
                .fuse(
                    rng,
                    spendable::QrSpendableInit,
                    (),
                    unspent.clone(),
                    empty.pcd.clone(),
                )
                .unwrap();
            assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
        }
    }
    assert_eq!(spends[0], spends[1]);
    for empty in [&honest_empty, &scaled_empty, &deep_bucket] {
        let unspent = user.bucket_unspent(rng, app, empty, &other);
        assert!(app.verify_differential(&unspent, &mut *rng).unwrap());
        for bucket in [&honest_held, &scaled_held, empty] {
            let (forged, ()) = app
                .fuse(
                    rng,
                    spendable::QrSpendableInit,
                    (),
                    unspent.clone(),
                    bucket.pcd.clone(),
                )
                .unwrap();
            assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
        }
        let wrong_profile = empty.segment(rng, app, |_| nf);
        assert!(!app.verify_uncompressed(&wrong_profile, &mut *rng).unwrap());
    }
}

#[test]
fn scaled_duplicate_split_answers_as_a_monic_stray_bucket() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(280);
    let user = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(700);
    let cm = Tachygram::from(note.commitment());
    let nf = user
        .pak
        .nk
        .derive_note_private(note.psi)
        .derive_nullifier(EpochIndex::new(0));
    let disc = iter::repeat_with(|| QrDiscriminant::random(rng))
        .find(|&candidate| {
            qr_profile_of(Fp::from(cm), candidate, 1) == qr_profile_of(Fp::from(nf), candidate, 1)
        })
        .unwrap();
    let side = qr::classify(Fp::from(cm), disc.at(0)).0;
    let absent = iter::repeat_with(|| Tachygram::random(rng))
        .find(|&value| qr::classify(Fp::from(value), disc.at(0)).0 != side)
        .unwrap();
    let companion = iter::repeat_with(|| Tachygram::random(rng))
        .find(|&value| qr::classify(Fp::from(value), disc.at(0)).0 == side)
        .unwrap();
    for (sibling, scale) in [(cm, Fp::from(7u64)), (companion, Fp::ONE)] {
        let pool = PoolSim::genesis_with(vec![vec![cm, sibling]]);
        let span = (Anchor::default(), pool.anchor());
        let root = pool.qr_intakes(app, span, disc, 0).pop().unwrap();
        let held = (root.members.clone(), Fp::ONE);
        let empty = (vec![], Fp::ONE);
        let honest_factors = if side { [empty, held] } else { [held, empty] };
        let [held_intake] = root
            .clone()
            .split_with_factors(rng, app, [side], &honest_factors);
        let child = (vec![cm], scale);
        let other = (vec![sibling], scale.invert().unwrap());
        let factors = if side { [child, other] } else { [other, child] };
        let [stray] = root.split_with_factors(rng, app, [!side], &factors);
        let [held_bucket, stray_bucket] =
            [held_intake, stray].map(|entry| entry.seal(rng, app, Anchor::from(Fp::ZERO)));
        assert_eq!(stray_bucket.pcd.data().4, QrProfile::ROOT.descend(!side));
        let unspent = user.bucket_unspent(rng, app, &held_bucket, &note);
        for bucket in [&held_bucket, &stray_bucket] {
            let (included, ()) = app
                .fuse(
                    rng,
                    spendable::QrSpendableInit,
                    (),
                    unspent.clone(),
                    bucket.pcd.clone(),
                )
                .unwrap();
            assert!(app.verify_differential(&included, &mut *rng).unwrap());
            assert_matches!(
                app.fuse(
                    rng, qr::QrUnspentInit, witness::qr_unspent_init((*bucket.pcd.data(), ()), cm),
                    bucket.pcd.clone(), app.bootstrap_proof().clone().carry::<()>(()),
                ).err(),
                Some(ragu::Error::InvalidWitness(error))
                    if error.to_string() == "division by zero"
            );
        }
        let segment = stray_bucket.segment(rng, app, |_| Nullifier::from(absent));
        assert!(app.verify_differential(&segment, &mut *rng).unwrap());
    }
}

// Oversized-bucket characterization: book/src/proof-tree.md,
// "Oversized buckets: observed behavior". Acceptance here is pinned, not
// endorsed.

#[test]
fn oversized_qr_bucket_seals_refuses_its_members_and_opens_from_a_tree() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let [absent, exceptional, companion] = qr_profile_triplet();
    let [_, _, _, full] = pool.qr_descent(app, span0, disc, absent);
    let members = [Tachygram::from(exceptional), Tachygram::from(companion)];
    assert_eq!(full.members, members);
    let (.., profile) = *full.pcd.data();
    assert_eq!(profile.depth, u32::BITS);
    let bucket = full.sealed(app, Anchor::from(Fp::ZERO));
    assert!(app.verify_uncompressed(&bucket.pcd, &mut *rng).unwrap());
    let (_epoch, _start, _next, _discriminant, bucket_profile, _contents_hash) = *bucket.pcd.data();
    assert_eq!(bucket_profile.depth, u32::BITS);
    assert_eq!(
        bucket.pcd.commitments()[1],
        Eq::from(members.into_iter().collect::<TachygramSetPoly>().commit()).to_affine()
    );
    for member in [exceptional, companion] {
        let witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), Tachygram::from(member));
        assert_matches!(
            app.fuse(rng, qr::QrUnspentInit, witness, bucket.pcd.clone(), app.bootstrap_proof().clone().carry::<()>(())).err(),
            Some(ragu::Error::InvalidWitness(err)) if err.to_string() == "division by zero"
        );
    }
    let tree = EvidenceTreeEntry::build(rng, app, slice::from_ref(&bucket));
    let opened = tree.open(rng, app, &tree.leaves[0]).unwrap();
    assert_eq!(*opened.pcd.data(), *bucket.pcd.data());
    assert!(app.verify_uncompressed(&opened.pcd, &mut *rng).unwrap());
}

#[test]
fn qr_side_select_checks_the_exceptional_value_at_its_depth() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let [absent, exceptional_value, _] = qr_profile_triplet();
    let [root_case, child_case] = [0, 1].map(|depth| {
        let epoch = EpochIndex::new(3);
        let start = Anchor::random(rng);
        let discriminant = QrDiscriminant::random(rng);
        let value = -Fp::from(discriminant) - Fp::from(u64::from(depth));
        let exceptional = Tachygram::from(value);
        let members: Vec<Tachygram> = iter::repeat_with(|| Tachygram::random(rng))
            .take(8)
            .chain([exceptional])
            .collect();

        let (root, ()) = app
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &members),
            )
            .unwrap();

        let mut intake = QrIntakeEntry { pcd: root, members };
        for level in 0..depth {
            let side = qr::classify(value, discriminant.at(level)).0;
            let [next] = intake.split(rng, app, [side]);
            intake = next;
        }
        (intake, discriminant, value)
    });
    let [_, _, deep_intake, _] = pool.qr_descent(app, span0, disc, absent);
    for (intake, discriminant, value) in [
        root_case,
        child_case,
        (deep_intake, disc, exceptional_value),
    ] {
        let (.., profile) = *intake.pcd.data();
        let depth = profile.depth;
        let exceptional = Tachygram::from(value);
        let (honest_sides, ()) = app
            .fuse(
                rng,
                qr::QrIntakeSplit,
                witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members),
                intake.pcd.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        for side in [false, true] {
            let (selection, ()) = app
                .fuse(
                    rng,
                    qr::QrSideSelect,
                    witness::qr_side_select((*honest_sides.data(), ()), &intake.members, side),
                    honest_sides.clone(),
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .unwrap();
            assert!(app.verify_uncompressed(&selection, &mut *rng).unwrap());
        }

        let (residue, non_residue): (Vec<Tachygram>, Vec<Tachygram>) =
            intake.members.iter().copied().partition(|member| {
                *member != exceptional && qr::classify(Fp::from(*member), discriminant.at(depth)).0
            });
        let mut split_witness = witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members);
        split_witness.0 = non_residue.iter().copied().collect();
        split_witness.1 = residue.iter().copied().collect();
        let (sides, ()) = app
            .fuse(
                rng,
                qr::QrIntakeSplit,
                split_witness,
                intake.pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert_matches!(
            app.fuse(
                rng,
                qr::QrSideSelect,
                witness::qr_side_select((*sides.data(), ()), &intake.members, false),
                sides,
                app.bootstrap_proof().clone().carry::<()>(()),
            ).err(),
            Some(ragu::Error::InvalidWitness(err)) if err.to_string()
                == "division by zero"
        );
    }
}

#[test]
fn qr_side_descend_carries_each_side_one_level_down() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let exceptional_epoch = EpochIndex::new(3);
    let exceptional_start = Anchor::random(rng);
    let exceptional_discriminant = QrDiscriminant::random(rng);
    let exceptional_members = vec![Tachygram::from(-Fp::from(exceptional_discriminant))];
    let (exceptional_root, ()) = app
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(
                ((), ()),
                exceptional_start,
                exceptional_epoch,
                exceptional_discriminant,
                &exceptional_members,
            ),
        )
        .unwrap();
    let exceptional_data = *exceptional_root.data();
    let (exceptional_split, ()) = app
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*exceptional_root.data(), ()), &exceptional_members),
            exceptional_root,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let root = pool.qr_root(app, span0, disc);
    let split0 = pool.qr_split(app, span0, disc, Fp::ZERO, 0);
    for (data, split, members) in [
        (exceptional_data, exceptional_split, exceptional_members),
        (*root.pcd.data(), split0, root.members),
    ] {
        let (epoch, start, anchor_end, discriminant, _) = data;

        for side in [true, false] {
            let side_members: Vec<Tachygram> = members
                .iter()
                .copied()
                .filter(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0 == side)
                .collect();
            let select_witness = witness::qr_side_select((*split.data(), ()), &members, side);
            let expected_selection = *split.data();
            let expected_hints = [
                Eq::from(select_witness.0.commit()).to_affine(),
                Eq::from(select_witness.1.commit()).to_affine(),
            ];
            let (selection, ()) = app
                .fuse(
                    rng,
                    qr::QrSideSelect,
                    select_witness,
                    split.clone(),
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .unwrap();
            assert_eq!(*selection.data(), expected_selection);
            assert_eq!(selection.commitments()[..2], expected_hints);
            let (child, ()) = app
                .fuse(
                    rng,
                    qr::QrSideDescend,
                    witness::qr_side_descend((*split.data(), *selection.data()), side),
                    split.clone(),
                    selection,
                )
                .unwrap();
            assert_eq!(
                *child.data(),
                (
                    epoch,
                    start,
                    anchor_end,
                    discriminant,
                    QrProfile::ROOT.descend(side),
                )
            );
            assert_eq!(
                child.commitments()[1],
                Eq::from(
                    side_members
                        .iter()
                        .copied()
                        .collect::<TachygramSetPoly>()
                        .commit()
                )
                .to_affine()
            );
            assert!(app.verify_uncompressed(&child, &mut *rng).unwrap());
        }
    }
}

#[test]
fn qr_side_select_defers_hint_validation_to_descent() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let root = pool.qr_root(app, span0, disc);
    let sides = pool.qr_split(app, span0, disc, Fp::ZERO, 0);
    let members = root.members;

    for side in [false, true] {
        let selection_witness = witness::qr_side_select((*sides.data(), ()), &members, !side);
        let (selection, ()) = app
            .fuse(
                rng,
                qr::QrSideSelect,
                selection_witness,
                sides.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        let (forged, ()) = app
            .fuse(
                rng,
                qr::QrSideDescend,
                witness::qr_side_descend((*sides.data(), *selection.data()), side),
                sides.clone(),
                selection,
            )
            .unwrap();
        assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
    }
}

#[test]
fn qr_side_descend_matches_selection_metadata() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::random(rng));
    let (root, ()) = app
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &members),
        )
        .unwrap();
    let (sides, ()) = app
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root.clone(),
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    let foreign_start = Anchor::random(rng);
    let foreign_discriminant = QrDiscriminant::random(rng);
    for (other_epoch, other_start, other_discriminant, other_members, expected) in [
        (
            epoch.next().unwrap(),
            start,
            discriminant,
            members.as_slice(),
            "a selection from another epoch",
        ),
        (
            epoch,
            foreign_start,
            discriminant,
            members.as_slice(),
            "a selection from another start anchor",
        ),
        (
            epoch,
            start,
            discriminant,
            &members[..11],
            "a selection ending at another anchor",
        ),
        (
            epoch,
            start,
            foreign_discriminant,
            members.as_slice(),
            "a selection under another discriminant",
        ),
    ] {
        let (foreign_root, ()) = app
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(
                    ((), ()),
                    other_start,
                    other_epoch,
                    other_discriminant,
                    other_members,
                ),
            )
            .unwrap();
        let (foreign_sides, ()) = app
            .fuse(
                rng,
                qr::QrIntakeSplit,
                witness::qr_intake_split((*foreign_root.data(), ()), other_members),
                foreign_root,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        let selection_witness =
            witness::qr_side_select((*foreign_sides.data(), ()), other_members, false);
        let (selection, ()) = app
            .fuse(
                rng,
                qr::QrSideSelect,
                selection_witness,
                foreign_sides,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        let (forged, ()) = app
            .fuse(
                rng,
                qr::QrSideDescend,
                witness::qr_side_descend((*sides.data(), *selection.data()), false),
                sides.clone(),
                selection,
            )
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
            "{expected}"
        );
    }
    // A genuine foreign split can share all scalar metadata yet have another q0.
    let mut split_witness = witness::qr_intake_split((*root.data(), ()), &members);
    mem::swap(&mut split_witness.0, &mut split_witness.1);
    let (foreign_sides, ()) = app
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            root,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    let (selection, ()) = app
        .fuse(
            rng,
            qr::QrSideSelect,
            witness::qr_side_select((*foreign_sides.data(), ()), &members, false),
            foreign_sides,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    let (forged, ()) = app
        .fuse(
            rng,
            qr::QrSideDescend,
            witness::qr_side_descend((*sides.data(), *selection.data()), false),
            sides,
            selection,
        )
        .unwrap();
    assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
}

#[test]
fn qr_side_descend_rejects_a_child_short_of_a_member() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let root = pool.qr_root(app, span0, disc);
    let members = root.members;

    let (mut short_residue, mut padded_non_residue): (Vec<Tachygram>, Vec<Tachygram>) = members
        .iter()
        .copied()
        .partition(|&member| qr::classify(Fp::from(member), Fp::from(disc)).0);
    let smuggled = short_residue.pop().unwrap();
    padded_non_residue.push(smuggled);
    let mut split_witness = witness::qr_intake_split((*root.pcd.data(), ()), &members);
    split_witness.0 = padded_non_residue.iter().copied().collect();
    split_witness.1 = short_residue.iter().copied().collect();
    let (sides, ()) = app
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            root.pcd,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();

    {
        let (selection, ()) = app
            .fuse(
                rng,
                qr::QrSideSelect,
                witness::qr_side_select((*sides.data(), ()), &members, true),
                sides.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        let (forged, ()) = app
            .fuse(
                rng,
                qr::QrSideDescend,
                witness::qr_side_descend((*sides.data(), *selection.data()), true),
                sides.clone(),
                selection,
            )
            .unwrap();
        assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
    }

    let members_without_smuggled: Vec<Tachygram> = members
        .iter()
        .copied()
        .filter(|&member| member != smuggled)
        .collect();
    let (selection, ()) = app
        .fuse(
            rng,
            qr::QrSideSelect,
            witness::qr_side_select((*sides.data(), ()), &members_without_smuggled, false),
            sides.clone(),
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    let (child, ()) = app
        .fuse(
            rng,
            qr::QrSideDescend,
            witness::qr_side_descend((*sides.data(), *selection.data()), false),
            sides,
            selection,
        )
        .unwrap();
    assert!(app.verify_uncompressed(&child, &mut *rng).unwrap());
    let (.., child_profile) = *child.data();
    assert_eq!(child_profile, QrProfile::ROOT.descend(false));
    assert_eq!(
        child.commitments()[1],
        Eq::from(
            padded_non_residue
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit()
        )
        .to_affine()
    );
}

#[test]
#[should_panic(expected = "profile has no bit left for another side")]
fn qr_side_descend_refuses_a_full_register() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let [absent, _, _] = qr_profile_triplet();
    let [_, _, _, intake] = pool.qr_descent(app, span0, disc, absent);
    let (.., profile) = *intake.pcd.data();
    assert_eq!(profile, qr_profile_of(absent, disc, u32::BITS));

    let split_witness = witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members);
    let (sides, ()) = app
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            intake.pcd,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    let (selection, ()) = app
        .fuse(
            rng,
            qr::QrSideSelect,
            witness::qr_side_select((*sides.data(), ()), &intake.members, true),
            sides.clone(),
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(app.verify_uncompressed(&selection, &mut *rng).unwrap());
    let (_descended, ()) = app
        .fuse(
            rng,
            qr::QrSideDescend,
            witness::qr_side_descend((*sides.data(), *selection.data()), true),
            sides,
            selection,
        )
        .unwrap();
}

#[test]
fn qr_intake_merge_joins_two_spans() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let discriminant = QrDiscriminant::random(rng);
    let start = Anchor::random(rng);
    let left_members: [Tachygram; 5] = array::from_fn(|_| Tachygram::random(rng));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::random(rng));

    let (left, ()) = app
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &left_members),
        )
        .unwrap();
    let junction = left.data().2;
    let (right, ()) = app
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), junction, epoch, discriminant, &right_members),
        )
        .unwrap();
    let end = right.data().2;

    let witness =
        witness::qr_intake_merge((*left.data(), *right.data()), &left_members, &right_members);
    let (merged, ()) = app
        .fuse(rng, qr::QrIntakeMerge, witness, left, right)
        .unwrap();

    let union = left_members
        .iter()
        .chain(&right_members)
        .copied()
        .collect::<TachygramSetPoly>();
    assert_eq!(
        *merged.data(),
        (epoch, start, end, discriminant, QrProfile::ROOT)
    );
    assert_eq!(
        merged.commitments()[1],
        Eq::from(union.commit()).to_affine()
    );
    assert!(app.verify_uncompressed(&merged, &mut *rng).unwrap());
}

#[test]
fn qr_intake_merge_rejects_mismatched_inputs() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let discriminant = QrDiscriminant::random(rng);
    let left_members: [Tachygram; 5] = array::from_fn(|_| Tachygram::random(rng));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::random(rng));
    let start = Anchor::random(rng);
    let (left, ()) = app
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &left_members),
        )
        .unwrap();
    let junction = left.data().2;

    for (anchor_prev, right_epoch, right_discriminant, expected) in [
        (
            Anchor::random(rng),
            epoch,
            discriminant,
            "intakes that do not meet",
        ),
        (
            junction,
            epoch.next().unwrap(),
            discriminant,
            "intakes from different epochs",
        ),
        (
            junction,
            epoch,
            QrDiscriminant::random(rng),
            "intakes under different discriminants",
        ),
    ] {
        let (right, ()) = app
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(
                    ((), ()),
                    anchor_prev,
                    right_epoch,
                    right_discriminant,
                    &right_members,
                ),
            )
            .unwrap();
        let (forged, ()) = app
            .fuse(
                rng,
                qr::QrIntakeMerge,
                witness::qr_intake_merge(
                    (*left.data(), *right.data()),
                    &left_members,
                    &right_members,
                ),
                left.clone(),
                right,
            )
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
            "{expected}"
        );
    }

    let (right, ()) = app
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), junction, epoch, discriminant, &right_members),
        )
        .unwrap();
    let (split, ()) = app
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*left.data(), ()), &left_members),
            left,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    let (selection, ()) = app
        .fuse(
            rng,
            qr::QrSideSelect,
            witness::qr_side_select((*split.data(), ()), &left_members, true),
            split.clone(),
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    let (deeper, ()) = app
        .fuse(
            rng,
            qr::QrSideDescend,
            witness::qr_side_descend((*split.data(), *selection.data()), true),
            split,
            selection,
        )
        .unwrap();
    let deeper_members: Vec<Tachygram> = left_members
        .iter()
        .copied()
        .filter(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0)
        .collect();
    let (forged, ()) = app
        .fuse(
            rng,
            qr::QrIntakeMerge,
            witness::qr_intake_merge(
                (*deeper.data(), *right.data()),
                &deeper_members,
                &right_members,
            ),
            deeper,
            right,
        )
        .unwrap();
    assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
}

#[test]
fn qr_bucket_seal_seals_a_fully_routed_intake() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let value = Fp::from(Tachygram::from(PoolSim::shared_note(500).commitment()));
    let intake = pool.qr_intake(app, span0, disc, value, 2);
    let (epoch, anchor_prev, _, _, profile) = *intake.pcd.data();
    let contents = intake.pcd.commitments()[1];
    let bucket = pool.qr_bucket(app, span0, disc, value, 2, Anchor::from(Fp::ZERO));

    assert_eq!(
        *bucket.pcd.data(),
        (
            epoch,
            anchor_prev,
            span0.1.next_epoch(epoch.next().unwrap()).unwrap(),
            disc,
            profile,
            TachygramSetBridge::from(app.bridge_hash(Eq::from(contents).to_affine()).unwrap()),
        )
    );
    assert_eq!(bucket.pcd.commitments()[1], contents);
    assert!(app.verify_uncompressed(&bucket.pcd, &mut *rng).unwrap());
}

#[test]
fn qr_bucket_seal_rejects_a_stamp_absorption_as_intake_start() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let span = (pool.mint_anchor(), pool.block(BlockHeight(1)).anchor());
    let disc = shared_discriminant();
    let intake = pool.qr_root(app, span, disc);
    let witness = witness::qr_bucket_seal((*intake.pcd.data(), ()), Anchor::from(Fp::ZERO));
    let (forged, ()) = app
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness,
            intake.pcd,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
}

#[test]
fn qr_empty_intake_seed_spans_a_stampless_epoch() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch2 = EpochIndex::new(2);
    let epoch3 = epoch2.next().unwrap();
    let epoch4 = epoch3.next().unwrap();
    let pool = PoolSim::shared();
    let user = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let [nf2, nf3] = [epoch2, epoch3].map(|epoch| mk.derive_nullifier(epoch));

    let final2 = pool.block(epoch2.last_block()).anchor();
    let entry3 = pool.entry_anchor(epoch3);
    let entry4 = pool.entry_anchor(epoch4);
    assert_eq!(pool.block(epoch3.last_block()).anchor(), entry3);

    let discriminant = pool.epoch_discriminant(epoch3);
    let intake = QrIntakeEntry::empty(app, entry3, epoch3, discriminant);
    let bucket = intake.seal(rng, app, final2);
    let (epoch, anchor_start, anchor_next, _, profile, _) = *bucket.pcd.data();
    assert_eq!((epoch, anchor_start, anchor_next), (epoch3, entry3, entry4));
    assert_eq!(profile, QrProfile::ROOT);
    assert_eq!(
        bucket.pcd.commitments()[1],
        Eq::from(iter::empty().collect::<TachygramSetPoly>().commit()).to_affine()
    );

    let left = pool.unspent(app, (epoch2, epoch3), |_| nf2);
    let right = bucket.segment(rng, app, |_| nf3);

    let (fused, ()) = app
        .fuse(
            rng,
            UnspentFuse,
            witness::unspent_fuse((*left.data(), *right.data()), &[nf2], &[nf3]),
            left,
            right,
        )
        .unwrap();
    let (fused_anchor_start, _, fused_epoch_next, fused_anchor_next) = *fused.data();
    assert_eq!(fused_anchor_start, pool.entry_anchor(epoch2));
    assert_eq!(fused_epoch_next, epoch4);
    assert_eq!(fused_anchor_next, entry4);
    assert_eq!(
        fused.commitments()[0],
        Eq::from(NfSeqPoly::new(epoch2, &[nf2, nf3]).commit()).to_affine()
    );
    assert!(app.verify_uncompressed(&fused, &mut *rng).unwrap());
}

#[test]
fn qr_spendable_init_starts_a_spendable_that_reaches_spend_bind() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let epoch2 = epoch1.next().unwrap();
    let pool = PoolSim::shared();

    let span = pool.epoch_span(epoch0);
    let discriminant = shared_discriminant();
    let bucket = pool.qr_bucket(
        app,
        span,
        discriminant,
        Fp::from(Tachygram::from(note.commitment())),
        2,
        Anchor::from(Fp::ZERO),
    );
    let nf_bucket = pool.qr_bucket(
        app,
        span,
        discriminant,
        Fp::from(mk.derive_nullifier(epoch0)),
        2,
        Anchor::from(Fp::ZERO),
    );
    assert_ne!(bucket.pcd.data().4, nf_bucket.pcd.data().4);
    let (_, _, anchor_next, ..) = *bucket.pcd.data();
    assert_eq!(anchor_next, span.1.next_epoch(epoch1).unwrap());
    let unspent = user.bucket_unspent(rng, app, &nf_bucket, &note);

    let (spendable, ()) = app
        .fuse(rng, spendable::QrSpendableInit, (), unspent, bucket.pcd)
        .unwrap();
    assert_eq!(*spendable.data(), (note.commitment(), epoch1, anchor_next));

    let lifted = user.lift(
        rng,
        app,
        spendable,
        pool.unspent(app, (epoch1, epoch2), |epoch| mk.derive_nullifier(epoch)),
        &note,
    );
    let secret = user.note_secret(app, note);
    let rcv = value::Trapdoor::random(rng);
    let (bind, ()) = app
        .fuse(
            rng,
            spend::SpendBind,
            witness::spend_bind((*lifted.data(), *secret.data()), rcv),
            lifted,
            secret,
        )
        .unwrap();
    let (bind_cm, nf_current, nf_next, ..) = *bind.data();
    assert_eq!(bind_cm, note.commitment());
    assert_eq!(
        (nf_current, nf_next),
        (
            mk.derive_nullifier(epoch2),
            mk.derive_nullifier(EpochIndex::new(u32::from(epoch2) + 1))
        )
    );
    assert!(app.verify_uncompressed(&bind, &mut *rng).unwrap());
}

#[test]
fn qr_short_bucket_yields_evidence_no_suffix_can_extend() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(196);
    let user = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(500);
    let epoch = EpochIndex::new(0);
    let pool = PoolSim::shared();
    let short_anchor = pool.mint_anchor();
    let tip_anchor = pool.block(epoch.last_block()).anchor();
    assert_ne!(short_anchor, tip_anchor);

    let discriminant = shared_discriminant();
    let bucket = pool.qr_bucket(
        app,
        (Anchor::default(), short_anchor),
        discriminant,
        Fp::from(Tachygram::from(note.commitment())),
        0,
        Anchor::from(Fp::ZERO),
    );
    let epoch_next = epoch.next().unwrap();
    let unpublished = short_anchor.next_epoch(epoch_next).unwrap();
    assert_eq!(bucket.pcd.data().2, unpublished);
    let unspent = user.bucket_unspent(rng, app, &bucket, &note);
    let (spendable, ()) = app
        .fuse(rng, spendable::QrSpendableInit, (), unspent, bucket.pcd)
        .unwrap();
    assert_eq!(
        *spendable.data(),
        (note.commitment(), epoch_next, unpublished)
    );
    assert!(app.verify_uncompressed(&spendable, &mut *rng).unwrap());
    assert!(
        pool.stamps_between(Anchor::default(), tip_anchor)
            .iter()
            .all(|entry| entry.3 != unpublished)
    );

    let bound_next = user.note_unspent(app, pool, &note, (epoch_next, epoch_next.next().unwrap()));
    assert_ne!(bound_next.data().1, unpublished);
    let (forged, ()) = app
        .fuse(rng, spendable::SpendableLift, (), spendable, bound_next)
        .unwrap();
    assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
}

#[test]
fn qr_spendable_init_rejects_a_bucket_that_does_not_match_the_segment() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(500);
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    let pool = PoolSim::shared();
    let discriminant = shared_discriminant();

    let unspent0 = user.note_unspent(app, pool, &note, (epoch0, epoch1));
    let bucket1 = pool.epoch_bucket(app, epoch1);
    let unspent1 = user.note_unspent(app, pool, &note, (epoch1, epoch1.next().unwrap()));

    let fake_anchor_final_prev = Anchor::from(Fp::ONE);
    let members = [Tachygram::from(note.commitment())];
    let (intake, ()) = app
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(
                ((), ()),
                fake_anchor_final_prev.next_epoch(epoch1).unwrap(),
                epoch1,
                discriminant,
                &members,
            ),
        )
        .unwrap();
    let elsewhere = QrIntakeEntry {
        pcd: intake,
        members: members.to_vec(),
    }
    .seal(rng, app, fake_anchor_final_prev);

    for (unspent, bucket, expected) in vec![
        (
            unspent0.clone(),
            pool.qr_bucket(
                app,
                (Anchor::default(), pool.mint_anchor()),
                discriminant,
                Fp::from(Tachygram::from(note.commitment())),
                0,
                Anchor::from(Fp::ZERO),
            ),
            "a bucket that closes elsewhere",
        ),
        (unspent0, bucket1, "a bucket from another epoch"),
        (unspent1, elsewhere, "a bucket that opens elsewhere"),
    ]
    .into_boxed_slice()
    {
        let (forged, ()) = app
            .fuse(rng, spendable::QrSpendableInit, (), unspent, bucket.pcd)
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
            "{expected}"
        );
    }
}

#[test]
fn qr_spendable_init_rejects_an_absent_commitment() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch0 = EpochIndex::new(0);
    let pool = PoolSim::shared();
    let bucket = pool.epoch_bucket(app, epoch0);
    let unspent = user.bucket_unspent(rng, app, &bucket, &note);

    let (forged, ()) = app
        .fuse(rng, spendable::QrSpendableInit, (), unspent, bucket.pcd)
        .unwrap();
    assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
}

#[test]
fn qr_unspent_init_rejects_corrupted_inputs() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let cm = Tachygram::from(PoolSim::shared_note(500).commitment());
    let nf = iter::repeat_with(|| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))))
        .find(|&candidate| {
            qr_profile_of(Fp::from(candidate), disc, 2) == qr_profile_of(Fp::from(cm), disc, 2)
        })
        .unwrap();
    let bucket = pool.qr_bucket(app, span0, disc, Fp::from(nf), 2, Anchor::from(Fp::ZERO));
    let (epoch, ..) = *bucket.pcd.data();
    let witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into());

    for (bucket_pcd, init_witness, expected) in vec![
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.1[0].1 += Fp::ONE;
                forged
            },
            "a root shifted by one",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.1[5].0 = !forged.1[5].0;
                forged
            },
            "a root with a flipped side",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.2 = array::from_fn(|position| position == 0 || position == 2);
                forged
            },
            "a depth mask that is not a prefix",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.2 = QrProfile { depth: 3, bits: 0 }.depth_mask();
                forged
            },
            "a depth mask deeper than the bucket",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness;
                forged.3 = NfSeqPoly::new(
                    epoch,
                    &[Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)))],
                );
                forged
            },
            "a sequence with a foreign nullifier",
        ),
        (
            bucket.pcd.clone(),
            witness::qr_unspent_init(
                (*bucket.pcd.data(), ()),
                Tachygram::from(
                    iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
                        .find(|&value| qr_profile_of(value, disc, 2) != bucket.pcd.data().4)
                        .unwrap(),
                ),
            ),
            "a value outside the bucket's profile",
        ),
    ]
    .into_boxed_slice()
    {
        let (forged, ()) = app
            .fuse(
                rng,
                qr::QrUnspentInit,
                init_witness,
                bucket_pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
            "{expected}"
        );
    }

    for (bucket_pcd, init_witness) in [
        (
            bucket.pcd.clone(),
            witness::qr_unspent_init((*bucket.pcd.data(), ()), Tachygram::from(Fp::ZERO)),
        ),
        (
            bucket.pcd.clone(),
            witness::qr_unspent_init((*bucket.pcd.data(), ()), bucket.members[0]),
        ),
    ] {
        assert_matches!(
            app
                .fuse(
                    rng,
                    qr::QrUnspentInit,
                    init_witness,
                    bucket_pcd,
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .err(),
            Some(ragu::Error::InvalidWitness(err)) if err.to_string() == "division by zero"
        );
    }
}

#[test]
fn qr_unspent_init_rejects_the_fixed_point_on_the_non_residue_side() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let position = 1;
    let value = -disc.at(position);
    assert_ne!(value, Fp::ZERO);
    let nf = Nullifier::from(value);

    let bucket = pool.qr_bucket(app, span0, disc, value, 2, Anchor::from(Fp::ZERO));
    assert!(
        !bucket
            .members
            .iter()
            .any(|&member| Fp::from(member) == value)
    );
    let mut witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into());
    let (_, honest_roots, ..) = witness;
    assert_eq!(
        honest_roots[usize::try_from(position).unwrap()],
        QrClassRoot(true, Fp::ZERO)
    );
    let (accepted, ()) = app
        .fuse(
            rng,
            qr::QrUnspentInit,
            witness.clone(),
            bucket.pcd.clone(),
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(app.verify_uncompressed(&accepted, &mut *rng).unwrap());

    let (_, ref mut roots, ..) = witness;
    let QrClassRoot(ref mut side, _) = roots[usize::try_from(position).unwrap()];
    *side = false;
    assert_matches!(
        app
            .fuse(
                rng,
                qr::QrUnspentInit,
                witness,
                bucket.pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .err(),
        Some(ragu::Error::InvalidWitness(err)) if err.to_string()
            == "division by zero"
    );
}

#[test]
fn qr_bucket_seal_refuses_the_final_epoch() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let discriminant = QrDiscriminant::random(rng);
    let final_epoch = EpochIndex::new(EPOCH_MAX);
    let anchor_final_prev = Anchor::from(Fp::ONE);
    let intake = QrIntakeEntry::empty(
        app,
        anchor_final_prev.next_epoch(final_epoch).unwrap(),
        final_epoch,
        discriminant,
    );
    let witness = witness::qr_bucket_seal((*intake.pcd.data(), ()), anchor_final_prev);
    let (sealed, ()) = app
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness,
            intake.pcd,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(!app.verify_uncompressed(&sealed, &mut *rng).unwrap());
}

#[test]
fn qr_unspent_init_accepts_buckets_at_every_depth() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let [absent, exceptional, companion] = qr_profile_triplet();
    let intakes = pool.qr_descent(app, span0, disc, absent);
    for (depth, intake) in QR_DEPTHS.into_iter().zip(intakes) {
        assert_eq!(intake.pcd.data().4, qr_profile_of(absent, disc, depth));
        let bucket = intake.sealed(app, Anchor::from(Fp::ZERO));
        assert!(bucket.members.contains(&Tachygram::from(exceptional)));
        assert!(bucket.members.contains(&Tachygram::from(companion)));
        let nf = Nullifier::from(absent);
        let segment = bucket.segment(rng, app, |_| nf);
        assert_eq!(
            *segment.data(),
            (
                Anchor::default(),
                epoch0,
                epoch1,
                span0.1.next_epoch(epoch1).unwrap()
            )
        );
        assert_eq!(
            segment.commitments()[0],
            Eq::from(NfSeqPoly::new(epoch0, &[nf]).commit()).to_affine()
        );
        assert!(app.verify_uncompressed(&segment, &mut *rng).unwrap());
    }
}

#[test]
fn unspent_lift_carries_a_spendable() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let (epoch1, epoch2, epoch3) = (EpochIndex::new(1), EpochIndex::new(2), EpochIndex::new(3));

    let pool = PoolSim::shared();

    let spendable = user.spendable_at(app, pool, &note, epoch1);
    let segment = pool.unspent(app, (epoch1, epoch2), |epoch| mk.derive_nullifier(epoch));
    let bucket = pool.epoch_bucket(app, epoch2);
    let lift = witness::unspent_lift(
        (*segment.data(), *bucket.pcd.data()),
        mk.derive_nullifier(epoch2).into(),
        &[mk.derive_nullifier(epoch1)],
    );
    let lifted = app
        .fuse(rng, UnspentLift, lift, segment, bucket.pcd)
        .unwrap()
        .0;

    let carried = user.lift(rng, app, spendable, lifted, &note);
    assert_eq!(
        *carried.data(),
        (note.commitment(), epoch3, pool.entry_anchor(epoch3))
    );
    assert!(app.verify_uncompressed(&carried, &mut *rng).unwrap());
}

#[test]
fn unspent_lift_rejects_invalid_extensions() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (epoch0, epoch1, epoch2) = (EpochIndex::new(0), EpochIndex::new(1), EpochIndex::new(2));
    let pool = PoolSim::shared();
    let user = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let [nf0, nf1] = [epoch0, epoch1].map(|epoch| mk.derive_nullifier(epoch));
    let nf = |epoch: EpochIndex| if epoch == epoch0 { nf0 } else { nf1 };

    let segment = pool.unspent(app, (epoch0, epoch1), nf);
    let bucket = pool.epoch_bucket(app, epoch1);
    let past = pool.epoch_bucket(app, epoch2);
    let honest = witness::unspent_lift((*segment.data(), *bucket.pcd.data()), nf1.into(), &[nf0]);
    let (_, _, _, discriminant, ..) = *bucket.pcd.data();

    for (lift_bucket, lift, expected) in [
        (
            &past,
            witness::unspent_lift((*segment.data(), *past.pcd.data()), nf1.into(), &[nf0]),
            "a bucket from a later epoch",
        ),
        (
            &bucket,
            witness::unspent_lift((*segment.data(), *bucket.pcd.data()), nf1.into(), &[nf1]),
            "an extension that repeats the tested nullifier",
        ),
        (
            &bucket,
            {
                let mut forged = honest.clone();
                forged.3 = NfSeqPoly::new(
                    epoch0,
                    &[
                        nf0,
                        Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))),
                    ],
                );
                forged
            },
            "an extension with a foreign nullifier",
        ),
        (
            &bucket,
            {
                let mut forged = honest;
                forged.1 =
                    QrClassRoot::along(Fp::random(|bytes| rng.fill_bytes(bytes)), discriminant);
                forged
            },
            "a root for another value",
        ),
    ] {
        let (forged, ()) = app
            .fuse(
                rng,
                UnspentLift,
                lift,
                segment.clone(),
                lift_bucket.pcd.clone(),
            )
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
            "{expected}"
        );
    }

    assert_matches!(
        app
            .fuse(
                rng,
                UnspentLift,
                witness::unspent_lift(
                    (*segment.data(), *bucket.pcd.data()),
                    bucket.members[0],
                    &[nf0],
                ),
                segment,
                bucket.pcd,
            )
            .err(),
        Some(ragu::Error::InvalidWitness(err))
            if err.to_string() == "division by zero"
    );
}
