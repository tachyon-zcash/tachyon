extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::{array, assert_matches, iter, mem};

use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::{curve::Projective as _, field::Field as _};
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetBridge, TachygramSetPoly,
    constants::{EPOCH_MAX, EPOCH_SIZE},
    nullifier::Nullifier,
    pasta::{Eq, Fp},
    stamp::proof::{
        pool::{UnspentFuse, UnspentLift},
        qr, spend, spendable, summary,
    },
    value, witness,
};

use super::fixtures::application;
use crate::fixtures::{
    PoolSim, QrIntakeEntry, WalletSim, WithPolynomials, build_evidence_tree_with_scales,
    build_qr_partition, build_unspent_pcd_over_epochs, epoch_bucket, open_evidence_tree,
    qr_bucket_at, qr_bucket_segment, qr_epoch_unspent, qr_profile_of, random_block,
    random_block_with, scaled_qr_contents, seal_qr_intake, seed_qr_empty_intake, shared_sk,
    small_epoch, split_qr_intake, split_qr_intake_with_factors, try_open_evidence_tree,
};

#[test]
fn qr_summary_intake_starts_a_root_from_a_summary() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let members: [Tachygram; 6] = array::from_fn(|_| Tachygram::random(rng));

    let (summary, ()) = app
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .unwrap();
    let (_, _, anchor_end) = *summary.data();
    let acc_commit = summary.commitments()[0];
    let (root, ()) = app
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), discriminant),
            summary,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();

    assert_eq!(
        *root.data(),
        (epoch, start, anchor_end, discriminant, QrProfile::ROOT)
    );
    assert_eq!(root.commitments()[0], acc_commit);
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
        Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == "invalid anchor step"
    );
}

#[test]
fn qr_intake_split_partitions_the_contents_by_class() {
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

    let (residue, non_residue): (Vec<Tachygram>, Vec<Tachygram>) = members
        .iter()
        .copied()
        .partition(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0);
    assert!(!residue.is_empty() && !non_residue.is_empty());

    let (split, ()) = app
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();

    let non_residue_commit = non_residue
        .iter()
        .copied()
        .collect::<TachygramSetPoly>()
        .commit();
    let non_residue_hash = TachygramSetBridge::from(
        app.bridge_hash(non_residue_commit.as_ref().to_affine())
            .unwrap(),
    );
    let stamp_commit = members
        .iter()
        .copied()
        .collect::<TachygramSetPoly>()
        .commit();
    assert_eq!(
        *split.data(),
        (
            epoch,
            start,
            start.next_stamp(epoch, &stamp_commit).unwrap(),
            discriminant,
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
}

#[test]
fn qr_intake_split_rejects_a_forged_partition() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let members: [Tachygram; 8] = array::from_fn(|_| Tachygram::random(rng));

    let (root, ()) = app
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &members),
        )
        .unwrap();

    let mut split_witness = witness::qr_intake_split((*root.data(), ()), &members);
    split_witness.1 = split_witness.0.clone();
    assert_matches!(
        app
            .fuse(
                rng,
                qr::QrIntakeSplit,
                split_witness,
                root,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrIntakeSplit: the sides do not partition the contents"
    );
}

#[test]
fn qr_intake_split_rejects_an_empty_intake() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let intake = seed_qr_empty_intake(rng, app, start, EpochIndex::new(3), discriminant);

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
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrIntakeSplit: an empty intake cannot be split"
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
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrSideDescend: the two sides are the same set"
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
    let root = build_qr_partition(rng, app, &duplicate, span, disc, 2, 0)
        .pop()
        .unwrap();
    let factors = [(vec![member], scale), (vec![member], inverse)];
    let [child] = split_qr_intake_with_factors(rng, app, root, [!side], &factors);
    assert!(app.verify_differential(&child.pcd, &mut *rng).unwrap());
    assert_eq!(child.members, [member]);
    assert_eq!(child.pcd.data().4, QrProfile::ROOT.descend(!side));

    let single = PoolSim::genesis_with(vec![vec![member]]);
    let single_span = (Anchor::default(), single.anchor());
    let root_single = build_qr_partition(rng, app, &single, single_span, disc, 1, 0)
        .pop()
        .unwrap();
    let occupied = (vec![member], scale);
    let empty = (Vec::new(), inverse);
    let split = if side {
        [empty, occupied]
    } else {
        [occupied, empty]
    };
    let [rootless] = split_qr_intake_with_factors(rng, app, root_single, [!side], &split);
    assert!(app.verify_differential(&rootless.pcd, &mut *rng).unwrap());
    assert_ne!(
        rootless.pcd.commitments()[0],
        Eq::from(scaled_qr_contents(&[], Fp::ONE).commit()).to_affine()
    );
    let deep = Fp::from(11u64);
    let factors_deep = [
        (Vec::new(), deep),
        (Vec::new(), (scale * deep).invert().unwrap()),
    ];
    let [deeper] = split_qr_intake_with_factors(rng, app, rootless, [false], &factors_deep);
    let sealed = seal_qr_intake(rng, app, deeper, zero);
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
    let note = user.random_note(400);
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
    let root = build_qr_partition(rng, app, &pool, span, disc, 1, 0)
        .pop()
        .unwrap();
    let (honest_non_residue, honest_residue) = split_qr_intake(rng, app, root.clone());
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
    let scaled = split_qr_intake_with_factors(rng, app, root, [side, !side], &factors);
    let deep = Fp::from(11u64);
    let factors_deep = [(vec![], deep), (vec![], (scale * deep).invert().unwrap())];
    let [deep_intake] =
        split_qr_intake_with_factors(rng, app, scaled[1].clone(), [deep_bit], &factors_deep);
    let deep_bucket = seal_qr_intake(rng, app, deep_intake, zero);
    let [honest_held, honest_empty] = honest.map(|entry| seal_qr_intake(rng, app, entry, zero));
    let [scaled_held, scaled_empty] = scaled.map(|entry| seal_qr_intake(rng, app, entry, zero));
    for (left, right) in [(&honest_held, &scaled_held), (&honest_empty, &scaled_empty)] {
        assert_eq!(left.pcd.data().4, right.pcd.data().4);
        assert_ne!(left.pcd.data().5, right.pcd.data().5);
        assert_eq!(left.pcd.data().2, right.pcd.data().2);
    }
    let tree = build_evidence_tree_with_scales(
        rng,
        app,
        vec![
            scaled_held.clone(),
            scaled_empty.clone(),
            honest_held.clone(),
            honest_empty.clone(),
        ],
        vec![scale, inverse, Fp::ONE, Fp::ONE],
    );
    let [opened_scaled, opened_honest] =
        [0, 2].map(|index| open_evidence_tree(rng, app, tree.pcd.clone(), &tree.leaves[index]));
    assert_eq!(opened_scaled.pcd.data(), scaled_held.pcd.data());
    assert_eq!(opened_honest.pcd.data(), honest_held.pcd.data());
    for (index, wrong_scale) in [(0, Fp::ONE), (2, scale)] {
        let mut leaf = tree.leaves[index].clone();
        leaf.contents = scaled_qr_contents(&leaf.members, wrong_scale);
        assert_matches!(
            try_open_evidence_tree(rng, app, tree.pcd.clone(), &leaf).err(),
            Some(ragu_core::Error::InvalidWitness(_))
        );
    }
    let rcv = value::Trapdoor::random(rng);
    let mut spends = Vec::new();
    for bucket in [&opened_honest, &opened_scaled] {
        let unspent = qr_epoch_unspent(rng, app, &user, &note, bucket);
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
        let secret = user.secret_pcd(rng, app, note);
        let bind_witness = witness::spend_bind((*spendable.data(), *secret.data()), rcv);
        let (bind, ()) = app
            .fuse(rng, spend::SpendBind, bind_witness, spendable, secret)
            .unwrap();
        assert!(app.verify_differential(&bind, &mut *rng).unwrap());
        let (bound_cm, current, next, anchor, pk, _) = *bind.data();
        spends.push((bound_cm, current, next, anchor, Fp::from(pk)));
        for empty in [&honest_empty, &scaled_empty, &deep_bucket] {
            assert_matches!(
                app.fuse(
                    rng,
                    spendable::QrSpendableInit,
                    (),
                    unspent.clone(),
                    empty.pcd.clone()
                )
                .err(),
                Some(ragu_core::Error::InvalidWitness(_))
            );
        }
    }
    assert_eq!(spends[0], spends[1]);
    for empty in [&honest_empty, &scaled_empty, &deep_bucket] {
        let unspent = qr_epoch_unspent(rng, app, &user, &other, empty);
        assert!(app.verify_differential(&unspent, &mut *rng).unwrap());
        for bucket in [&honest_held, &scaled_held, empty] {
            assert_matches!(
                app.fuse(
                    rng,
                    spendable::QrSpendableInit,
                    (),
                    unspent.clone(),
                    bucket.pcd.clone()
                )
                .err(),
                Some(ragu_core::Error::InvalidWitness(_))
            );
        }
        assert_matches!(
            app.fuse(
                rng,
                qr::QrUnspentInit,
                witness::qr_unspent_init((*empty.pcd.data(), ()), nf.into()),
                empty.pcd.clone(),
                app.bootstrap_proof().clone().carry::<()>(())
            )
            .err(),
            Some(ragu_core::Error::InvalidWitness(_))
        );
    }
}

#[test]
fn scaled_duplicate_split_answers_as_a_monic_stray_bucket() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(280);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(400);
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
        let root = build_qr_partition(rng, app, &pool, span, disc, 2, 0)
            .pop()
            .unwrap();
        let held = (root.members.clone(), Fp::ONE);
        let empty = (vec![], Fp::ONE);
        let honest_factors = if side { [empty, held] } else { [held, empty] };
        let [held_intake] =
            split_qr_intake_with_factors(rng, app, root.clone(), [side], &honest_factors);
        let child = (vec![cm], scale);
        let other = (vec![sibling], scale.invert().unwrap());
        let factors = if side { [child, other] } else { [other, child] };
        let [stray] = split_qr_intake_with_factors(rng, app, root, [!side], &factors);
        let [held_bucket, stray_bucket] = [held_intake, stray]
            .map(|entry| seal_qr_intake(rng, app, entry, Anchor::from(Fp::ZERO)));
        assert_eq!(stray_bucket.pcd.data().4, QrProfile::ROOT.descend(!side));
        let unspent = qr_epoch_unspent(rng, app, &user, &note, &held_bucket);
        for (bucket, rejection) in [
            (&held_bucket, "QrUnspentInit: found nullifier in the bucket"),
            (
                &stray_bucket,
                "QR profile: value does not take the bucket's profile",
            ),
        ] {
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
                Some(ragu_core::Error::InvalidWitness(error)) if error.to_string() == rejection
            );
        }
        let segment = qr_bucket_segment(rng, app, &stray_bucket, |_| Nullifier::from(absent));
        assert!(app.verify_differential(&segment, &mut *rng).unwrap());
    }
}

#[test]
fn qr_side_select_checks_the_exceptional_value_at_its_depth() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    for depth in [0, 1, 31] {
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
            let (non_residue_side, residue_side) = split_qr_intake(rng, app, intake);
            intake = if side { residue_side } else { non_residue_side };
        }
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
            app.fuse(
                rng,
                qr::QrSideSelect,
                witness::qr_side_select((*honest_sides.data(), ()), &intake.members, side),
                honest_sides.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
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
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string()
                == "QrSideSelect: exceptional value claimed the non-residue class"
        );
    }
}

#[test]
fn qr_side_descend_carries_each_side_one_level_down() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    for members in [
        vec![Tachygram::from(-Fp::from(discriminant))],
        iter::repeat_with(|| Tachygram::random(rng))
            .take(12)
            .collect(),
    ] {
        let (root, ()) = app
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &members),
            )
            .unwrap();
        let (_, _, anchor_end, ..) = *root.data();
        let (split, ()) = app
            .fuse(
                rng,
                qr::QrIntakeSplit,
                witness::qr_intake_split((*root.data(), ()), &members),
                root,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();

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
                child.commitments()[0],
                Eq::from(
                    side_members
                        .iter()
                        .copied()
                        .collect::<TachygramSetPoly>()
                        .commit()
                )
                .to_affine()
            );
        }
    }
}

#[test]
fn qr_side_select_defers_hint_validation_to_descent() {
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
            root,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();

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
        assert_matches!(
            app.fuse(
                rng,
                qr::QrSideDescend,
                witness::qr_side_descend((*sides.data(), *selection.data()), side),
                sides.clone(),
                selection,
            ).err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "QrSideDescend: the sibling fails its class decomposition"
        );
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
            "QrSideDescend: selection epoch does not match sides",
        ),
        (
            epoch,
            foreign_start,
            discriminant,
            members.as_slice(),
            "QrSideDescend: selection anchor_prev does not match sides",
        ),
        (
            epoch,
            start,
            discriminant,
            &members[..11],
            "QrSideDescend: selection anchor_end does not match sides",
        ),
        (
            epoch,
            start,
            foreign_discriminant,
            members.as_slice(),
            "QrSideDescend: selection discriminant does not match sides",
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
        assert_matches!(
            app.fuse(
                rng,
                qr::QrSideDescend,
                witness::qr_side_descend((*sides.data(), *selection.data()), false),
                sides.clone(),
                selection,
            ).err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
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
    assert_matches!(app.fuse(
        rng, qr::QrSideDescend, witness::qr_side_descend((*sides.data(), *selection.data()), false), sides, selection,
    ).err(), Some(ragu_core::Error::InvalidWitness(err))
        if err.to_string() == "QrSideDescend: selection non-residue hash does not match sides");
}

#[test]
fn qr_side_descend_rejects_a_child_short_of_a_member() {
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

    let (mut short_residue, mut padded_non_residue): (Vec<Tachygram>, Vec<Tachygram>) = members
        .iter()
        .copied()
        .partition(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0);
    let smuggled = short_residue.pop().unwrap();
    padded_non_residue.push(smuggled);
    let mut split_witness = witness::qr_intake_split((*root.data(), ()), &members);
    split_witness.0 = padded_non_residue.iter().copied().collect();
    split_witness.1 = short_residue.iter().copied().collect();
    let (sides, ()) = app
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            root,
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
        assert_matches!(
            app
                .fuse(
                    rng,
                    qr::QrSideDescend,
                    witness::qr_side_descend((*sides.data(), *selection.data()), true),
                    sides.clone(),
                    selection,
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "QrSideDescend: the sibling fails its class decomposition"
        );
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
    let (.., child_profile) = *child.data();
    assert_eq!(child_profile, QrProfile::ROOT.descend(false));
    assert_eq!(
        child.commitments()[0],
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
fn qr_side_descend_refuses_a_full_register() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let members: [Tachygram; 2] = array::from_fn(|_| Tachygram::random(rng));

    let (root, ()) = app
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &members),
        )
        .unwrap();

    let mut intake = QrIntakeEntry {
        pcd: root,
        members: members.to_vec(),
    };
    let followed = Fp::from(members[0]);
    for level in 0..u32::BITS {
        let (non_residue, residue) = split_qr_intake(rng, app, intake);
        intake = if qr::classify(followed, discriminant.at(level)).0 {
            residue
        } else {
            non_residue
        };
    }
    let (.., profile) = *intake.pcd.data();
    assert_eq!(profile, qr_profile_of(followed, discriminant, u32::BITS));

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
    assert_matches!(
        app
            .fuse(
                rng,
                qr::QrSideDescend,
                witness::qr_side_descend((*sides.data(), *selection.data()), true),
                sides,
                selection,
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrSideDescend: profile has no bit left for another side"
    );
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
        merged.commitments()[0],
        Eq::from(union.commit()).to_affine()
    );
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
            "QrIntakeMerge: left.anchor_end must equal right.anchor_prev",
        ),
        (
            junction,
            epoch.next().unwrap(),
            discriminant,
            "QrIntakeMerge: inputs cover different epochs",
        ),
        (
            junction,
            epoch,
            QrDiscriminant::random(rng),
            "QrIntakeMerge: inputs derive from different discriminants",
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
        assert_matches!(
            app
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
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
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
    assert_matches!(
        app
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
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrIntakeMerge: inputs sit at different depths"
    );
}

#[test]
fn qr_bucket_seal_seals_a_fully_routed_intake() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);

    let routed = build_qr_partition(
        rng,
        app,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        2,
    );
    let intake = routed.into_iter().next().unwrap();
    let (epoch, anchor_prev, _, _, profile) = *intake.pcd.data();
    let contents = intake.pcd.commitments()[0];
    let bucket = seal_qr_intake(rng, app, intake, Anchor::from(Fp::ZERO));

    assert_eq!(
        *bucket.pcd.data(),
        (
            epoch,
            anchor_prev,
            final_anchor.next_epoch(epoch.next().unwrap()).unwrap(),
            discriminant,
            profile,
            TachygramSetBridge::from(app.bridge_hash(Eq::from(contents).to_affine()).unwrap()),
        )
    );
    assert_eq!(bucket.pcd.commitments()[0], contents);
}

#[test]
fn qr_bucket_seal_rejects_a_stamp_absorption_as_intake_start() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, _) = small_epoch(rng);
    let final_anchor = pool.block(BlockHeight(2)).anchor();
    let discriminant = QrDiscriminant::random(rng);
    let start = pool.block(BlockHeight(0)).anchor();

    let routed = build_qr_partition(rng, app, &pool, (start, final_anchor), discriminant, 12, 1);
    let intake = routed.into_iter().next().unwrap();
    let witness = witness::qr_bucket_seal((*intake.pcd.data(), ()), Anchor::from(Fp::ZERO));
    assert_matches!(
        app
            .fuse(
                rng,
                qr::QrBucketSeal,
                witness,
                intake.pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err)) if err.to_string()
            == "QrBucketSeal: witnessed boundary digest does not match intake's first anchor"
    );
}

#[test]
fn qr_empty_intake_seed_rejects_nonempty_output_slot() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let witness = witness::qr_empty_intake_seed(
        ((), ()),
        Anchor::default(),
        EpochIndex::new(0),
        QrDiscriminant::random(rng),
    );
    assert_matches!(
        app.seed(
            rng,
            WithPolynomials(qr::QrEmptyIntakeSeed, [vec![Fp::ONE, Fp::ONE], vec![Fp::ONE]]),
            witness,
        ).err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrEmptyIntakeSeed: contents must be one"
    );
}

#[test]
fn qr_empty_intake_seed_spans_a_stampless_epoch() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let epoch2 = epoch1.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch0.last_block().0, |_| random_block(rng, 1, 1));
    pool.advance(EPOCH_SIZE, |_| Vec::new());
    pool.mine(random_block(rng, 1, 1));
    let [nf0, nf1] = array::from_fn(|_| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))));

    let final0 = pool.block(epoch0.last_block()).anchor();
    let entry1 = pool.block(epoch1.first_block()).prev;
    let entry2 = pool.block(epoch2.first_block()).prev;
    assert_eq!(pool.block(epoch1.last_block()).anchor(), entry1);

    let discriminant = QrDiscriminant::random(rng);
    let intake = seed_qr_empty_intake(rng, app, entry1, epoch1, discriminant);
    let bucket = seal_qr_intake(rng, app, intake, final0);
    let (epoch, anchor_start, anchor_next, _, profile, _) = *bucket.pcd.data();
    assert_eq!((epoch, anchor_start, anchor_next), (epoch1, entry1, entry2));
    assert_eq!(profile, QrProfile::ROOT);
    assert_eq!(
        bucket.pcd.commitments()[0],
        Eq::from(iter::empty().collect::<TachygramSetPoly>().commit()).to_affine()
    );

    let bucket0 = qr_bucket_at(
        rng,
        app,
        &pool,
        (Anchor::default(), final0),
        discriminant,
        EPOCH_SIZE as usize,
        0,
        Fp::from(nf0),
        Anchor::from(Fp::ZERO),
    );
    let left = qr_bucket_segment(rng, app, &bucket0, |_| nf0);
    let right = qr_bucket_segment(rng, app, &bucket, |_| nf1);

    let (fused, ()) = app
        .fuse(
            rng,
            UnspentFuse,
            witness::unspent_fuse((*left.data(), *right.data()), &[nf0], &[nf1]),
            left,
            right,
        )
        .unwrap();
    let (fused_anchor_start, _, fused_epoch_next, fused_anchor_next) = *fused.data();
    assert_eq!(fused_anchor_start, Anchor::default());
    assert_eq!(fused_epoch_next, epoch2);
    assert_eq!(fused_anchor_next, entry2);
    assert_eq!(
        fused.commitments()[0],
        Eq::from(NfSeqPoly::new(epoch0, &[nf0, nf1]).commit()).to_affine()
    );
}

#[test]
fn qr_spendable_init_starts_a_spendable_that_reaches_spend_bind() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(400);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let epoch2 = epoch1.next().unwrap();
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.advance(epoch2.first_block().0, |_| random_block(rng, 1, 1));

    let span = (Anchor::default(), pool.block(epoch0.last_block()).anchor());
    let discriminant = QrDiscriminant::random(rng);
    let bucket = qr_bucket_at(
        rng,
        app,
        &pool,
        span,
        discriminant,
        EPOCH_SIZE as usize,
        2,
        Fp::from(Tachygram::from(note.commitment())),
        Anchor::from(Fp::ZERO),
    );
    let nf_bucket = qr_bucket_at(
        rng,
        app,
        &pool,
        span,
        discriminant,
        EPOCH_SIZE as usize,
        2,
        Fp::from(mk.derive_nullifier(epoch0)),
        Anchor::from(Fp::ZERO),
    );
    assert_ne!(bucket.pcd.data().4, nf_bucket.pcd.data().4);
    let (_, _, anchor_next, ..) = *bucket.pcd.data();
    assert_eq!(anchor_next, span.1.next_epoch(epoch1).unwrap());
    let unspent = qr_epoch_unspent(rng, app, &user, &note, &nf_bucket);

    let (spendable, ()) = app
        .fuse(rng, spendable::QrSpendableInit, (), unspent, bucket.pcd)
        .unwrap();
    assert_eq!(*spendable.data(), (note.commitment(), epoch1, anchor_next));

    let lifted = user.lift_to_epoch(rng, app, &pool, &note, spendable, epoch2);
    let secret = user.secret_pcd(rng, app, note);
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
}

#[test]
fn qr_short_bucket_yields_evidence_no_suffix_can_extend() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(196);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch = EpochIndex::new(0);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    let short_anchor = pool.anchor();
    pool.mine(random_block(rng, 2, 1));
    let tip_anchor = pool.anchor();
    assert_ne!(short_anchor, tip_anchor);
    assert_eq!(pool.height().epoch(), epoch);

    let discriminant = QrDiscriminant::random(rng);
    let bucket = qr_bucket_at(
        rng,
        app,
        &pool,
        (Anchor::default(), short_anchor),
        discriminant,
        1,
        0,
        Fp::from(Tachygram::from(note.commitment())),
        Anchor::from(Fp::ZERO),
    );
    let epoch_next = epoch.next().unwrap();
    let unpublished = short_anchor.next_epoch(epoch_next).unwrap();
    assert_eq!(bucket.pcd.data().2, unpublished);
    let unspent = qr_epoch_unspent(rng, app, &user, &note, &bucket);
    let (spendable, ()) = app
        .fuse(rng, spendable::QrSpendableInit, (), unspent, bucket.pcd)
        .unwrap();
    assert_eq!(
        *spendable.data(),
        (note.commitment(), epoch_next, unpublished)
    );
    assert!(
        pool.stamps_between(Anchor::default(), tip_anchor)
            .iter()
            .all(|entry| entry.3 != unpublished)
    );

    pool.advance(epoch_next.last_block().0 - pool.height().0, |_| {
        random_block(rng, 1, 1)
    });
    let next = build_unspent_pcd_over_epochs(
        rng,
        app,
        &pool,
        |covered| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(covered)
        },
        (epoch_next, epoch_next.next().unwrap()),
    );
    let bound_next = user.unspent_bind(rng, app, next, &note);
    assert_ne!(bound_next.data().1, unpublished);
    assert_matches!(
        app
            .fuse(rng, spendable::SpendableLift, (), spendable, bound_next)
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "SpendableLift: unspent not adjacent to spendable"
    );
}

#[test]
fn qr_spendable_init_rejects_a_bucket_that_does_not_match_the_segment() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.advance(epoch1.last_block().0, |_| random_block(rng, 1, 1));
    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.block(epoch1.last_block()).anchor();
    let discriminant = QrDiscriminant::random(rng);

    let bucket0 = qr_bucket_at(
        rng,
        app,
        &pool,
        (Anchor::default(), final0),
        discriminant,
        EPOCH_SIZE as usize,
        0,
        Fp::from(mk.derive_nullifier(epoch0)),
        Anchor::from(Fp::ZERO),
    );
    let unspent0 = qr_epoch_unspent(rng, app, &user, &note, &bucket0);
    let bucket1 = qr_bucket_at(
        rng,
        app,
        &pool,
        (final0.next_epoch(epoch1).unwrap(), final1),
        discriminant,
        EPOCH_SIZE as usize,
        0,
        Fp::from(mk.derive_nullifier(epoch1)),
        final0,
    );
    let unspent1 = qr_epoch_unspent(rng, app, &user, &note, &bucket1);

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
    let elsewhere = seal_qr_intake(
        rng,
        app,
        QrIntakeEntry {
            pcd: intake,
            members: members.to_vec(),
        },
        fake_anchor_final_prev,
    );

    for (unspent, bucket, expected) in [
        (
            unspent0.clone(),
            qr_bucket_at(
                rng,
                app,
                &pool,
                (Anchor::default(), pool.block(BlockHeight(1)).anchor()),
                discriminant,
                EPOCH_SIZE as usize,
                0,
                Fp::from(Tachygram::from(note.commitment())),
                Anchor::from(Fp::ZERO),
            ),
            "QrSpendableInit: segment does not close where the bucket does",
        ),
        (
            unspent0,
            bucket1,
            "QrSpendableInit: segment does not start in the bucket's epoch",
        ),
        (
            unspent1,
            elsewhere,
            "QrSpendableInit: segment does not open where the bucket does",
        ),
    ] {
        assert_matches!(
            app
                .fuse(
                    rng,
                    spendable::QrSpendableInit,
                    (),
                    unspent,
                    bucket.pcd,
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
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
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch0.last_block().0, |_| random_block(rng, 1, 1));

    let discriminant = QrDiscriminant::random(rng);
    let bucket = qr_bucket_at(
        rng,
        app,
        &pool,
        (Anchor::default(), pool.block(epoch0.last_block()).anchor()),
        discriminant,
        EPOCH_SIZE as usize,
        0,
        Fp::from(Tachygram::from(note.commitment())),
        Anchor::from(Fp::ZERO),
    );
    let unspent = qr_epoch_unspent(rng, app, &user, &note, &bucket);

    assert_matches!(
        app
            .fuse(
                rng,
                spendable::QrSpendableInit,
                (),
                unspent,
                bucket.pcd,
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrSpendableInit: commitment not in bucket"
    );
}

#[test]
fn qr_unspent_init_rejects_corrupted_inputs() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let nf = Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let discriminant = QrDiscriminant::random(rng);
    let bucket = qr_bucket_at(
        rng,
        app,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        2,
        Fp::from(nf),
        Anchor::from(Fp::ZERO),
    );
    let (epoch, ..) = *bucket.pcd.data();
    let witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into());

    for (bucket_pcd, init_witness, expected) in [
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.1[0].1 += Fp::ONE;
                forged
            },
            "QR profile: root does not square to the claimed class",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.1[5].0 = !forged.1[5].0;
                forged
            },
            "QR profile: root does not square to the claimed class",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.2 = array::from_fn(|position| position == 0 || position == 2);
                forged
            },
            "QR profile: depth mask is not a prefix",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.2 = QrProfile { depth: 3, bits: 0 }.depth_mask();
                forged
            },
            "QR profile: depth mask does not match the bucket's depth",
        ),
        (
            bucket.pcd.clone(),
            witness::qr_unspent_init((*bucket.pcd.data(), ()), Tachygram::from(Fp::ZERO)),
            "QrUnspentInit: tested value is zero",
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
            "QrUnspentInit: sequence does not match the tested pair",
        ),
        (
            bucket.pcd.clone(),
            witness::qr_unspent_init((*bucket.pcd.data(), ()), bucket.members[0]),
            "QrUnspentInit: found nullifier in the bucket",
        ),
        (
            bucket.pcd.clone(),
            witness::qr_unspent_init(
                (*bucket.pcd.data(), ()),
                Tachygram::from(
                    iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
                        .find(|&value| qr_profile_of(value, discriminant, 2) != bucket.pcd.data().4)
                        .unwrap(),
                ),
            ),
            "QR profile: value does not take the bucket's profile",
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
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
    }
}

#[test]
fn qr_unspent_init_rejects_the_fixed_point_on_the_non_residue_side() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);
    let position = 1;
    let value = -discriminant.at(position);
    assert_ne!(value, Fp::ZERO);
    let nf = Nullifier::from(value);

    let bucket = qr_bucket_at(
        rng,
        app,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        2,
        value,
        Anchor::from(Fp::ZERO),
    );
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
    app.fuse(
        rng,
        qr::QrUnspentInit,
        witness.clone(),
        bucket.pcd.clone(),
        app.bootstrap_proof().clone().carry::<()>(()),
    )
    .unwrap();

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
        Some(ragu_core::Error::InvalidWitness(err)) if err.to_string()
            == "QR profile: exceptional discriminant claimed the non-residue class"
    );
}

#[test]
fn qr_bucket_seal_refuses_the_final_epoch() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let discriminant = QrDiscriminant::random(rng);
    let final_epoch = EpochIndex::new(EPOCH_MAX);
    let anchor_final_prev = Anchor::from(Fp::ONE);
    let intake = seed_qr_empty_intake(
        rng,
        app,
        anchor_final_prev.next_epoch(final_epoch).unwrap(),
        final_epoch,
        discriminant,
    );
    let witness = witness::qr_bucket_seal((*intake.pcd.data(), ()), anchor_final_prev);
    assert_matches!(
        app
            .fuse(
                rng,
                qr::QrBucketSeal,
                witness,
                intake.pcd,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "QrBucketSeal: crossing past the final epoch"
    );
}

#[test]
fn qr_unspent_init_accepts_buckets_at_every_depth() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (mut pool, _) = small_epoch(rng);
    let epoch = BlockHeight(0).epoch();
    let epoch_next = epoch.next().unwrap();
    let discriminant = QrDiscriminant::random(rng);

    // An element `n - discriminant` takes the quadratic character of `n + level`
    // at each level, and the 32 consecutive characters from 40621 match those
    // from 126676, so the member shares the absent value's whole profile.
    let value = Fp::from(40_621u64) - Fp::from(discriminant);
    let member = Fp::from(126_676u64) - Fp::from(discriminant);
    assert_ne!(value, member);
    assert_eq!(
        qr_profile_of(value, discriminant, u32::BITS),
        qr_profile_of(member, discriminant, u32::BITS)
    );
    pool.mine(vec![vec![Tachygram::from(member)]]);
    let final_anchor = pool.block(pool.height()).anchor();

    for depth in [0, 1, 31, u32::BITS] {
        let bucket = qr_bucket_at(
            rng,
            app,
            &pool,
            (Anchor::default(), final_anchor),
            discriminant,
            32,
            depth,
            value,
            Anchor::from(Fp::ZERO),
        );
        assert!(bucket.members.contains(&Tachygram::from(member)));
        let nf = Nullifier::from(value);
        let segment = qr_bucket_segment(rng, app, &bucket, |_| nf);
        assert_eq!(
            *segment.data(),
            (
                Anchor::default(),
                epoch,
                epoch_next,
                final_anchor.next_epoch(epoch_next).unwrap()
            )
        );
        assert_eq!(
            segment.commitments()[0],
            Eq::from(NfSeqPoly::new(epoch, &[nf]).commit()).to_affine()
        );
    }
}

#[test]
fn unspent_lift_carries_a_spendable() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let (epoch1, epoch2, epoch3) = (EpochIndex::new(1), EpochIndex::new(2), EpochIndex::new(3));

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 2));
    pool.advance(epoch3.first_block().0 - pool.height().0, |_| {
        random_block(rng, 1, 2)
    });

    let spendable = user.spendable_at(rng, app, &pool, &note, epoch1);
    let first = epoch_bucket(rng, app, &pool, epoch1);
    let segment = qr_bucket_segment(rng, app, &first, |epoch| mk.derive_nullifier(epoch));
    let bucket = epoch_bucket(rng, app, &pool, epoch2);
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
        (
            note.commitment(),
            epoch3,
            pool.block(epoch3.first_block()).prev
        )
    );
}

#[test]
fn unspent_lift_rejects_invalid_extensions() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (epoch0, epoch1, epoch2) = (EpochIndex::new(0), EpochIndex::new(1), EpochIndex::new(2));
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(EpochIndex::new(3).first_block().0, |_| {
        random_block(rng, 1, 2)
    });
    let [nf0, nf1] = array::from_fn(|_| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))));
    let nf = |epoch: EpochIndex| if epoch == epoch0 { nf0 } else { nf1 };

    let first = epoch_bucket(rng, app, &pool, epoch0);
    let segment = qr_bucket_segment(rng, app, &first, nf);
    let bucket = epoch_bucket(rng, app, &pool, epoch1);
    let past = epoch_bucket(rng, app, &pool, epoch2);
    let honest = witness::unspent_lift((*segment.data(), *bucket.pcd.data()), nf1.into(), &[nf0]);
    let (_, _, _, discriminant, ..) = *bucket.pcd.data();

    for (lift_bucket, lift, expected) in [
        (
            &past,
            witness::unspent_lift((*segment.data(), *past.pcd.data()), nf1.into(), &[nf0]),
            "UnspentLift: the bucket does not start where the segment ends",
        ),
        (
            &bucket,
            witness::unspent_lift(
                (*segment.data(), *bucket.pcd.data()),
                bucket.members[0],
                &[nf0],
            ),
            "UnspentLift: found nullifier in the bucket",
        ),
        (
            &bucket,
            witness::unspent_lift((*segment.data(), *bucket.pcd.data()), nf1.into(), &[nf1]),
            "UnspentLift: extended is not elapsed with the tested pair",
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
            "UnspentLift: extended is not elapsed with the tested pair",
        ),
        (
            &bucket,
            {
                let mut forged = honest;
                forged.1 =
                    QrClassRoot::along(Fp::random(|bytes| rng.fill_bytes(bytes)), discriminant);
                forged
            },
            "QR profile: root does not square to the claimed class",
        ),
    ] {
        assert_matches!(
            app
                .fuse(
                    rng,
                    UnspentLift,
                    lift,
                    segment.clone(),
                    lift_bucket.pcd.clone(),
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err)) if err.to_string() == expected
        );
    }
}
