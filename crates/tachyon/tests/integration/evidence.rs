use core::iter;

use ragu::Polynomial;
use rand::{SeedableRng as _, rngs::StdRng};
use udon::{curve::Projective as _, field::Field as _};
use zcash_tachyon::{
    Anchor, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, Tachygram, TachygramSetPoly,
    constants::EVIDENCE_TREE_ARITY,
    pasta::Fp,
    stamp::proof::{evidence, qr},
    witness,
};

use super::fixtures::application;
use crate::fixtures::{
    pool::PoolSim,
    qr::{QrIntakeEntry, shared_discriminant},
};

#[test]
fn evidence_tree_admission_rejects_substituted_contents() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let bucket = pool.epoch_bucket(app, epoch0);
    let (accepted, ()) = app
        .fuse(
            rng,
            evidence::EvidenceTreeLeafPair,
            (),
            bucket.pcd.clone(),
            bucket.pcd.clone(),
        )
        .unwrap();
    assert!(app.verify_uncompressed(&accepted, &mut *rng).unwrap());
    let replacement: TachygramSetPoly = iter::once(Tachygram::random(rng)).collect();
    let mut forged_header = *bucket.pcd.data();
    forged_header.5 = app
        .bridge_hash(replacement.commit().as_ref().to_affine())
        .unwrap()
        .into();
    let forged = bucket
        .pcd
        .proof()
        .clone()
        .carry::<qr::QrBucket>(forged_header);
    for (left, right) in
        vec![(forged.clone(), bucket.pcd.clone()), (bucket.pcd, forged)].into_boxed_slice()
    {
        let (parent, ()) = app
            .fuse(rng, evidence::EvidenceTreeLeafPair, (), left, right)
            .unwrap();
        assert!(!app.verify_uncompressed(&parent, &mut *rng).unwrap());
    }
}

#[test]
fn evidence_tree_replays_the_bucket_each_leaf_holds() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let tree = pool.evidence_tree(app);
    let real = &tree.leaves[..tree.real_leaves];
    assert!(real.iter().any(|leaf| leaf.profile().depth < 5));
    assert!(real.iter().filter(|leaf| !leaf.members.is_empty()).count() > 1);
    let (epoch, anchor_start, anchor_next, root_discriminant, _) = *tree.pcd.data();
    assert_eq!(
        (epoch, anchor_start, anchor_next, root_discriminant),
        (
            epoch0,
            Anchor::default(),
            span0.1.next_epoch(EpochIndex::new(1)).unwrap(),
            disc
        )
    );
    for leaf in real {
        let replayed = tree.open(rng, app, leaf).unwrap();
        assert_eq!(*replayed.pcd.data(), leaf.header);
        assert!(app.verify_uncompressed(&replayed.pcd, &mut *rng).unwrap());
    }
}

#[test]
fn evidence_tree_padded_leaves_replay_the_last_bucket() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let tree = pool.evidence_tree(app);
    let len = tree.real_leaves;
    let last = &tree.leaves[len - 1];
    assert_ne!(last.members, []);
    for range in [
        len..len.next_multiple_of(4),
        len.next_multiple_of(4)..len.next_multiple_of(16),
        len.next_multiple_of(16)..64,
    ] {
        assert!(!range.is_empty());
        for index in [range.start, range.end - 1].into_iter().take(range.len()) {
            let replayed = tree.open(rng, app, &tree.leaves[index]).unwrap();
            assert_eq!(*replayed.pcd.data(), last.header);
            assert!(app.verify_uncompressed(&replayed.pcd, &mut *rng).unwrap());
        }
    }
}

#[test]
fn evidence_tree_joins_reject_mismatched_trees() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let pool = PoolSim::shared();
    let span0 = pool.epoch_span(epoch0);
    let span1 = pool.epoch_span(epoch1);
    let discriminant = shared_discriminant();
    let tree0 = pool.evidence_tree(app).pcd;

    let bucket0 = pool.epoch_bucket(app, epoch0);
    let bucket1 = pool.qr_bucket(app, span1, discriminant, Fp::ZERO, 0, span0.1);
    let (forged, ()) = app
        .fuse(
            rng,
            evidence::EvidenceTreeLeafPair,
            (),
            bucket0.pcd,
            bucket1.pcd.clone(),
        )
        .unwrap();
    assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
    assert!(app.verify_uncompressed(&tree0, &mut *rng).unwrap());

    let other_discriminant = QrDiscriminant::random(rng);
    let foreign = pool.qr_bucket(
        app,
        span0,
        other_discriminant,
        Fp::ZERO,
        0,
        Anchor::from(Fp::ZERO),
    );
    let short = pool.qr_bucket(
        app,
        (Anchor::default(), pool.mint_anchor()),
        discriminant,
        Fp::ZERO,
        0,
        Anchor::from(Fp::ZERO),
    );
    let fake_anchor_final_prev = Anchor::from(Fp::ONE);
    let members = [Tachygram::random(rng)];
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

    let mut mismatches = vec![bucket1, foreign, short, elsewhere]
        .into_iter()
        .map(|bucket| {
            let (pair, ()) = app
                .fuse(
                    rng,
                    evidence::EvidenceTreeLeafPair,
                    (),
                    bucket.pcd.clone(),
                    bucket.pcd,
                )
                .unwrap();
            app.fuse(rng, evidence::EvidenceTreeFuse, (), pair.clone(), pair)
                .unwrap()
                .0
        })
        .collect::<Vec<_>>()
        .into_iter();
    let tree1 = mismatches.next().unwrap();
    let foreign_tree = mismatches.next().unwrap();
    let short_tree = mismatches.next().unwrap();
    let elsewhere_tree = mismatches.next().unwrap();
    let [pair0, pair1, foreign_pair, short_pair, elsewhere_pair] =
        [&tree0, &tree1, &foreign_tree, &short_tree, &elsewhere_tree].map(|tree| {
            app.fuse(
                rng,
                evidence::EvidenceTreePairFuse,
                (),
                (*tree).clone(),
                (*tree).clone(),
            )
            .unwrap()
            .0
        });

    for (left, right, left_pair, right_pair, complaint) in vec![
        (
            tree0.clone(),
            tree1.clone(),
            pair0.clone(),
            pair1.clone(),
            "inputs cover different epochs",
        ),
        (
            tree0.clone(),
            foreign_tree,
            pair0.clone(),
            foreign_pair,
            "inputs derive from different discriminants",
        ),
        (
            tree0,
            short_tree,
            pair0,
            short_pair,
            "inputs close at different anchors",
        ),
        (
            tree1,
            elsewhere_tree,
            pair1,
            elsewhere_pair,
            "inputs open at different anchors",
        ),
    ]
    .into_boxed_slice()
    {
        assert!(app.verify_uncompressed(&left_pair, &mut *rng).unwrap());
        let (forged_pair, ()) = app
            .fuse(rng, evidence::EvidenceTreePairFuse, (), left, right)
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged_pair, &mut *rng).unwrap(),
            "{complaint}"
        );
        let (forged_tree, ()) = app
            .fuse(rng, evidence::EvidenceTreeFuse, (), left_pair, right_pair)
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged_tree, &mut *rng).unwrap(),
            "{complaint}"
        );
    }
}

#[test]
fn evidence_tree_descend_and_open_reject_forgeries() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let tree = pool.evidence_tree(app);
    let index = tree.real_leaves - 1;
    let other_contents = tree.leaves[..tree.real_leaves]
        .iter()
        .find(|leaf| leaf.index != index && !leaf.members.is_empty())
        .unwrap()
        .contents
        .clone();
    let leaf = &tree.leaves[index];

    let mut path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(
        &leaf.path[..evidence::EvidenceTreeDescend::LEVELS],
    )
    .unwrap();
    let (_sides, ref mut children) = path[0];
    children[EVIDENCE_TREE_ARITY - 1] =
        EvidenceTreeRoot(Fp::from(children[EVIDENCE_TREE_ARITY - 1]) + Fp::ONE);
    let (forged_descent, ()) = app
        .fuse(
            rng,
            evidence::EvidenceTreeDescend,
            witness::evidence_tree_descend((*tree.pcd.data(), ()), path),
            tree.pcd.clone(),
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(!app.verify_uncompressed(&forged_descent, &mut *rng).unwrap());

    let mut node = tree.pcd.clone();
    for chunk in leaf.path.chunks(evidence::EvidenceTreeDescend::LEVELS) {
        let descent_path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(chunk).unwrap();
        node = app
            .fuse(
                rng,
                evidence::EvidenceTreeDescend,
                witness::evidence_tree_descend((*node.data(), ()), descent_path),
                node,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap()
            .0;
    }
    let QrProfile { depth, bits } = leaf.profile();
    let mut shifted_coeffs: Vec<_> = leaf.contents.as_ref().iter_coeffs().collect();
    shifted_coeffs[0] += Fp::ONE;
    let substituted = TachygramSetPoly::arbitrary(Polynomial::from_coeffs(shifted_coeffs));
    for (opened, profile, contents) in vec![
        (tree.pcd, leaf.profile(), leaf.contents.clone()),
        (
            node.clone(),
            QrProfile {
                depth: depth + 1,
                bits,
            },
            leaf.contents.clone(),
        ),
        (
            node.clone(),
            QrProfile {
                depth,
                bits: bits ^ 1,
            },
            leaf.contents.clone(),
        ),
        (node.clone(), leaf.profile(), other_contents),
        (node.clone(), leaf.profile(), substituted),
    ]
    .into_boxed_slice()
    {
        let (forged_open, ()) = app
            .fuse(
                rng,
                evidence::EvidenceTreeOpen,
                witness::evidence_tree_open((*opened.data(), ()), profile, contents),
                opened,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(!app.verify_uncompressed(&forged_open, &mut *rng).unwrap());
    }

    let (opened, ()) = app
        .fuse(
            rng,
            evidence::EvidenceTreeOpen,
            witness::evidence_tree_open((*node.data(), ()), leaf.profile(), leaf.contents.clone()),
            node,
            app.bootstrap_proof().clone().carry::<()>(()),
        )
        .unwrap();
    assert!(app.verify_uncompressed(&opened, &mut *rng).unwrap());
}
