use core::iter;

use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::{curve::Projective as _, field::Field as _};
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetPoly,
    constants::{EPOCH_SIZE, EVIDENCE_TREE_ARITY},
    pasta::Fp,
    stamp::proof::{evidence, qr},
    witness,
};

use super::fixtures::application;
use crate::fixtures::{
    PoolSim, QrIntakeEntry, WithPolynomials, build_evidence_tree, build_qr_partition,
    open_evidence_tree, qr_bucket_at, random_block, seal_qr_intake, small_epoch,
    small_epoch_evidence,
};

#[test]
fn evidence_tree_admission_rejects_substituted_contents() {
    let app = &*application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);
    let intake = build_qr_partition(
        rng,
        app,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        0,
    )
    .pop()
    .unwrap();
    let intake_pcd = intake.pcd.clone();
    let bucket = seal_qr_intake(rng, app, intake, Anchor::from(Fp::ZERO));
    let honest = intake_pcd.polynomials()[0].clone();
    let mut substituted = honest.clone();
    substituted[0] += Fp::ONE;
    for polynomials in [
        [substituted.clone(), honest.clone()],
        [honest, substituted.clone()],
        [substituted.clone(), substituted],
    ] {
        let (forged, ()) = app
            .fuse(
                rng,
                WithPolynomials(qr::QrBucketSeal, polynomials),
                witness::qr_bucket_seal((*intake_pcd.data(), ()), Anchor::from(Fp::ZERO)),
                intake_pcd.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert!(!app.verify_uncompressed(&forged, &mut *rng).unwrap());
    }
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
    let (shallow_final_anchor, discriminant, shallow, shallow_tree) = small_epoch_evidence();
    let app = &*application();
    let rng = &mut StdRng::seed_from_u64(0);
    assert!(shallow.iter().all(|bucket| bucket.pcd.data().4.depth == 2));

    let (pool, ragged_final_anchor) = small_epoch(rng);
    let routed = build_qr_partition(
        rng,
        app,
        &pool,
        (Anchor::default(), ragged_final_anchor),
        discriminant,
        24,
        5,
    );
    assert!(routed.iter().any(|intake| intake.pcd.data().4.depth < 5));
    let ragged = routed
        .into_iter()
        .map(|intake| seal_qr_intake(rng, app, intake, Anchor::from(Fp::ZERO)))
        .collect::<Vec<_>>();
    let ragged_tree = build_evidence_tree(rng, app, ragged.clone());

    for (final_anchor, sealed, tree) in [
        (shallow_final_anchor, shallow, shallow_tree),
        (ragged_final_anchor, ragged, ragged_tree),
    ] {
        let (epoch, anchor_start, anchor_next, root_discriminant, _) = *tree.pcd.data();
        assert_eq!(
            (epoch, anchor_start, anchor_next, root_discriminant),
            (
                EpochIndex::new(0),
                Anchor::default(),
                final_anchor.next_epoch(EpochIndex::new(1)).unwrap(),
                discriminant
            )
        );
        for (leaf, bucket) in tree.leaves.iter().zip(&sealed) {
            let replayed = open_evidence_tree(rng, app, tree.pcd.clone(), leaf);
            assert_eq!(*replayed.pcd.data(), *bucket.pcd.data());
            assert!(app.verify_uncompressed(&replayed.pcd, &mut *rng).unwrap());
        }
    }
}

#[test]
fn evidence_tree_padded_leaves_replay_the_last_bucket() {
    let app = &*application();
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
        3,
    );
    let sealed = routed
        .into_iter()
        .take(5)
        .map(|intake| seal_qr_intake(rng, app, intake, Anchor::from(Fp::ZERO)))
        .collect::<Vec<_>>();
    let expected = sealed
        .iter()
        .map(|bucket| *bucket.pcd.data())
        .collect::<Vec<_>>();
    let last = *expected.last().unwrap();

    let tree = build_evidence_tree(rng, app, sealed);
    for (index, leaf) in tree.leaves.iter().enumerate() {
        let replayed = open_evidence_tree(rng, app, tree.pcd.clone(), leaf);
        let bucket = expected.get(index).copied().unwrap_or(last);
        assert_eq!(*replayed.pcd.data(), bucket);
        assert!(app.verify_uncompressed(&replayed.pcd, &mut *rng).unwrap());
    }
}

#[test]
fn evidence_tree_joins_reject_mismatched_trees() {
    let app = &*application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(2, |_| random_block(rng, 1, 1));
    pool.mine_through(rng, epoch1.last_block());
    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.block(epoch1.last_block()).anchor();
    let discriminant = QrDiscriminant::random(rng);
    let value = Fp::random(|bytes| rng.fill_bytes(bytes));

    let bucket0 = qr_bucket_at(
        rng,
        app,
        &pool,
        (Anchor::default(), final0),
        discriminant,
        EPOCH_SIZE as usize,
        0,
        value,
        Anchor::from(Fp::ZERO),
    );
    let bucket1 = qr_bucket_at(
        rng,
        app,
        &pool,
        (final0.next_epoch(epoch1).unwrap(), final1),
        discriminant,
        EPOCH_SIZE as usize,
        0,
        value,
        final0,
    );
    let (forged, ()) = app
        .fuse(
            rng,
            evidence::EvidenceTreeLeafPair,
            (),
            bucket0.pcd.clone(),
            bucket1.pcd.clone(),
        )
        .unwrap();
    assert!(
        !app.verify_uncompressed(&forged, &mut *rng).unwrap(),
        "EvidenceTreeLeafPair: inputs cover different epochs"
    );
    let tree0 = build_evidence_tree(rng, app, vec![bucket0]).pcd;
    let tree1 = build_evidence_tree(rng, app, vec![bucket1]).pcd;
    assert!(app.verify_uncompressed(&tree0, &mut *rng).unwrap());

    let other_discriminant = QrDiscriminant::random(rng);
    let foreign = qr_bucket_at(
        rng,
        app,
        &pool,
        (Anchor::default(), final0),
        other_discriminant,
        EPOCH_SIZE as usize,
        0,
        value,
        Anchor::from(Fp::ZERO),
    );
    let short = qr_bucket_at(
        rng,
        app,
        &pool,
        (Anchor::default(), pool.block(BlockHeight(1)).anchor()),
        discriminant,
        EPOCH_SIZE as usize,
        0,
        value,
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
    let elsewhere = seal_qr_intake(
        rng,
        app,
        QrIntakeEntry {
            pcd: intake,
            members: members.to_vec(),
        },
        fake_anchor_final_prev,
    );

    for (left, right, complaint) in vec![
        (
            tree0.clone(),
            tree1.clone(),
            "inputs cover different epochs",
        ),
        (
            tree0.clone(),
            build_evidence_tree(rng, app, vec![foreign]).pcd,
            "inputs derive from different discriminants",
        ),
        (
            tree0,
            build_evidence_tree(rng, app, vec![short]).pcd,
            "inputs close at different anchors",
        ),
        (
            tree1,
            build_evidence_tree(rng, app, vec![elsewhere]).pcd,
            "inputs open at different anchors",
        ),
    ]
    .into_boxed_slice()
    {
        let left_pair = app
            .fuse(
                rng,
                evidence::EvidenceTreePairFuse,
                (),
                left.clone(),
                left.clone(),
            )
            .unwrap()
            .0;
        let right_pair = app
            .fuse(
                rng,
                evidence::EvidenceTreePairFuse,
                (),
                right.clone(),
                right.clone(),
            )
            .unwrap()
            .0;
        assert!(app.verify_uncompressed(&left_pair, &mut *rng).unwrap());
        let (forged_pair, ()) = app
            .fuse(rng, evidence::EvidenceTreePairFuse, (), left, right)
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged_pair, &mut *rng).unwrap(),
            "EvidenceTreePairFuse: {complaint}"
        );
        let (forged_tree, ()) = app
            .fuse(rng, evidence::EvidenceTreeFuse, (), left_pair, right_pair)
            .unwrap();
        assert!(
            !app.verify_uncompressed(&forged_tree, &mut *rng).unwrap(),
            "EvidenceTreeFuse: {complaint}"
        );
    }
}

#[test]
fn evidence_tree_descend_and_open_reject_forgeries() {
    let (_, _, sealed, tree) = small_epoch_evidence();
    let app = &*application();
    let rng = &mut StdRng::seed_from_u64(0);
    let other_contents: TachygramSetPoly = sealed[1].members.iter().copied().collect();
    let leaf = tree.leaves.first().unwrap();

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
    assert!(
        !app.verify_uncompressed(&forged_descent, &mut *rng).unwrap(),
        "EvidenceTreeDescend: children do not hash to the node"
    );

    let mut node = tree.pcd.clone();
    for chunk in leaf.path.chunks(evidence::EvidenceTreeDescend::LEVELS) {
        node = app
            .fuse(
                rng,
                evidence::EvidenceTreeDescend,
                witness::evidence_tree_descend(
                    (*node.data(), ()),
                    <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(chunk).unwrap(),
                ),
                node,
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap()
            .0;
    }
    let QrProfile { depth, bits } = leaf.profile;
    for (opened, profile, contents) in vec![
        (tree.pcd, leaf.profile, leaf.contents.clone()),
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
        (node.clone(), leaf.profile, other_contents),
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
        assert!(
            !app.verify_uncompressed(&forged_open, &mut *rng).unwrap(),
            "EvidenceTreeOpen: witnessed bucket is not the tree's leaf"
        );
    }

    let honest: Vec<_> = leaf.contents.as_ref().iter_coeffs().collect();
    let mut substituted = honest.clone();
    substituted[0] += Fp::ONE;
    for (polynomials, accepted) in [
        ([honest.clone(), honest.clone()], true),
        ([substituted.clone(), honest.clone()], false),
        ([honest, substituted.clone()], false),
        ([substituted.clone(), substituted], false),
    ] {
        let (opened, ()) = app
            .fuse(
                rng,
                WithPolynomials(evidence::EvidenceTreeOpen, polynomials),
                witness::evidence_tree_open(
                    (*node.data(), ()),
                    leaf.profile,
                    leaf.contents.clone(),
                ),
                node.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .unwrap();
        assert_eq!(
            app.verify_uncompressed(&opened, &mut *rng).unwrap(),
            accepted,
        );
    }
}
