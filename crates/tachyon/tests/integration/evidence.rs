use core::{assert_matches, iter};

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
    WithPolynomials,
    pool::PoolSim,
    qr::{QrIntakeEntry, shared_discriminant},
};

#[test]
fn evidence_tree_admission_rejects_substituted_contents() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::shared();
    let epoch0 = EpochIndex::new(0);
    let span0 = pool.epoch_span(epoch0);
    let disc = shared_discriminant();
    let intake = pool.qr_root(app, span0, disc);
    let intake_pcd = intake.pcd;
    let bucket = pool.epoch_bucket(app, epoch0);
    let honest = intake_pcd.polynomials()[0].clone();
    let mut substituted = honest.clone();
    substituted[0] += Fp::ONE;
    for polynomials in [
        [substituted.clone(), honest.clone()],
        [honest, substituted.clone()],
        [substituted.clone(), substituted],
    ] {
        assert!(
            app.fuse(
                rng,
                WithPolynomials(qr::QrBucketSeal, polynomials),
                witness::qr_bucket_seal((*intake_pcd.data(), ()), Anchor::from(Fp::ZERO)),
                intake_pcd.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .is_err()
        );
    }
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
    for (left, right) in [(forged.clone(), bucket.pcd.clone()), (bucket.pcd, forged)] {
        assert_matches!(
            app.fuse(rng, evidence::EvidenceTreeLeafPair, (), left, right).err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "child proof or carried header is not accepted by this application"
        );
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
    assert_matches!(
        app
            .fuse(
                rng,
                evidence::EvidenceTreeLeafPair,
                (),
                bucket0.pcd,
                bucket1.pcd.clone(),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "EvidenceTreeLeafPair: inputs cover different epochs"
    );
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

    let [tree1, foreign_tree, short_tree, elsewhere_tree] = [bucket1, foreign, short, elsewhere]
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
        });
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

    for (left, right, left_pair, right_pair, complaint) in [
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
    ] {
        assert_matches!(
            app
                .fuse(rng, evidence::EvidenceTreePairFuse, (), left, right)
                .err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == format!("EvidenceTreePairFuse: {complaint}")
        );
        assert_matches!(
            app
                .fuse(rng, evidence::EvidenceTreeFuse, (), left_pair, right_pair)
                .err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == format!("EvidenceTreeFuse: {complaint}")
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
    assert_matches!(
        app
            .fuse(
                rng,
                evidence::EvidenceTreeDescend,
                witness::evidence_tree_descend((*tree.pcd.data(), ()), path),
                tree.pcd.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "EvidenceTreeDescend: children do not hash to the node"
    );

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
    for (opened, profile, contents) in [
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
    ] {
        assert_matches!(
            app
                .fuse(
                    rng,
                    evidence::EvidenceTreeOpen,
                    witness::evidence_tree_open((*opened.data(), ()), profile, contents),
                    opened,
                    app.bootstrap_proof().clone().carry::<()>(()),
                )
                .err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "EvidenceTreeOpen: witnessed bucket is not the tree's leaf"
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
        assert_eq!(
            app.fuse(
                rng,
                WithPolynomials(evidence::EvidenceTreeOpen, polynomials),
                witness::evidence_tree_open(
                    (*node.data(), ()),
                    leaf.profile(),
                    leaf.contents.clone()
                ),
                node.clone(),
                app.bootstrap_proof().clone().carry::<()>(()),
            )
            .is_ok(),
            accepted,
        );
    }
}
