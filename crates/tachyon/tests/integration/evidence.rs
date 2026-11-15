use core::{assert_matches, iter};

use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
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
    pool::{PoolSim, small_epoch},
    qr::{EvidenceTreeEntry, QrIntakeEntry, shared_discriminant},
};

#[test]
fn evidence_tree_admission_rejects_substituted_contents() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);
    let intake = pool
        .qr_intakes(app, (Anchor::default(), final_anchor), discriminant, 0)
        .pop()
        .unwrap();
    let intake_pcd = intake.pcd.clone();
    let bucket = intake.seal(rng, app, Anchor::from(Fp::ZERO));
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
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);

    for depth in [2, 6] {
        let routed = pool.qr_intakes(app, (Anchor::default(), final_anchor), discriminant, depth);
        let ragged = routed
            .iter()
            .any(|intake| intake.pcd.data().4.depth < depth);
        assert_eq!(ragged, depth > 2);
        let sealed = routed
            .into_iter()
            .map(|intake| intake.seal(rng, app, Anchor::from(Fp::ZERO)))
            .collect::<Vec<_>>();
        let expected = sealed
            .iter()
            .map(|bucket| *bucket.pcd.data())
            .collect::<Vec<_>>();

        let tree = EvidenceTreeEntry::build(rng, app, sealed);
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

        for (leaf, bucket) in tree.leaves.iter().zip(&expected) {
            let replayed = tree.open(rng, app, leaf).unwrap();
            assert_eq!(*replayed.pcd.data(), *bucket);
        }
    }
}

#[test]
fn evidence_tree_padded_leaves_replay_the_last_bucket() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);

    let routed = pool.qr_intakes(app, (Anchor::default(), final_anchor), discriminant, 3);
    let sealed = routed
        .into_iter()
        .take(5)
        .map(|intake| intake.seal(rng, app, Anchor::from(Fp::ZERO)))
        .collect::<Vec<_>>();
    let expected = sealed
        .iter()
        .map(|bucket| *bucket.pcd.data())
        .collect::<Vec<_>>();
    let last = *expected.last().unwrap();

    let tree = EvidenceTreeEntry::build(rng, app, sealed);
    for (index, leaf) in tree.leaves.iter().enumerate() {
        let replayed = tree.open(rng, app, leaf).unwrap();
        let bucket = expected.get(index).copied().unwrap_or(last);
        assert_eq!(*replayed.pcd.data(), bucket);
    }
}

#[test]
fn evidence_tree_joins_reject_mismatched_trees() {
    let app = &application();
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let pool = PoolSim::shared();
    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.block(epoch1.last_block()).anchor();
    let discriminant = shared_discriminant();
    let value = Fp::random(|bytes| rng.fill_bytes(bytes));

    let bucket0 = pool.qr_bucket(
        app,
        (Anchor::default(), final0),
        discriminant,
        value,
        0,
        Anchor::from(Fp::ZERO),
    );
    let bucket1 = pool.qr_bucket(
        app,
        (pool.entry_anchor(epoch1), final1),
        discriminant,
        value,
        0,
        final0,
    );
    assert_matches!(
        app
            .fuse(
                rng,
                evidence::EvidenceTreeLeafPair,
                (),
                bucket0.pcd.clone(),
                bucket1.pcd.clone(),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "EvidenceTreeLeafPair: inputs cover different epochs"
    );
    let tree0 = EvidenceTreeEntry::build(rng, app, vec![bucket0]).pcd;
    let tree1 = EvidenceTreeEntry::build(rng, app, vec![bucket1]).pcd;

    let other_discriminant = QrDiscriminant::random(rng);
    let foreign = pool.qr_bucket(
        app,
        (Anchor::default(), final0),
        other_discriminant,
        value,
        0,
        Anchor::from(Fp::ZERO),
    );
    let short = pool.qr_bucket(
        app,
        (Anchor::default(), pool.mint_anchor()),
        discriminant,
        value,
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

    for (left, right, complaint) in [
        (
            tree0.clone(),
            tree1.clone(),
            "inputs cover different epochs",
        ),
        (
            tree0.clone(),
            EvidenceTreeEntry::build(rng, app, vec![foreign]).pcd,
            "inputs derive from different discriminants",
        ),
        (
            tree0,
            EvidenceTreeEntry::build(rng, app, vec![short]).pcd,
            "inputs close at different anchors",
        ),
        (
            tree1,
            EvidenceTreeEntry::build(rng, app, vec![elsewhere]).pcd,
            "inputs open at different anchors",
        ),
    ] {
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
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);
    let sealed = pool
        .qr_intakes(app, (Anchor::default(), final_anchor), discriminant, 2)
        .into_iter()
        .map(|intake| intake.seal(rng, app, Anchor::from(Fp::ZERO)))
        .collect::<Vec<_>>();
    let other_contents: TachygramSetPoly = sealed[1].members.iter().copied().collect();
    let tree = EvidenceTreeEntry::build(rng, app, sealed);
    let leaf = tree.leaves.first().unwrap();

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
    for (opened, profile, contents) in [
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
                    leaf.profile,
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
