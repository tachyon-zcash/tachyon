use core::{assert_matches, iter};

use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetPoly,
    constants::{EPOCH_SIZE, EVIDENCE_TREE_ARITY},
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, evidence, qr},
    witness,
};

use crate::fixtures::{
    PoolSim, QrIntakeEntry, WithPolynomials, build_evidence_tree, build_qr_partition,
    open_evidence_tree, qr_bucket_at, random_block, seal_qr_intake, small_epoch,
};

#[test]
fn evidence_tree_admission_rejects_substituted_contents() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);
    let intake = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        0,
    )
    .pop()
    .unwrap();
    let intake_pcd = intake.pcd.clone();
    let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));
    let honest = intake_pcd.polynomials()[0].clone();
    let mut substituted = honest.clone();
    substituted[0] += Fp::ONE;
    for polynomials in [
        [substituted.clone(), honest.clone()],
        [honest, substituted.clone()],
        [substituted.clone(), substituted],
    ] {
        assert!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    WithPolynomials(qr::QrBucketSeal, polynomials),
                    witness::qr_bucket_seal((*intake_pcd.data(), ()), Anchor::from(Fp::ZERO)),
                    intake_pcd.clone(),
                    PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
                )
                .is_err()
        );
    }
    let replacement: TachygramSetPoly = iter::once(Tachygram::random(rng)).collect();
    let mut forged_header = *bucket.pcd.data();
    forged_header.5 = replacement.commit().bridge().unwrap();
    let forged = bucket
        .pcd
        .proof()
        .clone()
        .carry::<qr::QrBucket>(forged_header);
    for (left, right) in [(forged.clone(), bucket.pcd.clone()), (bucket.pcd, forged)] {
        assert_matches!(
            PROOF_SYSTEM.fuse(rng, evidence::EvidenceTreeLeafPair, (), left, right).err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == "child proof or carried header is not accepted by this application"
        );
    }
}

#[test]
fn evidence_tree_replays_the_bucket_each_leaf_holds() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);

    for depth in [2, 6] {
        let routed = build_qr_partition(
            rng,
            &pool,
            (Anchor::default(), final_anchor),
            discriminant,
            24,
            depth,
        );
        let ragged = routed
            .iter()
            .any(|intake| intake.pcd.data().4.depth < depth);
        assert_eq!(ragged, depth > 2);
        let sealed = routed
            .into_iter()
            .map(|intake| seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO)))
            .collect::<Vec<_>>();
        let expected = sealed
            .iter()
            .map(|bucket| *bucket.pcd.data())
            .collect::<Vec<_>>();

        let tree = build_evidence_tree(rng, sealed);
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
            let replayed = open_evidence_tree(rng, tree.pcd.clone(), leaf);
            assert_eq!(*replayed.pcd.data(), *bucket);
        }
    }
}

#[test]
fn evidence_tree_padded_leaves_replay_the_last_bucket() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        3,
    );
    let sealed = routed
        .into_iter()
        .take(5)
        .map(|intake| seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO)))
        .collect::<Vec<_>>();
    let expected = sealed
        .iter()
        .map(|bucket| *bucket.pcd.data())
        .collect::<Vec<_>>();
    let last = *expected.last().unwrap();

    let tree = build_evidence_tree(rng, sealed);
    for (index, leaf) in tree.leaves.iter().enumerate() {
        let replayed = open_evidence_tree(rng, tree.pcd.clone(), leaf);
        let bucket = expected.get(index).copied().unwrap_or(last);
        assert_eq!(*replayed.pcd.data(), bucket);
    }
}

#[test]
fn evidence_tree_joins_reject_mismatched_trees() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch1.last_block().0, |_| random_block(rng, 1, 1));
    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.block(epoch1.last_block()).anchor();
    let discriminant = QrDiscriminant::random(rng);
    let value = Fp::random(|bytes| rng.fill_bytes(bytes));

    let bucket0 = qr_bucket_at(
        rng,
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
        &pool,
        (final0.next_epoch(epoch1).unwrap(), final1),
        discriminant,
        EPOCH_SIZE as usize,
        0,
        value,
        final0,
    );
    assert_matches!(
        PROOF_SYSTEM
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
    let tree0 = build_evidence_tree(rng, vec![bucket0]).pcd;
    let tree1 = build_evidence_tree(rng, vec![bucket1]).pcd;

    let other_discriminant = QrDiscriminant::random(rng);
    let foreign = qr_bucket_at(
        rng,
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
    let (intake, ()) = PROOF_SYSTEM
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
        QrIntakeEntry {
            pcd: intake,
            members: members.to_vec(),
        },
        fake_anchor_final_prev,
    );

    for (left, right, complaint) in [
        (
            tree0.clone(),
            tree1.clone(),
            "inputs cover different epochs",
        ),
        (
            tree0.clone(),
            build_evidence_tree(rng, vec![foreign]).pcd,
            "inputs derive from different discriminants",
        ),
        (
            tree0,
            build_evidence_tree(rng, vec![short]).pcd,
            "inputs close at different anchors",
        ),
        (
            tree1,
            build_evidence_tree(rng, vec![elsewhere]).pcd,
            "inputs open at different anchors",
        ),
    ] {
        let left_pair = PROOF_SYSTEM
            .fuse(
                rng,
                evidence::EvidenceTreePairFuse,
                (),
                left.clone(),
                left.clone(),
            )
            .unwrap()
            .0;
        let right_pair = PROOF_SYSTEM
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
            PROOF_SYSTEM
                .fuse(rng, evidence::EvidenceTreePairFuse, (), left, right)
                .err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == format!("EvidenceTreePairFuse: {complaint}")
        );
        assert_matches!(
            PROOF_SYSTEM
                .fuse(rng, evidence::EvidenceTreeFuse, (), left_pair, right_pair)
                .err(),
            Some(ragu_core::Error::InvalidWitness(err))
                if err.to_string() == format!("EvidenceTreeFuse: {complaint}")
        );
    }
}

#[test]
fn evidence_tree_descend_and_open_reject_forgeries() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);
    let sealed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        2,
    )
    .into_iter()
    .map(|intake| seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO)))
    .collect::<Vec<_>>();
    let other_contents: TachygramSetPoly = sealed[1].members.iter().copied().collect();
    let tree = build_evidence_tree(rng, sealed);
    let leaf = tree.leaves.first().unwrap();

    let mut path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(
        &leaf.path[..evidence::EvidenceTreeDescend::LEVELS],
    )
    .unwrap();
    let (_sides, ref mut children) = path[0];
    children[EVIDENCE_TREE_ARITY - 1] =
        EvidenceTreeRoot(Fp::from(children[EVIDENCE_TREE_ARITY - 1]) + Fp::ONE);
    assert_matches!(
        PROOF_SYSTEM
            .fuse(
                rng,
                evidence::EvidenceTreeDescend,
                witness::evidence_tree_descend((*tree.pcd.data(), ()), path),
                tree.pcd.clone(),
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
            )
            .err(),
        Some(ragu_core::Error::InvalidWitness(err))
            if err.to_string() == "EvidenceTreeDescend: children do not hash to the node"
    );

    let mut node = tree.pcd.clone();
    for chunk in leaf.path.chunks(evidence::EvidenceTreeDescend::LEVELS) {
        node = PROOF_SYSTEM
            .fuse(
                rng,
                evidence::EvidenceTreeDescend,
                witness::evidence_tree_descend(
                    (*node.data(), ()),
                    <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(chunk).unwrap(),
                ),
                node,
                PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
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
            PROOF_SYSTEM
                .fuse(
                    rng,
                    evidence::EvidenceTreeOpen,
                    witness::evidence_tree_open((*opened.data(), ()), profile, contents),
                    opened,
                    PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
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
            PROOF_SYSTEM
                .fuse(
                    rng,
                    WithPolynomials(evidence::EvidenceTreeOpen, polynomials),
                    witness::evidence_tree_open(
                        (*node.data(), ()),
                        leaf.profile,
                        leaf.contents.clone()
                    ),
                    node.clone(),
                    PROOF_SYSTEM.bootstrap_proof().clone().carry::<()>(()),
                )
                .is_ok(),
            accepted,
        );
    }
}
