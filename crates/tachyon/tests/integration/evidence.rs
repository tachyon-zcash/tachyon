use ragu::Proof;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, Tachygram,
    constants::{EPOCH_SIZE, EVIDENCE_TREE_ARITY},
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, evidence, qr},
    witness,
};

use crate::fixtures::{
    PoolSim, QrIntakeEntry, build_evidence_tree, build_qr_partition, open_evidence_tree,
    qr_bucket_at, random_block, seal_qr_intake, small_epoch,
};

#[test]
fn evidence_tree_replays_the_bucket_each_leaf_holds() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        2,
    );
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
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        evidence::EvidenceTreeLeafPair,
        (),
        bucket0.pcd.clone(),
        bucket1.pcd.clone(),
    ) {
        assert_eq!(
            err.to_string(),
            "EvidenceTreeLeafPair: inputs cover different epochs"
        );
    } else {
        panic!();
    }
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
        if let Err(ragu_core::Error::InvalidWitness(err)) =
            PROOF_SYSTEM.fuse(rng, evidence::EvidenceTreePairFuse, (), left, right)
        {
            assert_eq!(
                err.to_string(),
                format!("EvidenceTreePairFuse: {complaint}")
            );
        } else {
            panic!();
        }
        if let Err(ragu_core::Error::InvalidWitness(err)) =
            PROOF_SYSTEM.fuse(rng, evidence::EvidenceTreeFuse, (), left_pair, right_pair)
        {
            assert_eq!(err.to_string(), format!("EvidenceTreeFuse: {complaint}"));
        } else {
            panic!();
        }
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
    let other_contents = sealed[1].pcd.data().5;
    let tree = build_evidence_tree(rng, sealed);
    let leaf = tree.leaves.first().unwrap();

    let mut path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(
        &leaf.path[..evidence::EvidenceTreeDescend::LEVELS],
    )
    .unwrap();
    let (_sides, ref mut children) = path[0];
    children[EVIDENCE_TREE_ARITY - 1] =
        EvidenceTreeRoot(Fp::from(children[EVIDENCE_TREE_ARITY - 1]) + Fp::ONE);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        evidence::EvidenceTreeDescend,
        witness::evidence_tree_descend((*tree.pcd.data(), ()), path),
        tree.pcd.clone(),
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "EvidenceTreeDescend: children do not hash to the node"
        );
    } else {
        panic!();
    }

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
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap()
            .0;
    }
    let QrProfile { depth, bits } = leaf.profile;
    for (opened, profile, contents) in [
        (tree.pcd, leaf.profile, leaf.contents),
        (
            node.clone(),
            QrProfile {
                depth: depth + 1,
                bits,
            },
            leaf.contents,
        ),
        (
            node.clone(),
            QrProfile {
                depth,
                bits: bits ^ 1,
            },
            leaf.contents,
        ),
        (node, leaf.profile, other_contents),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            evidence::EvidenceTreeOpen,
            witness::evidence_tree_open((*opened.data(), ()), profile, contents),
            opened,
            Proof::bootstrap().carry::<()>(()),
        ) {
            assert_eq!(
                err.to_string(),
                "EvidenceTreeOpen: witnessed bucket is not the tree's leaf"
            );
        } else {
            panic!();
        }
    }
}
