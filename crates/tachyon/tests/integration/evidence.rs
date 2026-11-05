use ragu::{Pcd, Proof};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetCommit,
    constants::EVIDENCE_TREE_ARITY,
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, evidence, qr},
    witness,
};

use crate::{
    fixtures::{
        EvidenceLeaf, PoolSim, QrIntakeEntry, WalletSim, build_evidence_tree,
        build_qr_partition, open_evidence_tree, random_block, seal_qr_intake, shared_sk,
    },
    qr::{EPOCH_MEMBERS, qr_bucket_at, qr_bucket_for, qr_epoch_unspent, small_epoch},
};

fn pair_trees(
    rng: &mut StdRng,
    left: Pcd<evidence::EvidenceTree>,
    right: Pcd<evidence::EvidenceTree>,
) -> ragu_core::Result<Pcd<evidence::EvidenceTreePair>> {
    PROOF_SYSTEM
        .fuse(rng, evidence::EvidenceTreePairFuse, (), left, right)
        .map(|(pair, ())| pair)
}

fn fuse_trees(
    rng: &mut StdRng,
    left: Pcd<evidence::EvidenceTreePair>,
    right: Pcd<evidence::EvidenceTreePair>,
) -> ragu_core::Result<Pcd<evidence::EvidenceTree>> {
    PROOF_SYSTEM
        .fuse(rng, evidence::EvidenceTreeFuse, (), left, right)
        .map(|(tree, ())| tree)
}

fn assert_both_joins_reject(
    rng: &mut StdRng,
    left: Pcd<evidence::EvidenceTree>,
    right: Pcd<evidence::EvidenceTree>,
    complaint: &str,
) {
    let left_pair = pair_trees(rng, left.clone(), left.clone()).unwrap();
    let right_pair = pair_trees(rng, right.clone(), right.clone()).unwrap();

    if let Err(ragu_core::Error::InvalidWitness(err)) = pair_trees(rng, left, right) {
        assert_eq!(
            err.to_string(),
            format!("EvidenceTreePairFuse: {complaint}")
        );
    } else {
        panic!();
    }
    if let Err(ragu_core::Error::InvalidWitness(err)) = fuse_trees(rng, left_pair, right_pair) {
        assert_eq!(err.to_string(), format!("EvidenceTreeFuse: {complaint}"));
    } else {
        panic!();
    }
}

fn descend_to_leaf(
    rng: &mut StdRng,
    tree: Pcd<evidence::EvidenceTree>,
    leaf: &EvidenceLeaf,
) -> Pcd<evidence::EvidenceTree> {
    let mut node = tree;
    for chunk in leaf.path.chunks(evidence::EvidenceTreeDescend::LEVELS) {
        let path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(chunk).unwrap();
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                evidence::EvidenceTreeDescend,
                witness::evidence_tree_descend((*node.data(), ()), path),
                node,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        node = pcd;
    }
    node
}

fn open_leaf(
    rng: &mut StdRng,
    tree: Pcd<evidence::EvidenceTree>,
    leaf: &EvidenceLeaf,
    profile: QrProfile,
    contents: TachygramSetCommit,
) -> ragu_core::Result<Pcd<qr::QrBucket>> {
    let node = descend_to_leaf(rng, tree, leaf);
    PROOF_SYSTEM
        .fuse(
            rng,
            evidence::EvidenceTreeOpen,
            witness::evidence_tree_open((*node.data(), ()), profile, contents),
            node,
            Proof::bootstrap().carry::<()>(()),
        )
        .map(|(bucket, ())| bucket)
}

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
    assert_eq!(routed.len(), 4);
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
    assert_eq!(routed.len(), 8);
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
    assert_eq!(tree.leaves.len(), 16);

    for (index, leaf) in tree.leaves.iter().enumerate() {
        let replayed = open_evidence_tree(rng, tree.pcd.clone(), leaf);
        let bucket = expected.get(index).copied().unwrap_or(last);
        assert_eq!(
            *replayed.pcd.data(),
            bucket,
            "leaf {index} replays its bucket, or the last for padding"
        );
    }
}

#[test]
fn a_replayed_bucket_starts_a_segment_that_binds_to_the_note() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.advance(epoch0.last_block().0, |_| random_block(rng, 1, 1));

    let bucket = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), pool.block(epoch0.last_block()).anchor()),
        EPOCH_MEMBERS,
        2,
        Fp::from(
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(epoch0),
        ),
        Anchor::from(Fp::ZERO),
    );
    let sealed = *bucket.pcd.data();
    let direct = qr_epoch_unspent(rng, &user, &note, &bucket);

    let tree = build_evidence_tree(rng, vec![bucket]);
    let leaf = tree.leaves.first().unwrap();
    let replayed = open_evidence_tree(rng, tree.pcd.clone(), leaf);
    assert_eq!(*replayed.pcd.data(), sealed);

    let bound = qr_epoch_unspent(rng, &user, &note, &replayed);
    assert_eq!(*bound.data(), *direct.data());
    let (cm, _, epoch_start, epoch_next, _) = *bound.data();
    assert_eq!(cm, note.commitment());
    assert_eq!((epoch_start, epoch_next), (epoch0, epoch1));
}

#[test]
fn evidence_tree_pair_fuse_rejects_a_bucket_of_another_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch1.last_block().0, |_| random_block(rng, 1, 1));
    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.block(epoch1.last_block()).anchor();
    let value = Fp::random(|bytes| rng.fill_bytes(bytes));

    let first = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), final0),
        EPOCH_MEMBERS,
        0,
        value,
        Anchor::from(Fp::ZERO),
    );
    let second = qr_bucket_for(
        rng,
        &pool,
        (final0.next_epoch(epoch1).unwrap(), final1),
        EPOCH_MEMBERS,
        0,
        value,
        final0,
    );

    let (left, right) = (
        build_evidence_tree(rng, vec![first]).pcd,
        build_evidence_tree(rng, vec![second]).pcd,
    );
    assert_both_joins_reject(rng, left, right, "inputs cover different epochs");
}

#[test]
fn evidence_tree_pair_fuse_rejects_a_bucket_of_another_network() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let value = Fp::random(|bytes| rng.fill_bytes(bytes));
    let span = (Anchor::default(), final_anchor);

    let first = qr_bucket_for(
        rng,
        &pool,
        span,
        EPOCH_MEMBERS,
        0,
        value,
        Anchor::from(Fp::ZERO),
    );
    let second = qr_bucket_for(
        rng,
        &pool,
        span,
        EPOCH_MEMBERS,
        0,
        value,
        Anchor::from(Fp::ZERO),
    );
    assert_ne!(first.pcd.data().3, second.pcd.data().3);

    let (left, right) = (
        build_evidence_tree(rng, vec![first]).pcd,
        build_evidence_tree(rng, vec![second]).pcd,
    );
    assert_both_joins_reject(
        rng,
        left,
        right,
        "inputs derive from different discriminants",
    );
}

#[test]
fn evidence_tree_pair_fuse_rejects_an_extent_that_closes_elsewhere() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);
    let value = Fp::random(|bytes| rng.fill_bytes(bytes));

    let whole = qr_bucket_at(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        EPOCH_MEMBERS,
        0,
        value,
        Anchor::from(Fp::ZERO),
    );
    let short = qr_bucket_at(
        rng,
        &pool,
        (Anchor::default(), pool.block(BlockHeight(1)).anchor()),
        discriminant,
        EPOCH_MEMBERS,
        0,
        value,
        Anchor::from(Fp::ZERO),
    );

    let (left, right) = (
        build_evidence_tree(rng, vec![whole]).pcd,
        build_evidence_tree(rng, vec![short]).pcd,
    );
    assert_both_joins_reject(rng, left, right, "inputs close at different anchors");
}

#[test]
fn evidence_tree_pair_fuse_rejects_an_extent_that_opens_elsewhere() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch1.last_block().0, |_| random_block(rng, 1, 1));
    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.block(epoch1.last_block()).anchor();
    let discriminant = QrDiscriminant::random(rng);
    let value = Fp::random(|bytes| rng.fill_bytes(bytes));

    let genuine = qr_bucket_at(
        rng,
        &pool,
        (final0.next_epoch(epoch1).unwrap(), final1),
        discriminant,
        EPOCH_MEMBERS,
        0,
        value,
        final0,
    );

    let fake_anchor_final_prev = Anchor::from(Fp::ONE);
    let fake_prev = fake_anchor_final_prev.next_epoch(epoch1).unwrap();
    let members = [Tachygram::random(rng)];
    let (intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), fake_prev, epoch1, discriminant, &members),
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

    let (left, right) = (
        build_evidence_tree(rng, vec![genuine]).pcd,
        build_evidence_tree(rng, vec![elsewhere]).pcd,
    );
    assert_both_joins_reject(rng, left, right, "inputs open at different anchors");
}

#[test]
fn evidence_tree_leaf_pair_rejects_a_bucket_of_another_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch1.last_block().0, |_| random_block(rng, 1, 1));
    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.block(epoch1.last_block()).anchor();
    let value = Fp::random(|bytes| rng.fill_bytes(bytes));

    let bucket0 = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), final0),
        EPOCH_MEMBERS,
        0,
        value,
        Anchor::from(Fp::ZERO),
    );
    let bucket1 = qr_bucket_for(
        rng,
        &pool,
        (final0.next_epoch(epoch1).unwrap(), final1),
        EPOCH_MEMBERS,
        0,
        value,
        final0,
    );
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        evidence::EvidenceTreeLeafPair,
        (),
        bucket0.pcd,
        bucket1.pcd,
    ) {
        assert_eq!(
            err.to_string(),
            "EvidenceTreeLeafPair: inputs cover different epochs"
        );
    } else {
        panic!();
    }
}

#[test]
fn evidence_tree_cap_is_transparent_to_a_descent() {
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
    let tree = build_evidence_tree(rng, sealed);

    let (epoch, anchor_start, anchor_next, network, root) = *tree.pcd.data();
    let (capped, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            evidence::EvidenceTreeCap,
            (),
            tree.pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let raised = *capped.data();
    assert_eq!(
        (raised.0, raised.1, raised.2, raised.3),
        (epoch, anchor_start, anchor_next, network)
    );
    assert_ne!(raised.4, root);
}

#[test]
fn evidence_tree_open_rejects_a_forged_leaf() {
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
    let other_contents = sealed.get(1).unwrap().pcd.data().5;

    let tree = build_evidence_tree(rng, sealed);
    let leaf = tree.leaves.first().unwrap();
    let QrProfile { depth, bits } = leaf.profile;

    let forgeries = [
        (
            QrProfile {
                depth: depth + 1,
                bits,
            },
            leaf.contents,
        ),
        (
            QrProfile {
                depth,
                bits: bits ^ 1,
            },
            leaf.contents,
        ),
        (leaf.profile, other_contents),
    ];
    for (profile, contents) in forgeries {
        if let Err(ragu_core::Error::InvalidWitness(err)) =
            open_leaf(rng, tree.pcd.clone(), leaf, profile, contents)
        {
            assert_eq!(
                err.to_string(),
                "EvidenceTreeOpen: witnessed bucket is not the tree's leaf"
            );
        } else {
            panic!();
        }
    }

    open_leaf(rng, tree.pcd.clone(), leaf, leaf.profile, leaf.contents).unwrap();
}

#[test]
fn evidence_tree_descend_rejects_children_that_miss_the_node() {
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
    let tree = build_evidence_tree(rng, sealed);
    let leaf = tree.leaves.first().unwrap();

    let mut path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(
        leaf.path
            .get(..evidence::EvidenceTreeDescend::LEVELS)
            .unwrap(),
    )
    .unwrap();
    let (_sides, ref mut children) = path[0];
    children[EVIDENCE_TREE_ARITY - 1] =
        EvidenceTreeRoot(Fp::from(children[EVIDENCE_TREE_ARITY - 1]) + Fp::ONE);

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        evidence::EvidenceTreeDescend,
        witness::evidence_tree_descend((*tree.pcd.data(), ()), path),
        tree.pcd,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "EvidenceTreeDescend: children do not hash to the node"
        );
    } else {
        panic!();
    }
}

#[test]
fn evidence_tree_open_rejects_a_node_presented_as_a_leaf() {
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
    let tree = build_evidence_tree(rng, sealed);
    let leaf = tree.leaves.first().unwrap();

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        evidence::EvidenceTreeOpen,
        witness::evidence_tree_open((*tree.pcd.data(), ()), leaf.profile, leaf.contents),
        tree.pcd,
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
