//! Evidence trees: folding sealed QR buckets under one root and replaying them.

use ff::Field as _;
use pasta_curves::Fp;
use ragu::{Pcd, Proof};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetCommit,
    constants::EVIDENCE_TREE_ARITY,
    stamp::proof::{PROOF_SYSTEM, evidence, qr},
    witness,
};

use crate::{
    fixtures::{
        EvidenceLeaf, PoolSim, QrBucketEntry, QrIntakeEntry, WalletSim, build_evidence_tree,
        build_qr_partition, open_evidence_tree, random_block, seal_qr_intake, shared_sk,
    },
    qr::{
        EPOCH_MEMBERS, invalid_witness, qr_bucket_at, qr_bucket_for, qr_epoch_unspent, small_epoch,
    },
};

/// One sealed bucket as a one-leaf [`evidence::EvidenceTree`].
fn tree_of(rng: &mut StdRng, bucket: QrBucketEntry) -> Pcd<evidence::EvidenceTree> {
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            evidence::EvidenceTreeLeaf,
            (),
            bucket.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("EvidenceTreeLeaf");
    pcd
}

/// Pair two trees as half a node.
fn pair_trees(
    rng: &mut StdRng,
    left: Pcd<evidence::EvidenceTree>,
    right: Pcd<evidence::EvidenceTree>,
) -> ragu_core::Result<Pcd<evidence::EvidenceTreePair>> {
    PROOF_SYSTEM
        .fuse(rng, evidence::EvidenceTreePairFuse, (), left, right)
        .map(|(pair, ())| pair)
}

/// Join four trees under a fresh node, two pairs at a time.
fn fuse_trees(
    rng: &mut StdRng,
    left: Pcd<evidence::EvidenceTreePair>,
    right: Pcd<evidence::EvidenceTreePair>,
) -> ragu_core::Result<Pcd<evidence::EvidenceTree>> {
    PROOF_SYSTEM
        .fuse(rng, evidence::EvidenceTreeFuse, (), left, right)
        .map(|(tree, ())| tree)
}

/// Both joins check the same four fields, so a network mismatch is rejected
/// whether the two trees meet at a pair or one level up at a node.
fn assert_both_joins_reject(
    rng: &mut StdRng,
    left: Pcd<evidence::EvidenceTree>,
    right: Pcd<evidence::EvidenceTree>,
    complaint: &str,
) {
    let left_pair = pair_trees(rng, left.clone(), left.clone()).expect("one tree twice is a pair");
    let right_pair =
        pair_trees(rng, right.clone(), right.clone()).expect("one tree twice is a pair");

    assert_eq!(
        invalid_witness(pair_trees(rng, left, right).err().unwrap()),
        format!("EvidenceTreePairFuse: {complaint}")
    );
    assert_eq!(
        invalid_witness(fuse_trees(rng, left_pair, right_pair).err().unwrap()),
        format!("EvidenceTreeFuse: {complaint}")
    );
}

/// Descend `tree` along one leaf's path.
fn descend_to_leaf(
    rng: &mut StdRng,
    tree: Pcd<evidence::EvidenceTree>,
    leaf: &EvidenceLeaf,
) -> Pcd<evidence::EvidenceTree> {
    let mut node = tree;
    for chunk in leaf.path.chunks(evidence::EvidenceTreeDescend::LEVELS) {
        let path =
            <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(chunk).expect("a full descent");
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                evidence::EvidenceTreeDescend,
                witness::evidence_tree_descend((*node.data(), ()), path),
                node,
                Proof::trivial().carry::<()>(()),
            )
            .expect("EvidenceTreeDescend");
        node = pcd;
    }
    node
}

/// Replay one leaf of `tree` under a witnessed preimage, whatever the tree
/// actually holds there.
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
            Proof::trivial().carry::<()>(()),
        )
        .map(|(bucket, ())| bucket)
}

#[test]
fn evidence_tree_replays_the_bucket_each_leaf_holds() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        2,
    );
    assert_eq!(routed.len(), 4, "two layers leave one intake per profile");
    let sealed = routed
        .into_iter()
        .map(|intake| seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO)))
        .collect::<Vec<_>>();
    let expected = sealed
        .iter()
        .map(|bucket| *bucket.pcd.data())
        .collect::<Vec<_>>();

    let tree = build_evidence_tree(rng, sealed);
    let (epoch, anchor_prev, anchor_end, root_discriminant, _) = *tree.pcd.data();
    assert_eq!(
        (epoch, anchor_prev, anchor_end, root_discriminant),
        (
            EpochIndex::new(0),
            Anchor::default(),
            final_anchor.next_epoch(EpochIndex::new(1)).unwrap(),
            discriminant
        ),
        "the root carries the network every leaf belongs to"
    );

    for (leaf, bucket) in tree.leaves.iter().zip(&expected) {
        let replayed = open_evidence_tree(rng, tree.pcd.clone(), leaf);
        assert_eq!(
            *replayed.pcd.data(),
            *bucket,
            "the leaf replays its bucket field for field"
        );
    }
}

/// The tree is transparent to everything downstream: a replayed bucket starts
/// the same segment the sealed one does, and the wallet binds it.
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
        Fp::from(user.nf_at(&note, epoch0)),
        Anchor::from(Fp::ZERO),
    );
    let sealed = *bucket.pcd.data();
    let direct = qr_epoch_unspent(rng, &user, &note, &bucket);

    let tree = build_evidence_tree(rng, vec![bucket]);
    let leaf = tree.leaves.first().expect("one leaf");
    let replayed = open_evidence_tree(rng, tree.pcd.clone(), leaf);
    assert_eq!(*replayed.pcd.data(), sealed);

    let bound = qr_epoch_unspent(rng, &user, &note, &replayed);
    assert_eq!(
        *bound.data(),
        *direct.data(),
        "the segment is the one the sealed bucket starts"
    );
    let (cm, _, epoch_start, epoch_end, _) = *bound.data();
    assert_eq!(cm, note.commitment());
    assert_eq!((epoch_start, epoch_end), (epoch0, epoch1));
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
    let value = Fp::random(&mut *rng);

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
        (
            final0.next_epoch(epoch1).expect("epoch one is nonzero"),
            final1,
        ),
        EPOCH_MEMBERS,
        0,
        value,
        final0,
    );

    let (left, right) = (tree_of(rng, first), tree_of(rng, second));
    assert_both_joins_reject(rng, left, right, "inputs cover different epochs");
}

/// Two routing networks over one epoch are two trees. Their buckets share
/// every field but the discriminant, and the fuse refuses to join them.
#[test]
fn evidence_tree_pair_fuse_rejects_a_bucket_of_another_network() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let value = Fp::random(&mut *rng);
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
    assert_ne!(
        first.pcd.data().3,
        second.pcd.data().3,
        "the two networks sampled different bases"
    );

    let (left, right) = (tree_of(rng, first), tree_of(rng, second));
    assert_both_joins_reject(
        rng,
        left,
        right,
        "inputs derive from different discriminants",
    );
}

/// Chaining is not fusing. A bucket over a prefix of the epoch shares its
/// opening anchor and nothing else, and the tree refuses to span both.
#[test]
fn evidence_tree_pair_fuse_rejects_an_extent_that_closes_elsewhere() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let value = Fp::random(&mut *rng);

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

    let (left, right) = (tree_of(rng, whole), tree_of(rng, short));
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
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let value = Fp::random(&mut *rng);

    let genuine = qr_bucket_at(
        rng,
        &pool,
        (
            final0.next_epoch(epoch1).expect("epoch one is nonzero"),
            final1,
        ),
        discriminant,
        EPOCH_MEMBERS,
        0,
        value,
        final0,
    );

    // An invented preceding anchor gives an epoch-one opening the chain never
    // produced; the seal takes it, since the opening matches its witness.
    let fake_anchor_final_prev = Anchor::from(Fp::ONE);
    let fake_prev = fake_anchor_final_prev
        .next_epoch(epoch1)
        .expect("epoch one is nonzero");
    let members = [Tachygram::from(Fp::random(&mut *rng))];
    let (intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), fake_prev, epoch1, discriminant, &members),
        )
        .expect("QrStampIntakeSeed");
    let elsewhere = seal_qr_intake(
        rng,
        QrIntakeEntry {
            pcd: intake,
            members: members.to_vec(),
        },
        fake_anchor_final_prev,
    );

    let (left, right) = (tree_of(rng, genuine), tree_of(rng, elsewhere));
    assert_both_joins_reject(rng, left, right, "inputs open at different anchors");
}

/// Admitting two buckets at once checks the same four fields the pair fuse
/// does, since it stands for two `EvidenceTreeLeaf` steps and a pair fuse.
#[test]
fn evidence_tree_leaf_pair_rejects_a_bucket_of_another_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch1.last_block().0, |_| random_block(rng, 1, 1));
    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.block(epoch1.last_block()).anchor();
    let value = Fp::random(&mut *rng);

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
        (
            final0.next_epoch(epoch1).expect("epoch one is nonzero"),
            final1,
        ),
        EPOCH_MEMBERS,
        0,
        value,
        final0,
    );
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            evidence::EvidenceTreeLeafPair,
            (),
            bucket0.pcd,
            bucket1.pcd,
        )
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "EvidenceTreeLeafPair: inputs cover different epochs"
    );
}

/// A cap raises the root and leaves every other field alone.
#[test]
fn evidence_tree_cap_is_transparent_to_a_descent() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));

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

    let (epoch, anchor_prev, anchor_end, network, root) = *tree.pcd.data();
    let (capped, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            evidence::EvidenceTreeCap,
            (),
            tree.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("EvidenceTreeCap");
    let raised = *capped.data();
    assert_eq!(
        (raised.0, raised.1, raised.2, raised.3),
        (epoch, anchor_prev, anchor_end, network)
    );
    assert_ne!(raised.4, root);
}

/// The leaf binds the profile alongside the contents, so a real bucket cannot
/// be replayed under another profile. That is the forgery the binding exists
/// for: under the tested value's own profile the class fold would pass and the
/// opening would find nothing.
#[test]
fn evidence_tree_open_rejects_a_forged_leaf() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));

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
    let other_contents = sealed.get(1).expect("a second bucket").pcd.data().5;

    let tree = build_evidence_tree(rng, sealed);
    let leaf = tree.leaves.first().expect("one leaf");
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
        let err = open_leaf(rng, tree.pcd.clone(), leaf, profile, contents)
            .err()
            .unwrap();
        assert_eq!(
            invalid_witness(err),
            "EvidenceTreeOpen: witnessed bucket is not the tree's leaf"
        );
    }

    open_leaf(rng, tree.pcd.clone(), leaf, leaf.profile, leaf.contents)
        .expect("the genuine preimage opens");
}

#[test]
fn evidence_tree_descend_rejects_children_that_miss_the_node() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));

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
    let leaf = tree.leaves.first().expect("one leaf");

    let mut path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(
        leaf.path
            .get(..evidence::EvidenceTreeDescend::LEVELS)
            .expect("a full descent"),
    )
    .expect("a full descent");
    let (_sides, ref mut children) = path[0];
    children[EVIDENCE_TREE_ARITY - 1] =
        EvidenceTreeRoot(Fp::from(children[EVIDENCE_TREE_ARITY - 1]) + Fp::ONE);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            evidence::EvidenceTreeDescend,
            witness::evidence_tree_descend((*tree.pcd.data(), ()), path),
            tree.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "EvidenceTreeDescend: children do not hash to the node"
    );
}

/// A node is not a leaf. Stopping a descent one level short leaves an interior
/// node on the header. A node hashes four elements and a leaf nine, so no node
/// matches a leaf digest.
#[test]
fn evidence_tree_open_rejects_a_node_presented_as_a_leaf() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));

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
    let leaf = tree.leaves.first().expect("one leaf");

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            evidence::EvidenceTreeOpen,
            witness::evidence_tree_open((*tree.pcd.data(), ()), leaf.profile, leaf.contents),
            tree.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "EvidenceTreeOpen: witnessed bucket is not the tree's leaf"
    );
}
