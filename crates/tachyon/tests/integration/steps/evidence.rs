//! The evidence tree: `EvidenceTreeLeafPair`, `EvidenceTreePairFuse`,
//! `EvidenceTreeFuse`, `EvidenceTreeCap`, `EvidenceTreeDescend` and
//! `EvidenceTreeOpen`.

extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::Fp;
use proptest::{prelude::*, sample::Index};
use ragu::{Pcd, Proof};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, EvidenceTreeRoot, QrDiscriminant, QrProfile, TachygramSetPoly,
    constants::{EPOCH_SIZE, EVIDENCE_TREE_ARITY},
    stamp::proof::{PROOF_SYSTEM, evidence, qr},
    witness,
};

use crate::{
    fixtures::{
        PoolSim, QrBucketEntry, QrIntakeEntry, WalletSim, build_evidence_tree, build_qr_partition,
        descend_evidence_tree, mine_sparse, open_evidence_tree, qr_bucket_at, qr_epoch_unspent,
        qr_profile_of, random_block, seal_qr_intake, shared_sk, small_epoch,
    },
    strategies::{assert_rejections, check, tachygrams},
};

/// The sealed depth-three buckets of a small epoch under a fresh network,
/// with the epoch's last anchor and the network's discriminant.
fn small_network(rng: &mut StdRng) -> (Vec<QrBucketEntry>, Anchor, QrDiscriminant) {
    let (pool, end) = small_epoch(rng);
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let sealed = build_qr_partition(rng, &pool, (Anchor::default(), end), discriminant, 24, 3)
        .into_iter()
        .map(|intake| seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO)))
        .collect();
    (sealed, end, discriminant)
}

/// A tree over any number of one network's sealed buckets carries the
/// network's epoch, span and discriminant, pads its leaves to a power of the
/// arity with the last bucket, and replays every leaf field for field: its
/// own bucket, or the last for padding. A replayed bucket starts the segment
/// the sealed one does, bound to the note. A cap raises the root and keeps
/// every other field.
#[test]
fn trees_replay_every_leaf() {
    let strategy = (any::<u64>(), 1usize..=8, any::<Index>());
    check(10, strategy, |(seed, count, position)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::new(shared_sk());
        let note = wallet.random_note(300);
        let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
        let (mut sealed, end, discriminant) = small_network(rng);
        let crossing = end.next_epoch(epoch1).unwrap();

        let nf_profile = qr_profile_of(Fp::from(wallet.nf_at(&note, epoch0)), discriminant, 3);
        let slot = position.index(count);
        let held = sealed
            .iter()
            .position(|bucket| bucket.pcd.data().4 == nf_profile)
            .expect("every profile has a bucket");
        sealed.swap(held, slot);
        sealed.truncate(count);
        let expected: Vec<_> = sealed.iter().map(|bucket| *bucket.pcd.data()).collect();
        let direct = qr_epoch_unspent(rng, &wallet, &note, &sealed[slot]);
        prop_assert_eq!(
            *direct.data(),
            (
                note.commitment(),
                Anchor::default(),
                epoch0,
                epoch1,
                crossing
            )
        );

        let tree = build_evidence_tree(rng, sealed);
        let (tree_epoch, anchor_start, anchor_next, network, root) = *tree.pcd.data();
        prop_assert_eq!(
            (tree_epoch, anchor_start, anchor_next, network),
            (epoch0, Anchor::default(), crossing, discriminant)
        );
        let width = if count <= EVIDENCE_TREE_ARITY {
            EVIDENCE_TREE_ARITY
        } else {
            EVIDENCE_TREE_ARITY * EVIDENCE_TREE_ARITY
        };
        prop_assert_eq!(tree.leaves.len(), width);
        for (index, leaf) in tree.leaves.iter().enumerate() {
            let replayed = open_evidence_tree(rng, tree.pcd.clone(), leaf);
            prop_assert_eq!(*replayed.pcd.data(), expected[index.min(count - 1)]);
            if index == slot {
                let bound = qr_epoch_unspent(rng, &wallet, &note, &replayed);
                prop_assert_eq!(*bound.data(), *direct.data());
            }
        }

        let (capped, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                evidence::EvidenceTreeCap,
                (),
                tree.pcd,
                Proof::trivial().carry::<()>(()),
            )
            .expect("EvidenceTreeCap");
        let (capped_epoch, capped_start, capped_next, capped_network, raised) = *capped.data();
        prop_assert_eq!(
            (capped_epoch, capped_start, capped_next, capped_network),
            (tree_epoch, anchor_start, anchor_next, network)
        );
        prop_assert_ne!(raised, root);
        Ok(())
    });
}

/// Two buckets join one tree only when they cover one epoch, open and close
/// at the same anchors, and derive from one discriminant. Each mismatch is
/// refused where buckets meet as leaves, where trees meet as a pair, and
/// where pairs meet under a node.
#[test]
fn joins_reject_mismatched_networks() {
    check(16, any::<u64>(), |seed| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
        mine_sparse(rng, &mut pool, EpochIndex::new(2), None);
        let final0 = pool.block(epoch0.last_block()).anchor();
        let final1 = pool.block(epoch1.last_block()).anchor();
        let [discriminant, other_discriminant] =
            [(); 2].map(|()| QrDiscriminant::from(Fp::random(&mut *rng)));
        let value = Fp::random(&mut *rng);
        let capacity = usize::try_from(EPOCH_SIZE).unwrap();
        let bucket = |bucket_rng: &mut StdRng, span, network, anchor_final_prev| {
            qr_bucket_at(
                bucket_rng,
                &pool,
                span,
                (network, capacity, 0),
                value,
                anchor_final_prev,
            )
        };

        let zero = Anchor::from(Fp::ZERO);
        let whole = bucket(rng, (Anchor::default(), final0), discriminant, zero);
        let short = bucket(
            rng,
            (Anchor::default(), pool.block(BlockHeight(0)).anchor()),
            discriminant,
            zero,
        );
        let foreign = bucket(rng, (Anchor::default(), final0), other_discriminant, zero);
        let later = bucket(
            rng,
            (final0.next_epoch(epoch1).unwrap(), final1),
            discriminant,
            final0,
        );
        let invented = Anchor::from(Fp::random(&mut *rng));
        let members = tachygrams(rng, 1);
        let (intake, ()) = PROOF_SYSTEM
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(
                    ((), ()),
                    invented.next_epoch(epoch1).unwrap(),
                    epoch1,
                    discriminant,
                    &members,
                ),
            )
            .expect("QrStampIntakeSeed");
        let elsewhere = seal_qr_intake(
            rng,
            QrIntakeEntry {
                pcd: intake,
                members,
            },
            invented,
        );

        let pair = |pair_rng: &mut StdRng,
                    left: &Pcd<evidence::EvidenceTree>,
                    right: &Pcd<evidence::EvidenceTree>| {
            PROOF_SYSTEM
                .fuse(
                    pair_rng,
                    evidence::EvidenceTreePairFuse,
                    (),
                    left.clone(),
                    right.clone(),
                )
                .map(|(joined, ())| joined)
        };
        let [
            whole_tree,
            short_tree,
            foreign_tree,
            later_tree,
            elsewhere_tree,
        ] = [&whole, &short, &foreign, &later, &elsewhere]
            .map(|held| build_evidence_tree(rng, [held.clone()].to_vec()).pcd);
        let [
            whole_pair,
            short_pair,
            foreign_pair,
            later_pair,
            elsewhere_pair,
        ] = [
            &whole_tree,
            &short_tree,
            &foreign_tree,
            &later_tree,
            &elsewhere_tree,
        ]
        .map(|tree| pair(rng, tree, tree).expect("one tree twice is a pair"));
        let leaves = |leaves_rng: &mut StdRng, left: &QrBucketEntry, right: &QrBucketEntry| {
            PROOF_SYSTEM
                .fuse(
                    leaves_rng,
                    evidence::EvidenceTreeLeafPair,
                    (),
                    left.pcd.clone(),
                    right.pcd.clone(),
                )
                .map(drop)
        };
        let node = |node_rng: &mut StdRng,
                    left: &Pcd<evidence::EvidenceTreePair>,
                    right: &Pcd<evidence::EvidenceTreePair>| {
            PROOF_SYSTEM
                .fuse(
                    node_rng,
                    evidence::EvidenceTreeFuse,
                    (),
                    left.clone(),
                    right.clone(),
                )
                .map(drop)
        };

        assert_rejections([
            (
                "leaves of different epochs",
                leaves(rng, &whole, &later),
                "EvidenceTreeLeafPair: inputs cover different epochs",
            ),
            (
                "trees of different epochs",
                pair(rng, &whole_tree, &later_tree).map(drop),
                "EvidenceTreePairFuse: inputs cover different epochs",
            ),
            (
                "pairs of different epochs",
                node(rng, &whole_pair, &later_pair),
                "EvidenceTreeFuse: inputs cover different epochs",
            ),
            (
                "leaves opening at different anchors",
                leaves(rng, &later, &elsewhere),
                "EvidenceTreeLeafPair: inputs open at different anchors",
            ),
            (
                "trees opening at different anchors",
                pair(rng, &later_tree, &elsewhere_tree).map(drop),
                "EvidenceTreePairFuse: inputs open at different anchors",
            ),
            (
                "pairs opening at different anchors",
                node(rng, &later_pair, &elsewhere_pair),
                "EvidenceTreeFuse: inputs open at different anchors",
            ),
            (
                "leaves closing at different anchors",
                leaves(rng, &whole, &short),
                "EvidenceTreeLeafPair: inputs close at different anchors",
            ),
            (
                "trees closing at different anchors",
                pair(rng, &whole_tree, &short_tree).map(drop),
                "EvidenceTreePairFuse: inputs close at different anchors",
            ),
            (
                "pairs closing at different anchors",
                node(rng, &whole_pair, &short_pair),
                "EvidenceTreeFuse: inputs close at different anchors",
            ),
            (
                "leaves of different networks",
                leaves(rng, &whole, &foreign),
                "EvidenceTreeLeafPair: inputs derive from different discriminants",
            ),
            (
                "trees of different networks",
                pair(rng, &whole_tree, &foreign_tree).map(drop),
                "EvidenceTreePairFuse: inputs derive from different discriminants",
            ),
            (
                "pairs of different networks",
                node(rng, &whole_pair, &foreign_pair),
                "EvidenceTreeFuse: inputs derive from different discriminants",
            ),
        ]);
        Ok(())
    });
}

/// Opening any leaf refuses a preimage other than the leaf's: a deeper
/// profile, a flipped side or another set's contents, and the root in place
/// of the leaf. A descent refuses a child at any level that does not hash
/// to its node.
#[test]
fn descend_and_open_reject_forgeries() {
    let strategy = (
        any::<u64>(),
        1usize..=8,
        any::<Index>(),
        any::<Index>(),
        0..EVIDENCE_TREE_ARITY,
    );
    check(16, strategy, |(seed, count, leaf_index, level, child)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let (mut sealed, ..) = small_network(rng);
        sealed.truncate(count);
        let tree = build_evidence_tree(rng, sealed);
        let leaf = &tree.leaves[leaf_index.index(tree.leaves.len())];
        let node = descend_evidence_tree(rng, tree.pcd.clone(), leaf);
        let open = |open_rng: &mut StdRng,
                    at: &Pcd<evidence::EvidenceTree>,
                    profile: QrProfile,
                    contents| {
            PROOF_SYSTEM
                .fuse(
                    open_rng,
                    evidence::EvidenceTreeOpen,
                    witness::evidence_tree_open((*at.data(), ()), profile, contents),
                    at.clone(),
                    Proof::trivial().carry::<()>(()),
                )
                .map(drop)
        };
        let QrProfile { depth, bits } = leaf.profile;
        let stranger = tachygrams(rng, 1)
            .into_iter()
            .collect::<TachygramSetPoly>()
            .commit();

        let levels = evidence::EvidenceTreeDescend::LEVELS;
        let mut path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(&leaf.path[..levels])
            .expect("a full descent");
        let (_, ref mut children) = path[level.index(levels)];
        children[child] = EvidenceTreeRoot(Fp::from(children[child]) + Fp::ONE);
        let forged_descent = PROOF_SYSTEM.fuse(
            rng,
            evidence::EvidenceTreeDescend,
            witness::evidence_tree_descend((*tree.pcd.data(), ()), path),
            tree.pcd.clone(),
            Proof::trivial().carry::<()>(()),
        );

        assert_rejections([
            (
                "a deeper profile",
                open(
                    rng,
                    &node,
                    QrProfile {
                        depth: depth + 1,
                        bits,
                    },
                    leaf.contents,
                ),
                "EvidenceTreeOpen: witnessed bucket is not the tree's leaf",
            ),
            (
                "a flipped side",
                open(
                    rng,
                    &node,
                    QrProfile {
                        depth,
                        bits: bits ^ 1,
                    },
                    leaf.contents,
                ),
                "EvidenceTreeOpen: witnessed bucket is not the tree's leaf",
            ),
            (
                "another set's contents",
                open(rng, &node, leaf.profile, stranger),
                "EvidenceTreeOpen: witnessed bucket is not the tree's leaf",
            ),
            (
                "the root in place of the leaf",
                open(rng, &tree.pcd, leaf.profile, leaf.contents),
                "EvidenceTreeOpen: witnessed bucket is not the tree's leaf",
            ),
            (
                "a child that does not hash to its node",
                forged_descent.map(drop),
                "EvidenceTreeDescend: children do not hash to the node",
            ),
        ]);
        Ok(())
    });
}
