extern crate alloc;

use alloc::{vec, vec::Vec};
use core::iter;

use ragu::{Pcd, Proof};
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
    PoolSim, QrBucketEntry, WalletSim, assert_rejected, build_evidence_tree, build_qr_partition,
    descend_evidence_tree, mine_sparse, qr_bucket_at,
};

fn small_network(rng: &mut StdRng) -> (Vec<QrBucketEntry>, Anchor, QrDiscriminant) {
    let mut pool = PoolSim::genesis_with(
        iter::repeat_with(|| {
            iter::repeat_with(|| Tachygram::random(rng))
                .take(3)
                .collect()
        })
        .take(2)
        .collect(),
    );
    for _ in 0..3 {
        pool.mine(
            iter::repeat_with(|| {
                iter::repeat_with(|| Tachygram::random(rng))
                    .take(3)
                    .collect()
            })
            .take(2)
            .collect(),
        );
    }
    let end = pool.block(pool.height()).anchor();
    let discriminant = QrDiscriminant::random(rng);
    let sealed = build_qr_partition(rng, &pool, (Anchor::default(), end), discriminant, 24, 3)
        .into_iter()
        .map(|intake| {
            let seal_witness =
                witness::qr_bucket_seal((*intake.pcd.data(), ()), Anchor::from(Fp::ZERO));
            let (pcd, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    qr::QrBucketSeal,
                    seal_witness,
                    intake.pcd,
                    Proof::bootstrap().carry::<()>(()),
                )
                .unwrap();
            QrBucketEntry {
                pcd,
                members: intake.members,
            }
        })
        .collect();
    (sealed, end, discriminant)
}

#[test]
fn trees_replay_their_buckets() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let note = wallet.random_note(300);
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    let (sealed, end, discriminant) = small_network(rng);
    let crossing = end.next_epoch(epoch1).unwrap();
    let nf_value = Fp::from(
        wallet
            .pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch0),
    );
    let nf_profile = (0..3).fold(QrProfile::ROOT, |profile, level| {
        profile.descend(qr::classify(nf_value, discriminant.at(level)).0)
    });
    let held = sealed
        .iter()
        .position(|bucket| bucket.pcd.data().4 == nf_profile)
        .unwrap();
    let expected: Vec<_> = sealed.iter().map(|bucket| *bucket.pcd.data()).collect();
    let held_bucket = &sealed[held];
    let (held_epoch, ..) = *held_bucket.pcd.data();
    let init_witness = witness::qr_unspent_init(
        (*held_bucket.pcd.data(), ()),
        wallet
            .pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(held_epoch)
            .into(),
        &held_bucket.members,
    );
    let (arbitrary, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentInit,
            init_witness,
            held_bucket.pcd.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let direct = wallet.unspent_bind(rng, arbitrary, &note);
    assert_eq!(
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
    assert_eq!(
        (tree_epoch, anchor_start, anchor_next, network),
        (epoch0, Anchor::default(), crossing, discriminant)
    );
    for index in [0, held, expected.len() - 1] {
        let leaf = &tree.leaves[index];
        let leaf_node = descend_evidence_tree(rng, tree.pcd.clone(), leaf);
        let open_witness =
            witness::evidence_tree_open((*leaf_node.data(), ()), leaf.profile, leaf.contents);
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                evidence::EvidenceTreeOpen,
                open_witness,
                leaf_node,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        let replayed = QrBucketEntry {
            pcd,
            members: leaf.members.clone(),
        };
        assert_eq!(*replayed.pcd.data(), expected[index], "leaf {index}");
        if index == held {
            let (replayed_epoch, ..) = *replayed.pcd.data();
            let replayed_witness = witness::qr_unspent_init(
                (*replayed.pcd.data(), ()),
                wallet
                    .pak
                    .nk
                    .derive_note_private(note.psi)
                    .derive_nullifier(replayed_epoch)
                    .into(),
                &replayed.members,
            );
            let (replayed_segment, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    qr::QrUnspentInit,
                    replayed_witness,
                    replayed.pcd.clone(),
                    Proof::bootstrap().carry::<()>(()),
                )
                .unwrap();
            let bound = wallet.unspent_bind(rng, replayed_segment, &note);
            assert_eq!(*bound.data(), *direct.data());
        }
    }

    let (capped, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            evidence::EvidenceTreeCap,
            (),
            tree.pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .expect("EvidenceTreeCap");
    let (capped_epoch, capped_start, capped_next, capped_network, raised) = *capped.data();
    assert_eq!(
        (capped_epoch, capped_start, capped_next, capped_network),
        (tree_epoch, anchor_start, anchor_next, network)
    );
    assert_ne!(raised, root);
}

#[test]
fn joins_reject_mismatched_networks() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::random(rng)]]);
    mine_sparse(rng, &mut pool, EpochIndex::new(2), None);
    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.block(epoch1.last_block()).anchor();
    let [discriminant, other_discriminant] = [(); 2].map(|()| QrDiscriminant::random(rng));
    let value = Fp::random(|bytes| rng.fill_bytes(bytes));
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
    let invented = Anchor::random(rng);
    let members = vec![Tachygram::random(rng)];
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
    let seal_witness = witness::qr_bucket_seal((*intake.data(), ()), invented);
    let (sealed, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            seal_witness,
            intake,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let elsewhere = QrBucketEntry {
        pcd: sealed,
        members,
    };

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
    ] = [&whole, &short, &foreign, &later, &elsewhere].map(|held| {
        let entry = QrBucketEntry {
            pcd: held.pcd.clone(),
            members: held.members.clone(),
        };
        build_evidence_tree(rng, Vec::from([entry])).pcd
    });
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
    .map(|tree| pair(rng, tree, tree).unwrap());
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

    assert_rejected(
        leaves(rng, &whole, &later),
        "EvidenceTreeLeafPair: inputs cover different epochs",
    );
    assert_rejected(
        pair(rng, &whole_tree, &later_tree).map(drop),
        "EvidenceTreePairFuse: inputs cover different epochs",
    );
    assert_rejected(
        node(rng, &whole_pair, &later_pair),
        "EvidenceTreeFuse: inputs cover different epochs",
    );
    assert_rejected(
        leaves(rng, &later, &elsewhere),
        "EvidenceTreeLeafPair: inputs open at different anchors",
    );
    assert_rejected(
        pair(rng, &later_tree, &elsewhere_tree).map(drop),
        "EvidenceTreePairFuse: inputs open at different anchors",
    );
    assert_rejected(
        node(rng, &later_pair, &elsewhere_pair),
        "EvidenceTreeFuse: inputs open at different anchors",
    );
    assert_rejected(
        leaves(rng, &whole, &short),
        "EvidenceTreeLeafPair: inputs close at different anchors",
    );
    assert_rejected(
        pair(rng, &whole_tree, &short_tree).map(drop),
        "EvidenceTreePairFuse: inputs close at different anchors",
    );
    assert_rejected(
        node(rng, &whole_pair, &short_pair),
        "EvidenceTreeFuse: inputs close at different anchors",
    );
    assert_rejected(
        leaves(rng, &whole, &foreign),
        "EvidenceTreeLeafPair: inputs derive from different discriminants",
    );
    assert_rejected(
        pair(rng, &whole_tree, &foreign_tree).map(drop),
        "EvidenceTreePairFuse: inputs derive from different discriminants",
    );
    assert_rejected(
        node(rng, &whole_pair, &foreign_pair),
        "EvidenceTreeFuse: inputs derive from different discriminants",
    );
}

#[test]
fn descend_and_open_reject_forgeries() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (sealed, ..) = small_network(rng);
    let tree = build_evidence_tree(rng, sealed);
    let leaf = &tree.leaves[1];
    let node = descend_evidence_tree(rng, tree.pcd.clone(), leaf);
    let open =
        |open_rng: &mut StdRng, at: &Pcd<evidence::EvidenceTree>, profile: QrProfile, contents| {
            PROOF_SYSTEM
                .fuse(
                    open_rng,
                    evidence::EvidenceTreeOpen,
                    witness::evidence_tree_open((*at.data(), ()), profile, contents),
                    at.clone(),
                    Proof::bootstrap().carry::<()>(()),
                )
                .map(drop)
        };
    let QrProfile { depth, bits } = leaf.profile;
    let stranger = vec![Tachygram::random(rng)]
        .into_iter()
        .collect::<TachygramSetPoly>()
        .commit();

    assert_rejected(
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
    );
    assert_rejected(
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
    );
    assert_rejected(
        open(rng, &node, leaf.profile, stranger),
        "EvidenceTreeOpen: witnessed bucket is not the tree's leaf",
    );
    assert_rejected(
        open(rng, &tree.pcd, leaf.profile, leaf.contents),
        "EvidenceTreeOpen: witnessed bucket is not the tree's leaf",
    );

    let levels = evidence::EvidenceTreeDescend::LEVELS;
    for (level, child) in [(0, 0), (levels - 1, EVIDENCE_TREE_ARITY - 1)] {
        let mut path = <[_; evidence::EvidenceTreeDescend::LEVELS]>::try_from(&leaf.path[..levels])
            .expect("a full descent");
        let (_, ref mut children) = path[level];
        children[child] = EvidenceTreeRoot(Fp::from(children[child]) + Fp::ONE);
        assert_rejected(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    evidence::EvidenceTreeDescend,
                    witness::evidence_tree_descend((*tree.pcd.data(), ()), path),
                    tree.pcd.clone(),
                    Proof::bootstrap().carry::<()>(()),
                )
                .map(drop),
            "EvidenceTreeDescend: children do not hash to the node",
        );
    }
}
