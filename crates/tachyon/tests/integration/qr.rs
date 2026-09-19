//! QR epoch evidence: the partition of an epoch's tachygrams and the
//! `ArbitraryUnspent` lineage born from one bucket.

extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::{array, iter};

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use ragu::{Pcd, Proof, Step};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrProfile, QrTreeFork,
    QrTreeRoot, Tachygram, TachygramSetCommit, TachygramSetPoly,
    constants::{EPOCH_MAX, EPOCH_SIZE},
    note::Note,
    nullifier::Nullifier,
    stamp::proof::{
        PROOF_SYSTEM,
        pool::{ArbitraryUnspent, NoteUnspent, UnspentFuse},
        qr, spend, spendable, summary,
    },
    witness,
};

use crate::fixtures::{
    PoolSim, QrBucketEntry, QrBucketLeaf, QrIntakeEntry, WalletSim, build_qr_branch,
    build_qr_bucket_tree, build_qr_partition, build_summary_pcd, build_unspent_pcd_between_anchors,
    open_qr_bucket_tree, qr_discriminant, qr_profile_of, random_block, seal_qr_intake,
    seed_qr_stamp_intake, shared_sk, split_qr_intake,
};

/// The witness of [`qr::QrUnspentInit`].
type UnspentInitWitness = <qr::QrUnspentInit as Step>::Witness<'static>;

/// Run [`qr::QrUnspentInit`] over `bucket`.
fn fuse_unspent_init(
    rng: &mut StdRng,
    bucket: Pcd<qr::QrBucket>,
    witness: UnspentInitWitness,
) -> ragu_core::Result<Pcd<ArbitraryUnspent>> {
    PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentInit,
            witness,
            bucket,
            Proof::trivial().carry::<()>(()),
        )
        .map(|(unspent, ())| unspent)
}

/// The message of an `InvalidWitness` error.
fn invalid_witness(err: ragu_core::Error) -> String {
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    inner.to_string()
}

/// Four blocks of epoch zero, two actions of three tachygrams each; with the
/// terminal anchor.
fn small_epoch(rng: &mut StdRng) -> (PoolSim, Anchor) {
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    (pool, terminal)
}

/// The members an epoch holds in the pools these tests build: one tachygram
/// per stamp and one stamp per block, so the whole epoch fits one polynomial
/// and its partition reaches a bucket spanning it.
const EPOCH_MEMBERS: usize = EPOCH_SIZE as usize;

/// [`qr_bucket_at`] with a freshly sampled routing base.
fn qr_bucket_for(
    rng: &mut StdRng,
    pool: &PoolSim,
    span: (Anchor, Anchor),
    capacity: usize,
    depth: u32,
    value: Fp,
    anchor_prev_prev: Anchor,
) -> QrBucketEntry {
    let discriminant = qr_discriminant(rng);
    qr_bucket_at(
        rng,
        pool,
        span,
        discriminant,
        capacity,
        depth,
        value,
        anchor_prev_prev,
    )
}

/// The sealed bucket holding `value` at `depth` levels over the anchor span
/// `(start, terminal)`, routed at `discriminant` and sealed on
/// `anchor_prev_prev`.
#[expect(clippy::too_many_arguments, reason = "a fixture assembling one bucket")]
fn qr_bucket_at(
    rng: &mut StdRng,
    pool: &PoolSim,
    (start, terminal): (Anchor, Anchor),
    discriminant: QrDiscriminant,
    capacity: usize,
    depth: u32,
    value: Fp,
    anchor_prev_prev: Anchor,
) -> QrBucketEntry {
    let profile = qr_profile_of(value, discriminant, depth);
    let mut branch = build_qr_branch(
        rng,
        pool,
        (start, terminal),
        discriminant,
        capacity,
        value,
        depth,
    );
    assert_eq!(branch.len(), 1, "the value's profile fits one intake");
    let intake = branch.pop().expect("one intake");
    assert_eq!(intake.pcd.data().4, profile);
    seal_qr_intake(rng, intake, anchor_prev_prev)
}

/// The note's QR segment across a bucket's epoch and out over the crossing,
/// bound to the note.
fn qr_epoch_unspent(
    rng: &mut StdRng,
    user: &WalletSim,
    note: &Note,
    bucket: &QrBucketEntry,
) -> Pcd<NoteUnspent> {
    let (epoch, ..) = *bucket.pcd.data();
    let witness = witness::qr_unspent_init(
        (*bucket.pcd.data(), ()),
        user.nf_at(note, epoch).into(),
        user.nf_at(note, epoch.next().expect("an epoch follows the bucket's")),
        &bucket.members,
    );
    let arbitrary = fuse_unspent_init(rng, bucket.pcd.clone(), witness).expect("QrUnspentInit");
    user.unspent_bind(rng, arbitrary, note)
}

#[test]
fn qr_summary_intake_init_starts_a_root_from_a_summary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let members: [Tachygram; 6] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (_, _, anchor_last, acc_commit) = *summary.data();
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    assert_eq!(
        *root.data(),
        (
            epoch,
            start,
            anchor_last,
            discriminant,
            QrProfile::ROOT,
            acc_commit
        ),
        "a root intake carries the summary's span and contents at depth zero"
    );
}

#[test]
fn qr_stamp_intake_seed_roots_an_intake_on_one_stamp() {
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::genesis_with(random_block(rng, 3, 1));
    let block = pool.block(BlockHeight(0));
    let entry = block.stamps.first().expect("one stamp");
    let (anchor_prev, members, commit, anchor_last) = entry.clone();
    let (summary, _) = build_summary_pcd(rng, &pool, (anchor_prev, anchor_last));

    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let stamp_root = seed_qr_stamp_intake(rng, &pool, entry, discriminant);
    assert_eq!(
        *stamp_root.pcd.data(),
        (
            EpochIndex::new(0),
            anchor_prev,
            anchor_last,
            discriminant,
            QrProfile::ROOT,
            commit
        ),
        "the seed folds the stamp into its anchor and roots at depth zero"
    );
    assert_eq!(stamp_root.members, members);

    let (summary_root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    assert_eq!(
        *stamp_root.pcd.data(),
        *summary_root.data(),
        "a stamp-rooted intake matches the summary route over the same stamp"
    );
}

#[test]
fn qr_stamp_intake_seed_rejects_an_empty_stamp() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor_prev = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let err = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(
                ((), ()),
                anchor_prev,
                EpochIndex::new(3),
                discriminant,
                &[],
            ),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "invalid anchor step");
}

#[test]
fn qr_intake_split_partitions_the_contents_by_class() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let (residue, non_residue): (Vec<Tachygram>, Vec<Tachygram>) = members
        .iter()
        .copied()
        .partition(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0);
    assert!(
        !residue.is_empty() && !non_residue.is_empty(),
        "twelve random members reach both classes"
    );

    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

    assert_eq!(
        *split.data(),
        (
            epoch,
            start,
            start
                .next_stamp(
                    epoch,
                    &members
                        .iter()
                        .copied()
                        .collect::<TachygramSetPoly>()
                        .commit()
                )
                .unwrap(),
            discriminant,
            QrProfile::ROOT,
            non_residue
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit(),
            residue
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit()
        ),
        "the split emits each class as its own set, span and profile unchanged"
    );
}

#[test]
fn qr_intake_split_rejects_a_forged_partition() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let members: [Tachygram; 8] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let (contents, non_residue, _residue) = witness::qr_intake_split((*root.data(), ()), &members);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            (contents, non_residue.clone(), non_residue),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrIntakeSplit: the sides do not partition the contents"
    );
}

#[test]
fn qr_intake_split_rejects_the_exceptional_value_on_the_non_residue_side() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let exceptional = Tachygram::from(-Fp::from(discriminant));
    let members: Vec<Tachygram> = iter::repeat_with(|| Tachygram::from(Fp::random(&mut *rng)))
        .take(8)
        .chain([exceptional])
        .collect();

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    // Moving one member across the partition leaves the product intact, so
    // only the opening at -R separates the two filings.
    let (residue, non_residue): (Vec<Tachygram>, Vec<Tachygram>) =
        members.iter().copied().partition(|&member| {
            member != exceptional && qr::classify(Fp::from(member), Fp::from(discriminant)).0
        });
    let (contents, ..) = witness::qr_intake_split((*root.data(), ()), &members);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            (
                contents,
                non_residue.iter().copied().collect(),
                residue.iter().copied().collect(),
            ),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrIntakeSplit: exceptional value claimed the non-residue class"
    );
}

/// A split at `depth` opens the non-residue side at $-R_{\mathsf{depth}+1}$.
#[test]
fn qr_intake_split_checks_the_exceptional_value_at_its_depth() {
    let rng = &mut StdRng::seed_from_u64(0);
    for depth in [1, 31] {
        let epoch = EpochIndex::new(3);
        let start = Anchor::from(Fp::random(&mut *rng));
        let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
        // Choose x from R_1 and the selected split depth.
        let value = -Fp::from(discriminant) - Fp::from(u64::from(depth));
        assert_ne!(value, Fp::ZERO);
        let exceptional = Tachygram::from(value);
        let members: Vec<Tachygram> = iter::repeat_with(|| Tachygram::from(Fp::random(&mut *rng)))
            .take(8)
            .chain([exceptional])
            .collect();
        assert!(members.iter().all(|member| Fp::from(*member) != Fp::ZERO));
        for (index, member) in members.iter().enumerate() {
            assert!(!members[index + 1..].contains(member));
        }

        let (summary, ()) = PROOF_SYSTEM
            .seed(
                rng,
                summary::SummarySeed,
                witness::summary_seed(((), ()), start, epoch, &members),
            )
            .expect("SummarySeed");
        let (root, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSummaryIntakeInit,
                witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
                summary,
                Proof::trivial().carry::<()>(()),
            )
            .expect("QrSummaryIntakeInit");

        // Reach the selected depth through honest splits and descents, keeping
        // the branch containing x rather than fabricating a deeper profile.
        let mut intake = QrIntakeEntry { pcd: root, members };
        for level in 0..depth {
            let side = qr::classify(value, discriminant.at(level)).0;
            let (non_residue_side, residue_side) = split_qr_intake(rng, intake);
            intake = if side { residue_side } else { non_residue_side };
        }
        assert_eq!(intake.pcd.data().4.depth, depth);
        assert!(intake.members.contains(&exceptional));
        assert_eq!(value + discriminant.at(depth), Fp::ZERO);
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrIntakeSplit,
                witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members),
                intake.pcd.clone(),
                Proof::trivial().carry::<()>(()),
            )
            .expect("honest QrIntakeSplit accepts the exceptional value");

        // Moving only x across the partition leaves the product intact, so
        // only the opening at -R_{depth+1} separates the two filings.
        let (residue, non_residue): (Vec<Tachygram>, Vec<Tachygram>) =
            intake.members.iter().copied().partition(|member| {
                *member != exceptional && qr::classify(Fp::from(*member), discriminant.at(depth)).0
            });
        assert!(!residue.contains(&exceptional));
        assert!(non_residue.contains(&exceptional));
        let (contents, ..) = witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members);
        let err = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrIntakeSplit,
                (
                    contents,
                    non_residue.iter().copied().collect(),
                    residue.iter().copied().collect(),
                ),
                intake.pcd,
                Proof::trivial().carry::<()>(()),
            )
            .err()
            .unwrap();
        assert_eq!(
            invalid_witness(err),
            "QrIntakeSplit: exceptional value claimed the non-residue class"
        );
    }
}

#[test]
fn qr_side_descend_carries_each_side_one_level_down() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (_, _, anchor_last, ..) = *root.data();
    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

    for side in [true, false] {
        let side_members: Vec<Tachygram> = members
            .iter()
            .copied()
            .filter(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0 == side)
            .collect();
        let (child, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                witness::qr_side_descend((*split.data(), ()), &members, side),
                split.clone(),
                Proof::trivial().carry::<()>(()),
            )
            .expect("QrSideDescend");
        assert_eq!(
            *child.data(),
            (
                epoch,
                start,
                anchor_last,
                discriminant,
                QrProfile::ROOT.descend(side),
                side_members
                    .iter()
                    .copied()
                    .collect::<TachygramSetPoly>()
                    .commit()
            ),
            "a descent keeps the span and the discriminant"
        );
    }
}

#[test]
fn qr_side_descend_rejects_a_foreign_sibling() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

    let (_, foreign_sibling, ..) = witness::qr_side_descend((*split.data(), ()), &members, false);
    let (_, _, interpolant, quotient) =
        witness::qr_side_descend((*split.data(), ()), &members, true);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            (true, foreign_sibling, interpolant, quotient),
            split,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrSideDescend: sibling does not match the header"
    );
}

/// The interpolant of the other side does not decompose the sibling at its
/// class, on either side.
#[test]
fn qr_side_descend_rejects_a_foreign_interpolant() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

    for bit in [true, false] {
        let (_, sibling_contents, _interpolant, quotient) =
            witness::qr_side_descend((*split.data(), ()), &members, bit);
        let (_, _, foreign_interpolant, _) =
            witness::qr_side_descend((*split.data(), ()), &members, !bit);
        let err = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                (bit, sibling_contents, foreign_interpolant, quotient),
                split.clone(),
                Proof::trivial().carry::<()>(()),
            )
            .err()
            .unwrap();
        assert_eq!(
            invalid_witness(err),
            "QrSideDescend: the sibling fails its class decomposition"
        );
    }
}

/// The quotient of the other side does not complete the sibling's own
/// interpolant, on either side.
#[test]
fn qr_side_descend_rejects_a_foreign_quotient() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

    for bit in [true, false] {
        let (_, sibling_contents, interpolant, _quotient) =
            witness::qr_side_descend((*split.data(), ()), &members, bit);
        let (_, _, _, foreign_quotient) =
            witness::qr_side_descend((*split.data(), ()), &members, !bit);
        let err = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                (bit, sibling_contents, interpolant, foreign_quotient),
                split.clone(),
                Proof::trivial().carry::<()>(()),
            )
            .err()
            .unwrap();
        assert_eq!(
            invalid_witness(err),
            "QrSideDescend: the sibling fails its class decomposition"
        );
    }
}

#[test]
fn qr_side_descend_rejects_a_child_short_of_a_member() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    // File one residue-class member on the non-residue side. The product
    // still holds, so the split accepts the misfiled partition.
    let (mut short_residue, mut padded_non_residue): (Vec<Tachygram>, Vec<Tachygram>) = members
        .iter()
        .copied()
        .partition(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0);
    let smuggled = short_residue
        .pop()
        .expect("twelve random members reach the residue class");
    padded_non_residue.push(smuggled);
    let (contents, ..) = witness::qr_intake_split((*root.data(), ()), &members);
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            (
                contents,
                padded_non_residue.iter().copied().collect(),
                short_residue.iter().copied().collect(),
            ),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");

    // Extracting the short residue child attests the padded sibling, which
    // holds a residue-class root and so has no non-residue decomposition; the
    // honest sibling's decomposition is the best a prover can offer.
    let (_, _, interpolant, quotient) =
        witness::qr_side_descend((*sides.data(), ()), &members, true);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            (
                true,
                padded_non_residue.iter().copied().collect(),
                interpolant,
                quotient,
            ),
            sides.clone(),
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrSideDescend: the sibling fails its class decomposition"
    );

    // The padded child is complete for its class, merely impure: its short
    // sibling is pure, so the extraction passes and carries the stray member.
    let members_without_smuggled: Vec<Tachygram> = members
        .iter()
        .copied()
        .filter(|&member| member != smuggled)
        .collect();
    let (child, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            witness::qr_side_descend((*sides.data(), ()), &members_without_smuggled, false),
            sides,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSideDescend");
    let (.., child_profile, child_contents) = *child.data();
    assert_eq!(child_profile, QrProfile::ROOT.descend(false));
    assert_eq!(
        child_contents,
        padded_non_residue
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit(),
        "the impure child carries the stray member"
    );
}

#[test]
fn qr_side_descend_refuses_a_full_register() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let members: [Tachygram; 2] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .expect("SummarySeed");
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let mut intake = QrIntakeEntry {
        pcd: root,
        members: members.to_vec(),
    };
    for _ in 0..QrProfile::MAX_DEPTH {
        let (_non_residue, residue) = split_qr_intake(rng, intake);
        intake = residue;
    }
    let (.., profile, _contents) = *intake.pcd.data();
    assert_eq!(
        profile,
        QrProfile {
            depth: u32::BITS,
            bits: u32::MAX
        },
        "thirty-two residue sides reach the maximum depth"
    );

    let split_witness = witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members);
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            intake.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");
    let descend_witness = witness::qr_side_descend((*sides.data(), ()), &intake.members, true);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            descend_witness,
            sides,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrSideDescend: profile has no bit left for another side"
    );
}

#[test]
fn qr_intake_merge_joins_two_spans() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let start = Anchor::from(Fp::random(&mut *rng));
    let left_members: [Tachygram; 5] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (left_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &left_members),
        )
        .expect("SummarySeed");
    let (_, _, junction, _) = *left_summary.data();
    let (right_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), junction, epoch, &right_members),
        )
        .expect("SummarySeed");
    let (_, _, end, _) = *right_summary.data();

    let (left, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*left_summary.data(), ()), discriminant),
            left_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (right, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*right_summary.data(), ()), discriminant),
            right_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let witness =
        witness::qr_intake_merge((*left.data(), *right.data()), &left_members, &right_members);
    let (merged, ()) = PROOF_SYSTEM
        .fuse(rng, qr::QrIntakeMerge, witness, left, right)
        .expect("QrIntakeMerge");

    let union = left_members
        .iter()
        .chain(&right_members)
        .copied()
        .collect::<TachygramSetPoly>();
    assert_eq!(
        *merged.data(),
        (
            epoch,
            start,
            end,
            discriminant,
            QrProfile::ROOT,
            union.commit()
        ),
        "the merge spans both inputs and holds their union"
    );
}

#[test]
fn qr_intake_merge_rejects_a_gap() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let left_start = Anchor::from(Fp::random(&mut *rng));
    let right_start = Anchor::from(Fp::random(&mut *rng));
    let left_members: [Tachygram; 5] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (left_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), left_start, epoch, &left_members),
        )
        .expect("SummarySeed");
    let (right_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), right_start, epoch, &right_members),
        )
        .expect("SummarySeed");

    let (left, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*left_summary.data(), ()), discriminant),
            left_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (right, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*right_summary.data(), ()), discriminant),
            right_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let witness =
        witness::qr_intake_merge((*left.data(), *right.data()), &left_members, &right_members);
    let err = PROOF_SYSTEM
        .fuse(rng, qr::QrIntakeMerge, witness, left, right)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrIntakeMerge: left.anchor_last must equal right.anchor_prev"
    );
}

#[test]
fn qr_intake_merge_rejects_different_profiles() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let start = Anchor::from(Fp::random(&mut *rng));
    let left_members: [Tachygram; 12] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (left_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &left_members),
        )
        .expect("SummarySeed");
    let (_, _, junction, _) = *left_summary.data();
    let (right_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), junction, epoch, &right_members),
        )
        .expect("SummarySeed");

    let (left_root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*left_summary.data(), ()), discriminant),
            left_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (right, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*right_summary.data(), ()), discriminant),
            right_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*left_root.data(), ()), &left_members),
            left_root,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrIntakeSplit");
    let (deeper, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            witness::qr_side_descend((*split.data(), ()), &left_members, true),
            split,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSideDescend");

    let deeper_members: Vec<Tachygram> = left_members
        .iter()
        .copied()
        .filter(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0)
        .collect();
    let witness = witness::qr_intake_merge(
        (*deeper.data(), *right.data()),
        &deeper_members,
        &right_members,
    );
    let err = PROOF_SYSTEM
        .fuse(rng, qr::QrIntakeMerge, witness, deeper, right)
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrIntakeMerge: inputs sit at different depths"
    );
}

#[test]
fn qr_partition_covers_the_epoch_by_profile() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let discriminant = qr_discriminant(rng);
    let published: Vec<Tachygram> = (0..=3)
        .flat_map(|height| pool.block(BlockHeight(height)).tachygrams())
        .flatten()
        .collect();

    // The epoch's twenty-four members fit one polynomial, so each profile ends
    // up as a single intake over the whole span.
    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        24,
        2,
    );

    assert_eq!(routed.len(), 4, "two layers leave one intake per profile");
    let mut profiles: Vec<u32> = routed
        .iter()
        .map(|intake| {
            let (_, anchor_prev, anchor_last, _, profile, ..) = *intake.pcd.data();
            assert_eq!(profile.depth, 2);
            assert_eq!(anchor_prev, Anchor::default());
            assert_eq!(anchor_last, terminal, "every intake spans the whole epoch");
            profile.bits
        })
        .collect();
    profiles.sort_unstable();
    assert_eq!(profiles, [0, 1, 2, 3], "the intakes are the four profiles");

    let mut covered: Vec<Tachygram> = Vec::new();
    for intake in &routed {
        let (_, _, _, intake_discriminant, profile, contents) = *intake.pcd.data();
        assert_eq!(intake_discriminant, discriminant);
        assert_eq!(
            contents,
            intake
                .members
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit(),
            "an intake's header commits exactly the members it holds"
        );
        for &member in &intake.members {
            for level in 0..profile.depth {
                let side = ((profile.bits >> (profile.depth - 1 - level)) & 1) == 1;
                assert_eq!(
                    qr::classify(Fp::from(member), discriminant.at(level)).0,
                    side,
                    "a member's class at every level is its intake's path"
                );
            }
        }
        covered.extend(intake.members.iter().copied());
    }

    let sorted = |mut tgs: Vec<Tachygram>| {
        tgs.sort_unstable_by_key(|&tg| Fp::from(tg).to_repr());
        tgs
    };
    assert_eq!(
        sorted(covered),
        sorted(published),
        "the intakes partition the epoch's published tachygrams"
    );
}

/// A span past what one polynomial holds leaves each profile as a run of
/// adjacent intakes rather than a single one.
#[test]
fn qr_partition_chunks_a_span_past_the_polynomial_capacity() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let discriminant = qr_discriminant(rng);
    let published: Vec<Tachygram> = (0..=3)
        .flat_map(|height| pool.block(BlockHeight(height)).tachygrams())
        .flatten()
        .collect();
    let capacity = 11;

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        capacity,
        1,
    );

    assert!(
        routed.len() > 2,
        "no intake holds more than the capacity, so twenty-four members need three"
    );
    let mut covered: Vec<Tachygram> = Vec::new();
    for side in [true, false] {
        let run: Vec<&QrIntakeEntry> = routed
            .iter()
            .filter(|intake| intake.pcd.data().4 == QrProfile::ROOT.descend(side))
            .collect();
        let first = run.first().expect("each side carries an intake");
        assert_eq!(
            first.pcd.data().1,
            Anchor::default(),
            "the side's run opens at the span's start"
        );
        let mut cursor = first.pcd.data().2;
        for pair in run.windows(2) {
            assert_eq!(
                pair[1].pcd.data().1,
                cursor,
                "the side's intakes cover adjacent spans"
            );
            assert!(
                (pair[0].members.len() + pair[1].members.len()) > capacity,
                "neighbours merge as far as the capacity allows"
            );
            cursor = pair[1].pcd.data().2;
        }
        assert_eq!(cursor, terminal, "the side's run closes at the span's end");
        for intake in run {
            covered.extend(intake.members.iter().copied());
        }
    }

    let sorted = |mut tgs: Vec<Tachygram>| {
        tgs.sort_unstable_by_key(|&tg| Fp::from(tg).to_repr());
        tgs
    };
    assert_eq!(
        sorted(covered),
        sorted(published),
        "the runs still partition the epoch's published tachygrams"
    );
}

#[test]
fn qr_bucket_seal_seals_a_fully_routed_intake() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let discriminant = qr_discriminant(rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        24,
        2,
    );
    let intake = routed.into_iter().next().expect("one intake");
    let (epoch, anchor_prev, anchor_last, _, profile, contents) = *intake.pcd.data();
    let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));

    assert_eq!(
        *bucket.pcd.data(),
        (
            epoch,
            anchor_prev,
            anchor_last,
            discriminant,
            profile,
            contents
        ),
        "sealing keeps every field"
    );
    assert_eq!(
        anchor_prev,
        Anchor::default(),
        "epoch zero's opening anchor is the general rule at anchor_prev_prev = 0"
    );
    assert_eq!(
        anchor_last, terminal,
        "and the bucket closes on the epoch's terminal anchor, not past it"
    );
}

#[test]
fn qr_bucket_seal_rejects_an_intake_short_of_the_epoch_boundary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    // Opening the span past the epoch's first stamp leaves it rooted on a stamp
    // anchor, which the epoch domain cannot produce.
    let terminal = pool.block(BlockHeight(2)).anchor();
    let discriminant = qr_discriminant(rng);
    let start = pool.block(BlockHeight(0)).anchor();

    let routed = build_qr_partition(rng, &pool, (start, terminal), discriminant, 12, 1);
    let intake = routed.into_iter().next().expect("one intake");
    let witness = witness::qr_bucket_seal((*intake.pcd.data(), ()), Anchor::from(Fp::ZERO));
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness,
            intake.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrBucketSeal: intake's first anchor is not an epoch link into its epoch"
    );
}

/// The seal says nothing about where the extent ends: an intake that stops
/// well short of the epoch's terminal anchor still seals, carrying its own
/// endpoint. Consuming it is what fails, since `QrUnspentInit` then folds a
/// crossing the pool never published.
#[test]
fn qr_bucket_seal_accepts_an_extent_short_of_the_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let discriminant = qr_discriminant(rng);

    // A six-member capacity chunks the epoch into four roots.
    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        6,
        0,
    );
    let intake = routed.into_iter().next().expect("one intake");
    let (_, anchor_prev, anchor_last, ..) = *intake.pcd.data();
    assert_eq!(anchor_prev, Anchor::default());
    assert_ne!(
        anchor_last, terminal,
        "the first root stops inside the epoch"
    );

    let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));
    assert_eq!(
        (bucket.pcd.data().2, bucket.pcd.data().3),
        (anchor_last, discriminant),
        "the seal keeps the short extent and its routing base"
    );
}

/// The routing base moves how members distribute, not which bucket holds a
/// value under it: two networks over the same epoch at different bases each
/// admit the same absent nullifier.
#[test]
fn qr_unspent_init_accepts_a_nullifier_under_either_routing_base() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, terminal) = small_epoch(rng);
    let epoch = BlockHeight(0).epoch();
    let nf = Nullifier::from(Fp::random(&mut *rng));
    let nf_next = Nullifier::from(Fp::random(&mut *rng));

    let first = qr_discriminant(rng);
    let second = qr_discriminant(rng);
    assert_ne!(first, second);

    for discriminant in [first, second] {
        let bucket = qr_bucket_at(
            rng,
            &pool,
            (Anchor::default(), terminal),
            discriminant,
            24,
            2,
            Fp::from(nf),
            Anchor::from(Fp::ZERO),
        );
        assert_eq!(bucket.pcd.data().3, discriminant);

        let witness = witness::qr_unspent_init(
            (*bucket.pcd.data(), ()),
            nf.into(),
            nf_next,
            &bucket.members,
        );
        let unspent = fuse_unspent_init(rng, bucket.pcd, witness).expect("QrUnspentInit");
        assert_eq!(unspent.data().1, (epoch, nf));
    }
}

#[test]
fn qr_unspent_init_accepts_an_absent_nullifier_against_its_bucket() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let discriminant = qr_discriminant(rng);
    let epoch = BlockHeight(0).epoch();
    let epoch_next = epoch.next().unwrap();
    let [nf, nf_next] = array::from_fn(|_| Nullifier::from(Fp::random(&mut *rng)));

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        24,
        2,
    );
    let profile = qr_profile_of(Fp::from(nf), discriminant, 2);
    let intake = routed
        .into_iter()
        .find(|intake| intake.pcd.data().4 == profile)
        .expect("one intake carries the nullifier's own profile");
    assert!(
        !intake
            .members
            .iter()
            .any(|&member| Fp::from(member) == Fp::from(nf)),
        "a fresh nullifier is absent from the epoch"
    );
    let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));

    let witness = witness::qr_unspent_init(
        (*bucket.pcd.data(), ()),
        nf.into(),
        nf_next,
        &bucket.members,
    );
    let unspent = fuse_unspent_init(rng, bucket.pcd, witness).expect("QrUnspentInit");

    let (anchor_prev, first, elapsed, last, anchor_last) = *unspent.data();
    assert_eq!(
        anchor_prev,
        Anchor::default(),
        "the segment opens where the partition's span does"
    );
    assert_eq!(
        anchor_last,
        terminal.next_epoch(epoch_next).unwrap(),
        "and closes on the crossing out of the epoch"
    );
    assert_eq!(first, (epoch, nf));
    assert_eq!(
        last,
        (epoch_next, nf_next),
        "the segment carries the crossing's far member"
    );
    assert_eq!(elapsed, NfSeqPoly::new(epoch, &[nf, nf_next]).commit());
}

/// Every QR segment crosses out of its own epoch, so two consecutive epochs'
/// segments abut at the entry anchor and `UnspentFuse` composes them directly,
/// with no `EndEpochUnspentSeed` in between.
#[test]
fn qr_unspent_segments_of_consecutive_epochs_fuse_directly() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let epoch2 = epoch1.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    // Fill epoch zero and open epoch one, one stamp per block.
    pool.advance(epoch1.first_block().0 + 1, |_| random_block(rng, 1, 1));
    let [nf0, nf1, nf2] = array::from_fn(|_| Nullifier::from(Fp::random(&mut *rng)));

    let terminal0 = pool.block(epoch0.last_block()).anchor();
    let terminal1 = pool.anchor();
    let bucket0 = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), terminal0),
        EPOCH_MEMBERS,
        0,
        Fp::from(nf0),
        Anchor::from(Fp::ZERO),
    );
    let bucket1 = qr_bucket_for(
        rng,
        &pool,
        (pool.block(epoch1.first_block()).prev, terminal1),
        EPOCH_MEMBERS,
        0,
        Fp::from(nf1),
        terminal0,
    );

    let mut segment = |bucket: QrBucketEntry, nf: Nullifier, nf_next: Nullifier| {
        let witness = witness::qr_unspent_init(
            (*bucket.pcd.data(), ()),
            nf.into(),
            nf_next,
            &bucket.members,
        );
        fuse_unspent_init(rng, bucket.pcd, witness).expect("QrUnspentInit")
    };
    let left = segment(bucket0, nf0, nf1);
    let right = segment(bucket1, nf1, nf2);
    let entry1 = terminal0.next_epoch(epoch1).unwrap();
    assert_eq!(
        left.data().4,
        entry1,
        "epoch zero's segment crosses to epoch one's entry anchor"
    );
    assert_eq!(
        left.data().4,
        right.data().0,
        "which is exactly where epoch one's segment opens"
    );

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            UnspentFuse,
            witness::unspent_fuse((*left.data(), *right.data()), &[nf0, nf1], &[nf1, nf2]),
            left,
            right,
        )
        .expect("UnspentFuse straight across the boundary");

    let (anchor_prev, first, elapsed, last, anchor_last) = *fused.data();
    assert_eq!(anchor_prev, Anchor::default());
    assert_eq!(first, (epoch0, nf0));
    assert_eq!(last, (epoch2, nf2));
    assert_eq!(anchor_last, terminal1.next_epoch(epoch2).unwrap());
    assert_eq!(
        elapsed,
        NfSeqPoly::new(epoch0, &[nf0, nf1, nf2]).commit(),
        "the junction epoch's member is shared, not repeated"
    );
}

/// A note created in epoch zero bootstraps from the bucket holding its `cm`
/// over its own QR segment, rests at epoch one's entry anchor because the
/// segment already crossed, lifts through epoch one on ordinary segments, and
/// binds a spend in epoch two.
#[test]
fn qr_spendable_init_starts_a_spendable_that_reaches_spend_bind() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let epoch2 = epoch1.next().unwrap();
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    // Fill epochs zero and one and open epoch two, one stamp per block.
    pool.advance(epoch2.first_block().0, |_| random_block(rng, 1, 1));

    // Two levels down, the note's `cm` and its epoch-zero nullifier take
    // different paths, so the spendable pairs one bucket against a segment
    // built over another. Both span the epoch, which is what closes them.
    let span = (Anchor::default(), pool.block(epoch0.last_block()).anchor());
    let bucket = qr_bucket_for(
        rng,
        &pool,
        span,
        EPOCH_MEMBERS,
        2,
        Fp::from(Tachygram::from(note.commitment())),
        Anchor::from(Fp::ZERO),
    );
    let nf_bucket = qr_bucket_for(
        rng,
        &pool,
        span,
        EPOCH_MEMBERS,
        2,
        Fp::from(user.nf_at(&note, epoch0)),
        Anchor::from(Fp::ZERO),
    );
    assert_ne!(
        bucket.pcd.data().4,
        nf_bucket.pcd.data().4,
        "the commitment and the nullifier route to different buckets"
    );
    let (_, _, anchor_last, ..) = *bucket.pcd.data();
    let unspent = qr_epoch_unspent(rng, &user, &note, &nf_bucket);

    let (spendable, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::QrSpendableInit,
            witness::qr_spendable_init((*unspent.data(), *bucket.pcd.data()), &bucket.members),
            unspent,
            bucket.pcd,
        )
        .expect("QrSpendableInit");
    assert_eq!(
        *spendable.data(),
        (
            note.commitment(),
            (epoch1, user.nf_at(&note, epoch1)),
            anchor_last.next_epoch(epoch1).unwrap()
        ),
        "the spendable rests on epoch one's entry anchor with that epoch's nullifier"
    );

    let lifted = user.lift_to_epoch(rng, &pool, &note, spendable, epoch2);
    let derived = user.derivation_pcd(rng, note, epoch2, EpochIndex::new(u32::from(epoch2) + 1));
    let (bind, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spend::SpendBind,
            witness::spend_bind(
                (*lifted.data(), *derived.data()),
                &user.covering_window(&note, &derived),
            ),
            lifted,
            derived,
        )
        .expect("SpendBind");
    let (bind_cm, nf_current, nf_next, _) = *bind.data();
    assert_eq!(bind_cm, note.commitment());
    assert_eq!(
        (nf_current, nf_next),
        (
            user.nf_at(&note, epoch2),
            user.nf_at(&note, EpochIndex::new(u32::from(epoch2) + 1))
        )
    );
}

/// A short bucket's evidence is unconsumable. The init folds the crossing out
/// of the bucket's own last anchor, and for a bucket that stopped inside its
/// epoch that lands on an anchor the pool never published, so no same-epoch
/// suffix is adjacent to the spendable it bootstraps.
#[test]
fn qr_short_bucket_yields_evidence_no_suffix_can_extend() {
    let rng = &mut StdRng::seed_from_u64(196);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch = EpochIndex::new(0);
    let nf = user.nf_at(&note, epoch);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    let short_anchor = pool.anchor();
    pool.mine(random_block(rng, 2, 1));
    let tip_anchor = pool.anchor();
    assert_ne!(short_anchor, tip_anchor, "the bucket omits later stamps");
    assert_eq!(
        pool.height().epoch(),
        epoch,
        "no epoch boundary was crossed"
    );

    let bucket = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), short_anchor),
        1,
        0,
        Fp::from(Tachygram::from(note.commitment())),
        Anchor::from(Fp::ZERO),
    );
    assert_eq!(
        bucket.pcd.data().2,
        short_anchor,
        "the seal keeps the short extent"
    );
    let unspent = qr_epoch_unspent(rng, &user, &note, &bucket);
    let (spendable, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::QrSpendableInit,
            witness::qr_spendable_init((*unspent.data(), *bucket.pcd.data()), &bucket.members),
            unspent,
            bucket.pcd,
        )
        .expect("QrSpendableInit over the short extent");
    let epoch_next = epoch.next().unwrap();
    let unpublished = short_anchor.next_epoch(epoch_next).unwrap();
    assert_eq!(
        *spendable.data(),
        (
            note.commitment(),
            (epoch_next, user.nf_at(&note, epoch_next)),
            unpublished
        ),
        "the spendable rests on an epoch link the pool never published"
    );
    assert!(
        pool.stamps_between(Anchor::default(), tip_anchor)
            .iter()
            .all(|entry| entry.3 != unpublished),
        "no published anchor equals the short extent's crossing"
    );

    // The same-epoch suffix opens on the bucket's own last anchor, which the
    // crossing has already left behind, so the lift finds nothing adjacent.
    let suffix = build_unspent_pcd_between_anchors(rng, &pool, &[nf], (short_anchor, tip_anchor));
    let bound_suffix = user.unspent_bind(rng, suffix, &note);
    assert_ne!(
        bound_suffix.data().1,
        unpublished,
        "the suffix opens on the bucket's own last anchor, not the crossing"
    );
    let err = PROOF_SYSTEM
        .fuse(rng, spendable::SpendableLift, (), spendable, bound_suffix)
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "SpendableLift: segment does not start at the lineage nullifier",
        "the lift rejects it; a same-epoch suffix cannot reopen the crossed epoch"
    );
}

#[test]
fn qr_spendable_init_rejects_an_absent_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch0 = EpochIndex::new(0);
    // The note's cm is published nowhere in this pool.
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch0.last_block().0, |_| random_block(rng, 1, 1));

    let bucket = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), pool.block(epoch0.last_block()).anchor()),
        EPOCH_MEMBERS,
        0,
        Fp::from(Tachygram::from(note.commitment())),
        Anchor::from(Fp::ZERO),
    );
    let unspent = qr_epoch_unspent(rng, &user, &note, &bucket);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::QrSpendableInit,
            witness::qr_spendable_init((*unspent.data(), *bucket.pcd.data()), &bucket.members),
            unspent,
            bucket.pcd,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrSpendableInit: commitment not in bucket"
    );
}

/// A bucket sealed short of the epoch opens at the real boundary but closes
/// inside it, so it cannot pair with the note's whole-epoch segment.
#[test]
fn qr_spendable_init_rejects_a_bucket_whose_span_differs_from_the_segment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch0 = EpochIndex::new(0);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.advance(epoch0.last_block().0, |_| random_block(rng, 1, 1));

    let cm = Fp::from(Tachygram::from(note.commitment()));
    let whole = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), pool.block(epoch0.last_block()).anchor()),
        EPOCH_MEMBERS,
        0,
        cm,
        Anchor::from(Fp::ZERO),
    );
    let unspent = qr_epoch_unspent(rng, &user, &note, &whole);
    let short = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), pool.block(BlockHeight(1)).anchor()),
        EPOCH_MEMBERS,
        0,
        cm,
        Anchor::from(Fp::ZERO),
    );

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::QrSpendableInit,
            witness::qr_spendable_init((*unspent.data(), *short.pcd.data()), &short.members),
            unspent,
            short.pcd,
        )
        .err()
        .unwrap();
    let ragu_core::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrSpendableInit: segment does not close on the bucket's crossing"
    );
}

/// Evidence of the pre-crossing shape, ending on the bucket's own last anchor,
/// no longer pairs with the bucket it was built over.
#[test]
fn qr_spendable_init_rejects_a_segment_that_stops_inside_the_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch0 = EpochIndex::new(0);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.advance(epoch0.last_block().0, |_| random_block(rng, 1, 1));
    let terminal0 = pool.block(epoch0.last_block()).anchor();

    let bucket = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), terminal0),
        EPOCH_MEMBERS,
        0,
        Fp::from(Tachygram::from(note.commitment())),
        Anchor::from(Fp::ZERO),
    );
    // The old shape: ordinary same-epoch evidence over the bucket's own extent.
    let nf = user.nf_at(&note, epoch0);
    let arbitrary =
        build_unspent_pcd_between_anchors(rng, &pool, &[nf], (Anchor::default(), terminal0));
    let unspent = user.unspent_bind(rng, arbitrary, &note);
    assert_eq!(unspent.data().4, terminal0);

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::QrSpendableInit,
            witness::qr_spendable_init((*unspent.data(), *bucket.pcd.data()), &bucket.members),
            unspent,
            bucket.pcd,
        )
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrSpendableInit: segment does not close on the bucket's crossing"
    );
}

/// A bucket of the following epoch cannot pair with a segment over the
/// creation epoch.
#[test]
fn qr_spendable_init_rejects_a_bucket_of_another_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.advance(epoch1.last_block().0, |_| random_block(rng, 1, 1));
    let terminal0 = pool.block(epoch0.last_block()).anchor();
    let terminal1 = pool.block(epoch1.last_block()).anchor();

    let nf_bucket = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), terminal0),
        EPOCH_MEMBERS,
        0,
        Fp::from(user.nf_at(&note, epoch0)),
        Anchor::from(Fp::ZERO),
    );
    let unspent = qr_epoch_unspent(rng, &user, &note, &nf_bucket);
    let later = qr_bucket_for(
        rng,
        &pool,
        (
            terminal0.next_epoch(epoch1).expect("epoch one is nonzero"),
            terminal1,
        ),
        EPOCH_MEMBERS,
        0,
        Fp::from(Tachygram::from(note.commitment())),
        terminal0,
    );

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::QrSpendableInit,
            witness::qr_spendable_init((*unspent.data(), *later.pcd.data()), &later.members),
            unspent,
            later.pcd,
        )
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrSpendableInit: segment does not start in the bucket's epoch"
    );
}

/// A bucket sealed over an invented boundary of the same epoch opens
/// elsewhere than the note's segment.
#[test]
fn qr_spendable_init_rejects_a_bucket_opening_elsewhere() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch1.last_block().0, |_| random_block(rng, 1, 1));
    let terminal0 = pool.block(epoch0.last_block()).anchor();
    let terminal1 = pool.block(epoch1.last_block()).anchor();

    let nf_bucket = qr_bucket_for(
        rng,
        &pool,
        (
            terminal0.next_epoch(epoch1).expect("epoch one is nonzero"),
            terminal1,
        ),
        EPOCH_MEMBERS,
        0,
        Fp::from(user.nf_at(&note, epoch1)),
        terminal0,
    );
    let unspent = qr_epoch_unspent(rng, &user, &note, &nf_bucket);

    // The invented preceding anchor gives an epoch-one boundary the chain never
    // produced; the seal accepts it because the opening matches `anchor_prev_prev`.
    let fake_anchor_prev_prev = Anchor::from(Fp::ONE);
    let fake_prev = fake_anchor_prev_prev
        .next_epoch(epoch1)
        .expect("epoch one is nonzero");
    let members = [Tachygram::from(note.commitment())];
    let discriminant = qr_discriminant(rng);
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
        fake_anchor_prev_prev,
    );

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::QrSpendableInit,
            witness::qr_spendable_init(
                (*unspent.data(), *elsewhere.pcd.data()),
                &elsewhere.members,
            ),
            unspent,
            elsewhere.pcd,
        )
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrSpendableInit: segment does not open where the bucket does"
    );
}

#[test]
fn qr_unspent_init_rejects_a_published_nullifier() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let discriminant = qr_discriminant(rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        24,
        2,
    );
    let intake = routed
        .into_iter()
        .find(|intake| !intake.members.is_empty())
        .expect("some intake holds a member");
    let published = *intake.members.first().expect("a member");
    let nf = Nullifier::from(Fp::from(published));
    let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));

    let witness = witness::qr_unspent_init(
        (*bucket.pcd.data(), ()),
        nf.into(),
        Nullifier::from(Fp::random(&mut *rng)),
        &bucket.members,
    );
    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: found nullifier in the bucket"
    );
}

#[test]
fn qr_unspent_init_rejects_a_foreign_bucket() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let discriminant = qr_discriminant(rng);
    let nf = Nullifier::from(Fp::random(&mut *rng));

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        24,
        2,
    );
    let profile = qr_profile_of(Fp::from(nf), discriminant, 2);
    let foreign = routed
        .into_iter()
        .find(|intake| intake.pcd.data().4 != profile)
        .expect("three intakes carry another profile");
    let bucket = seal_qr_intake(rng, foreign, Anchor::from(Fp::ZERO));

    let witness = witness::qr_unspent_init(
        (*bucket.pcd.data(), ()),
        nf.into(),
        Nullifier::from(Fp::random(&mut *rng)),
        &bucket.members,
    );
    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: value does not take the bucket's profile"
    );
}

/// A fresh nullifier, its depth-two bucket over a small epoch, and the honest
/// witness, which is checked to pass before any test tampers with it.
fn honest_unspent_init(rng: &mut StdRng) -> (Nullifier, QrBucketEntry, UnspentInitWitness) {
    let (pool, terminal) = small_epoch(rng);
    let nf = Nullifier::from(Fp::random(&mut *rng));
    let bucket = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), terminal),
        24,
        2,
        Fp::from(nf),
        Anchor::from(Fp::ZERO),
    );
    let witness = witness::qr_unspent_init(
        (*bucket.pcd.data(), ()),
        nf.into(),
        Nullifier::from(Fp::random(&mut *rng)),
        &bucket.members,
    );
    fuse_unspent_init(rng, bucket.pcd.clone(), witness.clone()).expect("the honest witness passes");
    (nf, bucket, witness)
}

#[test]
fn qr_unspent_init_rejects_a_root_off_its_class() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_nf, bucket, mut witness) = honest_unspent_init(rng);

    let (_, _, ref mut roots, ..) = witness;
    let QrClassRoot(_, ref mut root) = roots[0];
    let off = *root + Fp::ONE;
    assert_ne!(off.square(), root.square());
    *root = off;

    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: root does not square to the claimed class"
    );
}

/// Positions past the bucket's depth are compared to nothing, but still
/// tested against the value.
#[test]
fn qr_unspent_init_tests_sides_past_the_bucket_depth() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (nf, bucket, mut witness) = honest_unspent_init(rng);
    let (_, _, _, discriminant, profile, ..) = *bucket.pcd.data();
    assert_eq!(profile.depth, 2);

    let position = 5;
    let shifted = Fp::from(nf) + discriminant.at(position);
    assert_ne!(shifted, Fp::ZERO);
    let (_, _, ref mut roots, ..) = witness;
    let QrClassRoot(ref mut side, _) = roots[usize::try_from(position).unwrap()];
    *side = !*side;

    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: root does not square to the claimed class"
    );
}

/// The exceptional value $-R_j$ has root zero under either class and is filed
/// residue-side, so claiming the non-residue side there is refused.
#[test]
fn qr_unspent_init_rejects_the_fixed_point_on_the_non_residue_side() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, terminal) = small_epoch(rng);
    let discriminant = qr_discriminant(rng);
    let position = 1;
    let value = -discriminant.at(position);
    assert_ne!(value, Fp::ZERO);
    let nf = Nullifier::from(value);

    let bucket = qr_bucket_at(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        24,
        2,
        value,
        Anchor::from(Fp::ZERO),
    );
    assert!(
        !bucket
            .members
            .iter()
            .any(|&member| Fp::from(member) == value),
        "the fixed point is absent from the epoch"
    );
    let mut witness = witness::qr_unspent_init(
        (*bucket.pcd.data(), ()),
        nf.into(),
        Nullifier::from(Fp::random(&mut *rng)),
        &bucket.members,
    );
    let (_, _, honest_roots, ..) = witness;
    assert_eq!(
        honest_roots[usize::try_from(position).unwrap()],
        QrClassRoot(true, Fp::ZERO)
    );
    fuse_unspent_init(rng, bucket.pcd.clone(), witness.clone())
        .expect("the fixed point passes on the residue side");

    let (_, _, ref mut roots, ..) = witness;
    let QrClassRoot(ref mut side, _) = roots[usize::try_from(position).unwrap()];
    *side = false;
    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: exceptional discriminant claimed the non-residue class"
    );
}

#[test]
fn qr_unspent_init_rejects_a_non_prefix_mask() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_nf, bucket, mut witness) = honest_unspent_init(rng);

    let (_, _, _, ref mut depth_mask, ..) = witness;
    *depth_mask = array::from_fn(|position| position == 0 || position == 2);

    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: depth mask is not a prefix"
    );
}

#[test]
fn qr_unspent_init_rejects_a_mask_of_the_wrong_depth() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_nf, bucket, mut witness) = honest_unspent_init(rng);

    let (_, _, _, ref mut depth_mask, ..) = witness;
    *depth_mask = QrProfile { depth: 3, bits: 0 }.depth_mask();

    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: depth mask does not match the bucket's depth"
    );
}

/// Recarrying a proof under altered header data exercises the step's own
/// constraints under mock ragu; a real proof would not authenticate the
/// altered header.
fn recarry_bucket(
    bucket: &QrBucketEntry,
    alter: impl FnOnce(&mut <qr::QrBucket as ragu::Header>::Data),
) -> Pcd<qr::QrBucket> {
    let mut data = *bucket.pcd.data();
    alter(&mut data);
    bucket.pcd.proof().clone().carry::<qr::QrBucket>(data)
}

/// The final epoch has no successor, so there is no crossing to fold and the
/// init refuses. Nothing is lost: a spend in the final epoch cannot bind
/// either.
#[test]
fn qr_unspent_init_refuses_a_bucket_in_the_final_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (nf, bucket, _witness) = honest_unspent_init(rng);

    let forged = recarry_bucket(&bucket, |&mut (ref mut epoch, ..)| {
        *epoch = EpochIndex::new(EPOCH_MAX);
    });
    let witness = witness::qr_unspent_init(
        (*forged.data(), ()),
        nf.into(),
        Nullifier::from(Fp::random(&mut *rng)),
        &bucket.members,
    );
    let err = fuse_unspent_init(rng, forged, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: crossing past the final epoch"
    );
}

#[test]
fn qr_unspent_init_rejects_a_bucket_past_the_maximum_depth() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_nf, bucket, mut witness) = honest_unspent_init(rng);

    let forged = recarry_bucket(&bucket, |&mut (_, _, _, _, ref mut profile, ..)| {
        profile.depth = u32::BITS + 1;
    });
    let (_, _, _, ref mut depth_mask, ..) = witness;
    // Bypass the constructor's range check to exercise the step's constraint.
    *depth_mask = [true; QrProfile::MAX_DEPTH];
    let err = fuse_unspent_init(rng, forged, witness.clone())
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: depth mask does not match the bucket's depth"
    );

    let saturated = recarry_bucket(&bucket, |&mut (_, _, _, _, ref mut profile, ..)| {
        profile.depth = u32::MAX;
    });
    let (_, _, _, ref mut saturated_mask, ..) = witness;
    *saturated_mask = [true; QrProfile::MAX_DEPTH];
    let saturated_err = fuse_unspent_init(rng, saturated, witness).err().unwrap();
    assert_eq!(
        invalid_witness(saturated_err),
        "QrUnspentInit: depth mask does not match the bucket's depth"
    );
}

#[test]
fn qr_unspent_init_rejects_a_malformed_profile() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_nf, bucket, witness) = honest_unspent_init(rng);

    let forged = recarry_bucket(&bucket, |&mut (_, _, _, _, ref mut profile, ..)| {
        *profile = QrProfile { depth: 0, bits: 1 };
    });
    let mut shallow = witness.clone();
    let (_, _, _, ref mut depth_mask, ..) = shallow;
    *depth_mask = QrProfile::ROOT.depth_mask();
    let err = fuse_unspent_init(rng, forged, shallow).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: value does not take the bucket's profile"
    );

    let overflowing = recarry_bucket(&bucket, |&mut (_, _, _, _, ref mut profile, ..)| {
        profile.bits |= 1 << 2;
    });
    let overflowing_err = fuse_unspent_init(rng, overflowing, witness).err().unwrap();
    assert_eq!(
        invalid_witness(overflowing_err),
        "QrUnspentInit: value does not take the bucket's profile"
    );
}

#[test]
fn qr_unspent_init_rejects_a_zero_value() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_nf, bucket, _witness) = honest_unspent_init(rng);

    let witness = witness::qr_unspent_init(
        (*bucket.pcd.data(), ()),
        Tachygram::from(Fp::ZERO),
        Nullifier::from(Fp::random(&mut *rng)),
        &bucket.members,
    );
    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(invalid_witness(err), "QrUnspentInit: tested value is zero");
}

#[test]
fn qr_unspent_init_rejects_a_zero_next_nullifier() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (nf, bucket, _witness) = honest_unspent_init(rng);

    let witness = witness::qr_unspent_init(
        (*bucket.pcd.data(), ()),
        nf.into(),
        Nullifier::from(Fp::ZERO),
        &bucket.members,
    );
    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: next-epoch nullifier is zero"
    );
}

#[test]
fn qr_unspent_init_rejects_a_sequence_naming_another_value() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (nf, bucket, mut witness) = honest_unspent_init(rng);
    let (epoch, ..) = *bucket.pcd.data();

    let other = Nullifier::from(Fp::random(&mut *rng));
    assert_ne!(other, nf);
    let nf_next = witness.1;
    let (_, _, _, _, ref mut sequence, _) = witness;
    *sequence = NfSeqPoly::new(epoch, &[other, nf_next]);

    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: sequence does not match the crossing pairs"
    );
}

#[test]
fn qr_unspent_init_rejects_foreign_contents() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_nf, bucket, mut witness) = honest_unspent_init(rng);

    let foreign = iter::once(Tachygram::from(Fp::random(&mut *rng))).collect::<TachygramSetPoly>();
    let (.., contents_commit) = *bucket.pcd.data();
    assert_ne!(foreign.commit(), contents_commit);
    let (.., ref mut contents) = witness;
    *contents = foreign;

    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: contents do not match the bucket"
    );
}

/// The step reads one bucket's depth, so a router splits only what is over
/// capacity and its partition is an unbalanced trie: one side sealed at
/// depth 1 and a leaf under the other side sealed at depth 3 each admit
/// their own value's segment.
#[test]
fn qr_unspent_init_accepts_ragged_depths() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, terminal) = small_epoch(rng);
    let epoch = BlockHeight(0).epoch();
    let epoch_next = epoch.next().unwrap();
    let discriminant = qr_discriminant(rng);
    let shallow_value = Fp::random(&mut *rng);
    let shallow_side = qr::classify(shallow_value, discriminant.at(0)).0;
    let deep_value = iter::repeat_with(|| Fp::random(&mut *rng))
        .find(|&value| qr::classify(value, discriminant.at(0)).0 != shallow_side)
        .expect("a value on the other side");

    let root = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        24,
        0,
    )
    .pop()
    .expect("one root");
    let (non_residue, residue) = split_qr_intake(rng, root);
    let (shallow, mut deep) = if shallow_side {
        (residue, non_residue)
    } else {
        (non_residue, residue)
    };
    for level in 1..3 {
        let (deep_non_residue, deep_residue) = split_qr_intake(rng, deep);
        deep = if qr::classify(deep_value, discriminant.at(level)).0 {
            deep_residue
        } else {
            deep_non_residue
        };
    }

    let buckets = [(shallow, shallow_value, 1), (deep, deep_value, 3)];
    for (intake, value, depth) in buckets {
        let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));
        let (_, _, _, _, profile, _) = *bucket.pcd.data();
        assert_eq!(profile, qr_profile_of(value, discriminant, depth));
        let nf = Nullifier::from(value);
        let nf_next = Nullifier::from(Fp::random(&mut *rng));
        let witness = witness::qr_unspent_init(
            (*bucket.pcd.data(), ()),
            nf.into(),
            nf_next,
            &bucket.members,
        );
        let unspent = fuse_unspent_init(rng, bucket.pcd, witness).expect("QrUnspentInit");
        assert_eq!(
            *unspent.data(),
            (
                Anchor::default(),
                (epoch, nf),
                NfSeqPoly::new(epoch, &[nf, nf_next]).commit(),
                (epoch_next, nf_next),
                terminal.next_epoch(epoch_next).unwrap()
            ),
            "the segment is the bucket's extent plus the crossing, at depth {depth}"
        );
    }
}

/// A bucket at any depth up to the maximum admits the segment, whatever its
/// bits.
#[test]
fn qr_unspent_init_accepts_buckets_at_every_depth() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, terminal) = small_epoch(rng);
    let epoch = BlockHeight(0).epoch();
    let epoch_next = epoch.next().unwrap();
    let nf = Nullifier::from(Fp::random(&mut *rng));

    for depth in [0, 1, 31, u32::BITS] {
        let bucket = qr_bucket_for(
            rng,
            &pool,
            (Anchor::default(), terminal),
            24,
            depth,
            Fp::from(nf),
            Anchor::from(Fp::ZERO),
        );
        let (_, _, _, discriminant, profile, _) = *bucket.pcd.data();
        assert_eq!(profile, qr_profile_of(Fp::from(nf), discriminant, depth));

        let nf_next = Nullifier::from(Fp::random(&mut *rng));
        let witness = witness::qr_unspent_init(
            (*bucket.pcd.data(), ()),
            nf.into(),
            nf_next,
            &bucket.members,
        );
        let unspent = fuse_unspent_init(rng, bucket.pcd, witness).expect("QrUnspentInit");
        assert_eq!(
            *unspent.data(),
            (
                Anchor::default(),
                (epoch, nf),
                NfSeqPoly::new(epoch, &[nf, nf_next]).commit(),
                (epoch_next, nf_next),
                terminal.next_epoch(epoch_next).unwrap()
            ),
            "the segment is the bucket's extent plus the crossing, at depth {depth}"
        );
    }
}

#[test]
fn qr_intake_merge_rejects_different_discriminants() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let left_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (left_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &left_members),
        )
        .expect("SummarySeed");
    let (_, _, junction, _) = *left_summary.data();
    let (right_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), junction, epoch, &right_members),
        )
        .expect("SummarySeed");

    let [left, right] = [left_summary, right_summary].map(|summary| {
        let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
        let (root, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSummaryIntakeInit,
                witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
                summary,
                Proof::trivial().carry::<()>(()),
            )
            .expect("QrSummaryIntakeInit");
        root
    });
    assert_ne!(left.data().3, right.data().3);

    let witness =
        witness::qr_intake_merge((*left.data(), *right.data()), &left_members, &right_members);
    let err = PROOF_SYSTEM
        .fuse(rng, qr::QrIntakeMerge, witness, left, right)
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrIntakeMerge: inputs derive from different discriminants"
    );
}

#[test]
fn qr_intake_merge_rejects_different_epochs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let start = Anchor::from(Fp::random(&mut *rng));
    let left_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::from(Fp::random(&mut *rng)));

    let (left_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &left_members),
        )
        .expect("SummarySeed");
    let (_, _, junction, _) = *left_summary.data();
    let (right_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), junction, epoch.next().unwrap(), &right_members),
        )
        .expect("SummarySeed");

    let [left, right] = [left_summary, right_summary].map(|summary| {
        let (root, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSummaryIntakeInit,
                witness::qr_summary_intake_init((*summary.data(), ()), discriminant),
                summary,
                Proof::trivial().carry::<()>(()),
            )
            .expect("QrSummaryIntakeInit");
        root
    });
    assert_ne!(left.data().0, right.data().0);

    let witness =
        witness::qr_intake_merge((*left.data(), *right.data()), &left_members, &right_members);
    let err = PROOF_SYSTEM
        .fuse(rng, qr::QrIntakeMerge, witness, left, right)
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrIntakeMerge: inputs cover different epochs"
    );
}

/// Routing consecutive values: each lands in the bucket of its own profile,
/// and the buckets together hold every value. A correctness check on
/// structured input, not a balance measurement.
#[test]
fn qr_partition_routes_consecutive_values_by_profile() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let anchor_prev = Anchor::from(Fp::random(&mut *rng));
    let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
    let base = Fp::random(&mut *rng);
    let members: Vec<Tachygram> = (0..12u64)
        .map(|offset| Tachygram::from(base + Fp::from(offset)))
        .collect();
    let depth = 3;

    let (pcd, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), anchor_prev, epoch, discriminant, &members),
        )
        .expect("QrStampIntakeSeed");
    let mut layer = vec![QrIntakeEntry {
        pcd,
        members: members.clone(),
    }];
    for _ in 0..depth {
        let mut next = Vec::with_capacity(layer.len() * 2);
        for intake in layer {
            let (non_residue, residue) = split_qr_intake(rng, intake);
            next.push(non_residue);
            next.push(residue);
        }
        layer = next;
    }

    let mut routed = Vec::new();
    for leaf in &layer {
        let (.., profile, _contents) = *leaf.pcd.data();
        for &member in &leaf.members {
            assert_eq!(
                qr_profile_of(Fp::from(member), discriminant, depth),
                profile
            );
            routed.push(member);
        }
    }
    routed.sort_by_key(|member| Fp::from(*member).to_repr());
    let mut expected = members;
    expected.sort_by_key(|member| Fp::from(*member).to_repr());
    assert_eq!(routed, expected, "every value reaches exactly one leaf");
}

/// One sealed bucket as a one-leaf [`qr::QrBucketTree`].
fn tree_of(rng: &mut StdRng, bucket: QrBucketEntry) -> Pcd<qr::QrBucketTree> {
    let (pcd, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketTreeInit,
            (),
            bucket.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrBucketTreeInit");
    pcd
}

/// Join two trees under a fresh node.
fn fuse_trees(
    rng: &mut StdRng,
    left: Pcd<qr::QrBucketTree>,
    right: Pcd<qr::QrBucketTree>,
) -> ragu_core::Result<Pcd<qr::QrBucketTree>> {
    PROOF_SYSTEM
        .fuse(rng, qr::QrBucketTreeFuse, (), left, right)
        .map(|(tree, ())| tree)
}

/// Descend `tree` along one leaf's path, stopping on the leaf itself.
fn descend_to_leaf(
    rng: &mut StdRng,
    tree: Pcd<qr::QrBucketTree>,
    leaf: &QrBucketLeaf,
) -> Pcd<qr::QrBucketTree> {
    let mut node = tree;
    for chunk in leaf.path.chunks(QrTreeFork::LEVELS) {
        let path = <[QrTreeFork; QrTreeFork::LEVELS]>::try_from(chunk).expect("a full descent");
        let (pcd, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrBucketTreeDescend,
                witness::qr_bucket_tree_descend((*node.data(), ()), path),
                node,
                Proof::trivial().carry::<()>(()),
            )
            .expect("QrBucketTreeDescend");
        node = pcd;
    }
    node
}

/// Replay one leaf of `tree` under a witnessed preimage, whatever the tree
/// actually holds there.
fn open_leaf(
    rng: &mut StdRng,
    tree: Pcd<qr::QrBucketTree>,
    leaf: &QrBucketLeaf,
    profile: QrProfile,
    contents: TachygramSetCommit,
) -> ragu_core::Result<Pcd<qr::QrBucket>> {
    let node = descend_to_leaf(rng, tree, leaf);
    PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketTreeOpen,
            witness::qr_bucket_tree_open((*node.data(), ()), profile, contents),
            node,
            Proof::trivial().carry::<()>(()),
        )
        .map(|(bucket, ())| bucket)
}

#[test]
fn qr_bucket_tree_replays_the_bucket_each_leaf_holds() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, terminal) = small_epoch(rng);
    let discriminant = qr_discriminant(rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
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

    let tree = build_qr_bucket_tree(rng, sealed);
    let (epoch, anchor_prev, anchor_last, root_discriminant, _) = *tree.pcd.data();
    assert_eq!(
        (epoch, anchor_prev, anchor_last, root_discriminant),
        (
            EpochIndex::new(0),
            Anchor::default(),
            terminal,
            discriminant
        ),
        "the root carries the network every leaf belongs to"
    );

    for (leaf, bucket) in tree.leaves.iter().zip(&expected) {
        let replayed = open_qr_bucket_tree(rng, tree.pcd.clone(), leaf);
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

    let tree = build_qr_bucket_tree(rng, vec![bucket]);
    let leaf = tree.leaves.first().expect("one leaf");
    let replayed = open_qr_bucket_tree(rng, tree.pcd.clone(), leaf);
    assert_eq!(*replayed.pcd.data(), sealed);

    let bound = qr_epoch_unspent(rng, &user, &note, &replayed);
    assert_eq!(
        *bound.data(),
        *direct.data(),
        "the segment is the one the sealed bucket starts"
    );
    let (cm, _, (epoch_first, _), (epoch_last, _), _) = *bound.data();
    assert_eq!(cm, note.commitment());
    assert_eq!((epoch_first, epoch_last), (epoch0, epoch1));
}

#[test]
fn qr_bucket_tree_fuse_rejects_a_bucket_of_another_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch1.last_block().0, |_| random_block(rng, 1, 1));
    let terminal0 = pool.block(epoch0.last_block()).anchor();
    let terminal1 = pool.block(epoch1.last_block()).anchor();
    let value = Fp::random(&mut *rng);

    let first = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), terminal0),
        EPOCH_MEMBERS,
        0,
        value,
        Anchor::from(Fp::ZERO),
    );
    let second = qr_bucket_for(
        rng,
        &pool,
        (
            terminal0.next_epoch(epoch1).expect("epoch one is nonzero"),
            terminal1,
        ),
        EPOCH_MEMBERS,
        0,
        value,
        terminal0,
    );

    let (left, right) = (tree_of(rng, first), tree_of(rng, second));
    assert_eq!(
        invalid_witness(fuse_trees(rng, left, right).err().unwrap()),
        "QrBucketTreeFuse: inputs cover different epochs"
    );
}

/// Two routing networks over one epoch are two trees. Their buckets share
/// every field but the base they classified at, which the fuse separates.
#[test]
fn qr_bucket_tree_fuse_rejects_a_bucket_of_another_network() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, terminal) = small_epoch(rng);
    let value = Fp::random(&mut *rng);
    let span = (Anchor::default(), terminal);

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
    assert_eq!(
        invalid_witness(fuse_trees(rng, left, right).err().unwrap()),
        "QrBucketTreeFuse: inputs derive from different discriminants"
    );
}

/// Chaining is not fusing. A bucket over a prefix of the epoch shares its
/// opening anchor and nothing else, and the tree refuses to span both.
#[test]
fn qr_bucket_tree_fuse_rejects_an_extent_that_closes_elsewhere() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, terminal) = small_epoch(rng);
    let discriminant = qr_discriminant(rng);
    let value = Fp::random(&mut *rng);

    let whole = qr_bucket_at(
        rng,
        &pool,
        (Anchor::default(), terminal),
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
    assert_eq!(
        invalid_witness(fuse_trees(rng, left, right).err().unwrap()),
        "QrBucketTreeFuse: inputs close at different anchors"
    );
}

#[test]
fn qr_bucket_tree_fuse_rejects_an_extent_that_opens_elsewhere() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch1.last_block().0, |_| random_block(rng, 1, 1));
    let terminal0 = pool.block(epoch0.last_block()).anchor();
    let terminal1 = pool.block(epoch1.last_block()).anchor();
    let discriminant = qr_discriminant(rng);
    let value = Fp::random(&mut *rng);

    let genuine = qr_bucket_at(
        rng,
        &pool,
        (
            terminal0.next_epoch(epoch1).expect("epoch one is nonzero"),
            terminal1,
        ),
        discriminant,
        EPOCH_MEMBERS,
        0,
        value,
        terminal0,
    );

    // An invented preceding anchor gives an epoch-one opening the chain never
    // produced; the seal takes it, since the opening matches its witness.
    let fake_anchor_prev_prev = Anchor::from(Fp::ONE);
    let fake_prev = fake_anchor_prev_prev
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
        fake_anchor_prev_prev,
    );

    let (left, right) = (tree_of(rng, genuine), tree_of(rng, elsewhere));
    assert_eq!(
        invalid_witness(fuse_trees(rng, left, right).err().unwrap()),
        "QrBucketTreeFuse: inputs open at different anchors"
    );
}

/// The leaf binds the profile alongside the contents, so a real bucket cannot
/// be replayed under another profile. That is the forgery the binding exists
/// for: under the tested value's own profile the class fold would pass and the
/// opening would find nothing.
#[test]
fn qr_bucket_tree_open_rejects_a_forged_leaf() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, terminal) = small_epoch(rng);
    let discriminant = qr_discriminant(rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        24,
        2,
    );
    let sealed = routed
        .into_iter()
        .map(|intake| seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO)))
        .collect::<Vec<_>>();
    let other_contents = sealed.get(1).expect("a second bucket").pcd.data().5;

    let tree = build_qr_bucket_tree(rng, sealed);
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
            "QrBucketTreeOpen: witnessed bucket is not the tree's leaf"
        );
    }

    open_leaf(rng, tree.pcd.clone(), leaf, leaf.profile, leaf.contents)
        .expect("the genuine preimage opens");
}

#[test]
fn qr_bucket_tree_descend_rejects_children_that_miss_the_node() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, terminal) = small_epoch(rng);
    let discriminant = qr_discriminant(rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        24,
        2,
    );
    let sealed = routed
        .into_iter()
        .map(|intake| seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO)))
        .collect::<Vec<_>>();
    let tree = build_qr_bucket_tree(rng, sealed);
    let leaf = tree.leaves.first().expect("one leaf");

    let mut path = <[QrTreeFork; QrTreeFork::LEVELS]>::try_from(
        leaf.path.get(..QrTreeFork::LEVELS).expect("a full descent"),
    )
    .expect("a full descent");
    let QrTreeFork(side, left_child, right_child) = path[0];
    path[0] = QrTreeFork(
        side,
        left_child,
        QrTreeRoot(Fp::from(right_child) + Fp::ONE),
    );

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketTreeDescend,
            witness::qr_bucket_tree_descend((*tree.pcd.data(), ()), path),
            tree.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrBucketTreeDescend: children do not hash to the node"
    );
}

/// A node is not a leaf. Stopping a descent one level short leaves an interior
/// node on the header, and the leaf domain refuses to match it.
#[test]
fn qr_bucket_tree_open_rejects_a_node_presented_as_a_leaf() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, terminal) = small_epoch(rng);
    let discriminant = qr_discriminant(rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant,
        24,
        2,
    );
    let sealed = routed
        .into_iter()
        .map(|intake| seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO)))
        .collect::<Vec<_>>();
    let tree = build_qr_bucket_tree(rng, sealed);
    let leaf = tree.leaves.first().expect("one leaf");

    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketTreeOpen,
            witness::qr_bucket_tree_open((*tree.pcd.data(), ()), leaf.profile, leaf.contents),
            tree.pcd,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrBucketTreeOpen: witnessed bucket is not the tree's leaf"
    );
}
