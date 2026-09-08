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
    Anchor, BlockHeight, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetPoly,
    constants::EPOCH_SIZE,
    note::Note,
    nullifier::Nullifier,
    stamp::proof::{
        PROOF_SYSTEM,
        pool::{ArbitraryUnspent, EndEpochUnspentSeed, Unspent, UnspentFuse},
        qr, spend, spendable, summary,
    },
    witness,
};

use crate::fixtures::{
    PoolSim, QrBucketEntry, QrIntakeEntry, WalletSim, build_qr_branch, build_qr_partition,
    build_summary_pcd, qr_profile_of, random_block, seal_qr_intake, seed_qr_stamp_intake,
    shared_sk, split_qr_intake,
};

/// The witness of [`qr::QrUnspentInit`].
type UnspentInitWitness = <qr::QrUnspentInit as Step>::Witness<'static>;

/// Run [`qr::QrUnspentInit`] over `bucket`.
fn fuse_unspent_init(
    rng: &mut StdRng,
    bucket: Pcd<qr::QrBucket>,
    witness: UnspentInitWitness,
) -> ragu::Result<Pcd<ArbitraryUnspent>> {
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
fn invalid_witness(err: ragu::Error) -> String {
    let ragu::Error::InvalidWitness(inner) = err else {
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

/// The sealed bucket holding `value` at `depth` levels under a discriminant
/// from fresh random entropy, over the anchor span `(start, terminal)`,
/// sealed on `prev_last`.
fn qr_bucket_for(
    rng: &mut StdRng,
    pool: &PoolSim,
    (start, terminal): (Anchor, Anchor),
    capacity: usize,
    depth: u32,
    value: Fp,
    prev_last: Anchor,
) -> QrBucketEntry {
    let discriminant_entropy = Fp::random(&mut *rng);
    qr_bucket_under(
        rng,
        pool,
        (start, terminal),
        capacity,
        depth,
        value,
        prev_last,
        discriminant_entropy,
    )
}

/// [`qr_bucket_for`] at chosen discriminant entropy.
#[expect(clippy::too_many_arguments, reason = "test fixture")]
fn qr_bucket_under(
    rng: &mut StdRng,
    pool: &PoolSim,
    (start, terminal): (Anchor, Anchor),
    capacity: usize,
    depth: u32,
    value: Fp,
    prev_last: Anchor,
    discriminant_entropy: Fp,
) -> QrBucketEntry {
    let profile = qr_profile_of(value, QrDiscriminant::derive(discriminant_entropy), depth);
    let mut branch = build_qr_branch(
        rng,
        pool,
        (start, terminal),
        discriminant_entropy,
        capacity,
        value,
        depth,
    );
    assert_eq!(branch.len(), 1, "the value's profile fits one intake");
    let intake = branch.pop().expect("one intake");
    assert_eq!(intake.pcd.data().4, profile);
    seal_qr_intake(rng, intake, prev_last)
}

/// The note's QR segment across a bucket's epoch, bound to the note.
fn qr_epoch_unspent(
    rng: &mut StdRng,
    user: &WalletSim,
    note: &Note,
    bucket: &QrBucketEntry,
) -> Pcd<Unspent> {
    let (epoch, ..) = *bucket.pcd.data();
    let witness = witness::qr_unspent_init(
        (*bucket.pcd.data(), ()),
        user.nf_at(note, epoch).into(),
        &bucket.members,
    );
    let arbitrary = fuse_unspent_init(rng, bucket.pcd.clone(), witness).expect("QrUnspentInit");
    user.unspent_bind(rng, arbitrary, note)
}

#[test]
fn qr_summary_intake_init_starts_a_root_from_a_summary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
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
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
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

    let discriminant_entropy = Fp::random(&mut *rng);
    let stamp_root = seed_qr_stamp_intake(rng, &pool, entry, discriminant_entropy);
    assert_eq!(
        *stamp_root.pcd.data(),
        (
            EpochIndex(0),
            anchor_prev,
            anchor_last,
            QrDiscriminant::derive(discriminant_entropy),
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
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
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
    let discriminant_entropy = Fp::random(&mut *rng);
    let err = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(
                ((), ()),
                anchor_prev,
                EpochIndex(3),
                discriminant_entropy,
                &[],
            ),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(inner.to_string(), "invalid anchor step");
}

#[test]
fn qr_intake_split_partitions_the_contents_by_class() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
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
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
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
            residue
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit(),
            non_residue
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
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant_entropy = Fp::random(&mut *rng);
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
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let (contents, residue, _non_residue) = witness::qr_intake_split((*root.data(), ()), &members);
    let err = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            (contents, residue.clone(), residue),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
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
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
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
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
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
                residue.iter().copied().collect(),
                non_residue.iter().copied().collect(),
            ),
            root,
            Proof::trivial().carry::<()>(()),
        )
        .err()
        .unwrap();
    let ragu::Error::InvalidWitness(inner) = err else {
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
        let epoch = EpochIndex(3);
        let start = Anchor::from(Fp::random(&mut *rng));
        let discriminant_entropy = Fp::random(&mut *rng);
        let discriminant = QrDiscriminant::derive(discriminant_entropy);
        // Choose x from the derived R_1 and the selected split depth.
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
                witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
                summary,
                Proof::trivial().carry::<()>(()),
            )
            .expect("QrSummaryIntakeInit");

        // Reach the selected depth through honest splits and descents, keeping
        // the branch containing x rather than fabricating a deeper profile.
        let mut intake = QrIntakeEntry { pcd: root, members };
        for level in 0..depth {
            let side = qr::classify(value, discriminant.at(level)).0;
            let (residue_side, non_residue_side) = split_qr_intake(rng, intake);
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
                    residue.iter().copied().collect(),
                    non_residue.iter().copied().collect(),
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
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
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
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
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
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant_entropy = Fp::random(&mut *rng);
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
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
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
    let ragu::Error::InvalidWitness(inner) = err else {
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
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant_entropy = Fp::random(&mut *rng);
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
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
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

#[test]
fn qr_side_descend_rejects_a_child_short_of_a_member() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
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
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
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
                short_residue.iter().copied().collect(),
                padded_non_residue.iter().copied().collect(),
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
    let epoch = EpochIndex(3);
    let start = Anchor::from(Fp::random(&mut *rng));
    let discriminant_entropy = Fp::random(&mut *rng);
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
            witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
            summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");

    let mut intake = QrIntakeEntry {
        pcd: root,
        members: members.to_vec(),
    };
    for _ in 0..QrProfile::MAX_DEPTH {
        let (residue, _non_residue) = split_qr_intake(rng, intake);
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
    let ragu::Error::InvalidWitness(inner) = err else {
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
    let epoch = EpochIndex(3);
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
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
            witness::qr_summary_intake_init((*left_summary.data(), ()), discriminant_entropy),
            left_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (right, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*right_summary.data(), ()), discriminant_entropy),
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
    let epoch = EpochIndex(3);
    let discriminant_entropy = Fp::random(&mut *rng);
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
            witness::qr_summary_intake_init((*left_summary.data(), ()), discriminant_entropy),
            left_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (right, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*right_summary.data(), ()), discriminant_entropy),
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
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrIntakeMerge: right input does not continue the left span"
    );
}

#[test]
fn qr_intake_merge_rejects_different_profiles() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
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
            witness::qr_summary_intake_init((*left_summary.data(), ()), discriminant_entropy),
            left_summary,
            Proof::trivial().carry::<()>(()),
        )
        .expect("QrSummaryIntakeInit");
    let (right, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntakeInit,
            witness::qr_summary_intake_init((*right_summary.data(), ()), discriminant_entropy),
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
    let ragu::Error::InvalidWitness(inner) = err else {
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
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
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
        discriminant_entropy,
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
    let discriminant_entropy = Fp::random(&mut *rng);
    let published: Vec<Tachygram> = (0..=3)
        .flat_map(|height| pool.block(BlockHeight(height)).tachygrams())
        .flatten()
        .collect();
    let capacity = 11;

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant_entropy,
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
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant_entropy,
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
        "epoch zero's opening anchor is the general rule at prev_last = 0"
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
    let discriminant_entropy = Fp::random(&mut *rng);
    let start = pool.block(BlockHeight(0)).anchor();

    let routed = build_qr_partition(rng, &pool, (start, terminal), discriminant_entropy, 12, 1);
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
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrBucketSeal: intake does not begin at the epoch boundary"
    );
}

/// The seal does not know the epoch's terminal anchor. That a bucket's span
/// reaches it closes through the lineage that consumes the segment, so a
/// bucket built while the epoch is live seals like any other.
#[test]
fn qr_bucket_seal_accepts_a_span_short_of_the_terminal_anchor() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let discriminant_entropy = Fp::random(&mut *rng);

    // A six-member capacity chunks the epoch into four roots; the first opens at
    // the epoch boundary and stops well short of the terminal.
    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant_entropy,
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
        bucket.pcd.data().2,
        anchor_last,
        "the seal keeps the short span"
    );
}

#[test]
fn qr_unspent_init_accepts_an_absent_nullifier_against_its_bucket() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let terminal = pool.block(pool.height()).anchor();
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
    let epoch = BlockHeight(0).epoch();
    let nf = Nullifier::from(Fp::random(&mut *rng));

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant_entropy,
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

    let witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
    let unspent = fuse_unspent_init(rng, bucket.pcd, witness).expect("QrUnspentInit");

    let (anchor_prev, first, elapsed, last, anchor_last) = *unspent.data();
    assert_eq!(
        anchor_prev,
        Anchor::default(),
        "the segment opens where the partition's span does"
    );
    assert_eq!(
        anchor_last, terminal,
        "and closes on the epoch's terminal anchor, inside the epoch"
    );
    assert_eq!(first, (epoch, nf));
    assert_eq!(
        last,
        (epoch, nf),
        "one epoch, so both boundary caches agree"
    );
    assert_eq!(elapsed, NfSeqPoly::new(epoch, &[nf]).commit());
}

/// Each QR segment stops on its own epoch's terminal anchor, so two
/// consecutive epochs' segments do not abut. `EndEpochUnspentSeed` supplies the
/// boundary link between them, and `UnspentFuse` composes the three.
#[test]
fn qr_unspent_segments_of_consecutive_epochs_fuse_over_a_boundary_link() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex(0);
    let epoch1 = epoch0.next();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    // Fill epoch zero and open epoch one, one stamp per block.
    pool.advance(epoch1.first_block().0 + 1, |_| random_block(rng, 1, 1));
    let [nf0, nf1] = array::from_fn(|_| Nullifier::from(Fp::random(&mut *rng)));

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

    let mut segment = |bucket: QrBucketEntry, nf: Nullifier| {
        let witness =
            witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
        fuse_unspent_init(rng, bucket.pcd, witness).expect("QrUnspentInit")
    };
    let left = segment(bucket0, nf0);
    let right = segment(bucket1, nf1);
    assert_eq!(
        left.data().4,
        terminal0,
        "epoch zero's segment stops inside epoch zero"
    );
    assert_ne!(
        left.data().4,
        right.data().0,
        "so it does not reach epoch one's opening anchor"
    );

    let (crossing, ()) = PROOF_SYSTEM
        .seed(
            rng,
            EndEpochUnspentSeed,
            witness::end_epoch_unspent_seed(((), ()), terminal0, epoch0, nf0, nf1),
        )
        .expect("EndEpochUnspentSeed");
    let (lifted, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            UnspentFuse,
            witness::unspent_fuse((*left.data(), *crossing.data()), &[nf0], &[nf0, nf1]),
            left,
            crossing,
        )
        .expect("UnspentFuse over the boundary link");
    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            UnspentFuse,
            witness::unspent_fuse((*lifted.data(), *right.data()), &[nf0, nf1], &[nf1]),
            lifted,
            right,
        )
        .expect("UnspentFuse over epoch one");

    let (anchor_prev, first, elapsed, last, anchor_last) = *fused.data();
    assert_eq!(anchor_prev, Anchor::default());
    assert_eq!(first, (epoch0, nf0));
    assert_eq!(last, (epoch1, nf1));
    assert_eq!(anchor_last, terminal1);
    assert_eq!(
        elapsed,
        NfSeqPoly::new(epoch0, &[nf0, nf1]).commit(),
        "the junction epoch's member is shared, not repeated"
    );
}

/// A note created in epoch zero bootstraps from the bucket holding its `cm`
/// over its own QR segment, rests at epoch zero's terminal anchor, lifts over
/// the boundary and epoch one on ordinary segments, and binds a spend in epoch
/// two.
#[test]
fn qr_spendable_init_starts_a_spendable_that_reaches_spend_bind() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch0 = EpochIndex(0);
    let epoch1 = epoch0.next();
    let epoch2 = epoch1.next();
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
            (epoch0, user.nf_at(&note, epoch0)),
            anchor_last
        ),
        "the spendable rests on the creation epoch's terminal anchor with that epoch's nullifier"
    );

    let lifted = user.lift_to_epoch(rng, &pool, &note, spendable, epoch2);
    let derived = user.derivation_pcd(rng, note, epoch2, EpochIndex(epoch2.0 + 2));
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
    let (bind_cm, present_nf, nf_next, _) = *bind.data();
    assert_eq!(bind_cm, note.commitment());
    assert_eq!(
        (present_nf, nf_next),
        (
            user.nf_at(&note, epoch2),
            user.nf_at(&note, EpochIndex(epoch2.0 + 1))
        )
    );
}

#[test]
fn qr_spendable_init_rejects_an_absent_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch0 = EpochIndex(0);
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
    let ragu::Error::InvalidWitness(inner) = err else {
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
    let epoch0 = EpochIndex(0);
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
    let ragu::Error::InvalidWitness(inner) = err else {
        panic!("expected InvalidWitness, got {err:?}");
    };
    assert_eq!(
        inner.to_string(),
        "QrSpendableInit: segment does not close where the bucket does"
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
    let discriminant_entropy = Fp::random(&mut *rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant_entropy,
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

    let witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
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
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
    let nf = Nullifier::from(Fp::random(&mut *rng));

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant_entropy,
        24,
        2,
    );
    let profile = qr_profile_of(Fp::from(nf), discriminant, 2);
    let foreign = routed
        .into_iter()
        .find(|intake| intake.pcd.data().4 != profile)
        .expect("three intakes carry another profile");
    let bucket = seal_qr_intake(rng, foreign, Anchor::from(Fp::ZERO));

    let witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
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
    let witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
    fuse_unspent_init(rng, bucket.pcd.clone(), witness.clone()).expect("the honest witness passes");
    (nf, bucket, witness)
}

#[test]
fn qr_unspent_init_rejects_a_root_off_its_class() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_nf, bucket, mut witness) = honest_unspent_init(rng);

    let (_, ref mut roots, ..) = witness;
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
    let (_, ref mut roots, ..) = witness;
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
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
    let position = 1;
    let value = -discriminant.at(position);
    assert_ne!(value, Fp::ZERO);
    let nf = Nullifier::from(value);

    let bucket = qr_bucket_under(
        rng,
        &pool,
        (Anchor::default(), terminal),
        24,
        2,
        value,
        Anchor::from(Fp::ZERO),
        discriminant_entropy,
    );
    assert!(
        !bucket
            .members
            .iter()
            .any(|&member| Fp::from(member) == value),
        "the fixed point is absent from the epoch"
    );
    let mut witness =
        witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
    let (_, honest_roots, ..) = witness;
    assert_eq!(
        honest_roots[usize::try_from(position).unwrap()],
        QrClassRoot(true, Fp::ZERO)
    );
    fuse_unspent_init(rng, bucket.pcd.clone(), witness.clone())
        .expect("the fixed point passes on the residue side");

    let (_, ref mut roots, ..) = witness;
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

    let (_, _, ref mut depth_mask, ..) = witness;
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

    let (_, _, ref mut depth_mask, ..) = witness;
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

#[test]
fn qr_unspent_init_rejects_a_bucket_past_the_maximum_depth() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_nf, bucket, mut witness) = honest_unspent_init(rng);

    let forged = recarry_bucket(&bucket, |&mut (_, _, _, _, ref mut profile, ..)| {
        profile.depth = u32::BITS + 1;
    });
    let (_, _, ref mut depth_mask, ..) = witness;
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
    let (_, _, ref mut saturated_mask, ..) = witness;
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
    let (_, _, ref mut depth_mask, ..) = shallow;
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
        &bucket.members,
    );
    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(invalid_witness(err), "QrUnspentInit: tested value is zero");
}

#[test]
fn qr_unspent_init_rejects_a_sequence_naming_another_value() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (nf, bucket, mut witness) = honest_unspent_init(rng);
    let (epoch, ..) = *bucket.pcd.data();

    let other = Nullifier::from(Fp::random(&mut *rng));
    assert_ne!(other, nf);
    let (_, _, _, ref mut sequence, _) = witness;
    *sequence = NfSeqPoly::new(epoch, &[other]);

    let err = fuse_unspent_init(rng, bucket.pcd, witness).err().unwrap();
    assert_eq!(
        invalid_witness(err),
        "QrUnspentInit: sequence does not match the tested value"
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
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
    let shallow_value = Fp::random(&mut *rng);
    let shallow_side = qr::classify(shallow_value, discriminant.at(0)).0;
    let deep_value = iter::repeat_with(|| Fp::random(&mut *rng))
        .find(|&value| qr::classify(value, discriminant.at(0)).0 != shallow_side)
        .expect("a value on the other side");

    let root = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), terminal),
        discriminant_entropy,
        24,
        0,
    )
    .pop()
    .expect("one root");
    let (residue, non_residue) = split_qr_intake(rng, root);
    let (shallow, mut deep) = if shallow_side {
        (residue, non_residue)
    } else {
        (non_residue, residue)
    };
    for level in 1..3 {
        let (deep_residue, deep_non_residue) = split_qr_intake(rng, deep);
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
        let witness =
            witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
        let unspent = fuse_unspent_init(rng, bucket.pcd, witness).expect("QrUnspentInit");
        assert_eq!(
            *unspent.data(),
            (
                Anchor::default(),
                (epoch, nf),
                NfSeqPoly::new(epoch, &[nf]).commit(),
                (epoch, nf),
                terminal
            ),
            "the segment is the bucket's span at depth {depth}"
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

        let witness =
            witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
        let unspent = fuse_unspent_init(rng, bucket.pcd, witness).expect("QrUnspentInit");
        assert_eq!(
            *unspent.data(),
            (
                Anchor::default(),
                (epoch, nf),
                NfSeqPoly::new(epoch, &[nf]).commit(),
                (epoch, nf),
                terminal
            ),
            "the segment is the bucket's span at depth {depth}"
        );
    }
}

#[test]
fn qr_intake_merge_rejects_different_discriminants() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
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
        let discriminant_entropy = Fp::random(&mut *rng);
        let (root, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSummaryIntakeInit,
                witness::qr_summary_intake_init((*summary.data(), ()), discriminant_entropy),
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

/// Routing consecutive values: each lands in the bucket of its own profile,
/// and the buckets together hold every value. A correctness check on
/// structured input, not a balance measurement.
#[test]
fn qr_partition_routes_consecutive_values_by_profile() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex(3);
    let anchor_prev = Anchor::from(Fp::random(&mut *rng));
    let discriminant_entropy = Fp::random(&mut *rng);
    let discriminant = QrDiscriminant::derive(discriminant_entropy);
    let base = Fp::random(&mut *rng);
    let members: Vec<Tachygram> = (0..12u64)
        .map(|offset| Tachygram::from(base + Fp::from(offset)))
        .collect();
    let depth = 3;

    let (pcd, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(
                ((), ()),
                anchor_prev,
                epoch,
                discriminant_entropy,
                &members,
            ),
        )
        .expect("QrStampIntakeSeed");
    let mut layer = vec![QrIntakeEntry {
        pcd,
        members: members.clone(),
    }];
    for _ in 0..depth {
        let mut next = Vec::with_capacity(layer.len() * 2);
        for intake in layer {
            let (residue, non_residue) = split_qr_intake(rng, intake);
            next.push(residue);
            next.push(non_residue);
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
