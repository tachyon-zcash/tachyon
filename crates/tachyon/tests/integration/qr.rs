extern crate alloc;

use alloc::{string::ToString as _, vec, vec::Vec};
use core::{array, iter};

use ragu::{Pcd, Proof};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetPoly,
    constants::{EPOCH_MAX, EPOCH_SIZE},
    note::Note,
    nullifier::Nullifier,
    pasta::Fp,
    stamp::proof::{
        PROOF_SYSTEM,
        pool::{NoteUnspent, UnspentFuse, UnspentLift},
        qr, spend, spendable, summary,
    },
    value, witness,
};

use crate::fixtures::{
    PoolSim, QrBucketEntry, QrIntakeEntry, WalletSim, build_qr_branch, build_qr_partition,
    build_summary_pcd, build_unspent_pcd_over_epochs, epoch_bucket, qr_bucket_segment,
    qr_profile_of, random_block, random_block_with, seal_qr_intake, seed_qr_empty_intake,
    seed_qr_stamp_intake, shared_sk, split_qr_intake, unpinned_challenge,
};

pub(crate) fn small_epoch(rng: &mut StdRng) -> (PoolSim, Anchor) {
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let final_anchor = pool.block(pool.height()).anchor();
    (pool, final_anchor)
}

pub(crate) const EPOCH_MEMBERS: usize = EPOCH_SIZE as usize;

pub(crate) fn qr_bucket_for(
    rng: &mut StdRng,
    pool: &PoolSim,
    span: (Anchor, Anchor),
    capacity: usize,
    depth: u32,
    value: Fp,
    anchor_final_prev: Anchor,
) -> QrBucketEntry {
    let discriminant = QrDiscriminant::random(rng);
    qr_bucket_at(
        rng,
        pool,
        span,
        discriminant,
        capacity,
        depth,
        value,
        anchor_final_prev,
    )
}

#[expect(clippy::too_many_arguments, reason = "a fixture assembling one bucket")]
pub(crate) fn qr_bucket_at(
    rng: &mut StdRng,
    pool: &PoolSim,
    (start, final_anchor): (Anchor, Anchor),
    discriminant: QrDiscriminant,
    capacity: usize,
    depth: u32,
    value: Fp,
    anchor_final_prev: Anchor,
) -> QrBucketEntry {
    let profile = qr_profile_of(value, discriminant, depth);
    let mut branch = build_qr_branch(
        rng,
        pool,
        (start, final_anchor),
        discriminant,
        capacity,
        value,
        depth,
    );
    assert_eq!(branch.len(), 1);
    let intake = branch.pop().unwrap();
    assert_eq!(intake.pcd.data().4, profile);
    seal_qr_intake(rng, intake, anchor_final_prev)
}

pub(crate) fn qr_epoch_unspent(
    rng: &mut StdRng,
    user: &WalletSim,
    note: &Note,
    bucket: &QrBucketEntry,
) -> Pcd<NoteUnspent> {
    let (epoch, ..) = *bucket.pcd.data();
    let witness = witness::qr_unspent_init(
        (*bucket.pcd.data(), ()),
        user.pak
            .nk
            .derive_note_private(note.psi)
            .derive_nullifier(epoch)
            .into(),
        &bucket.members,
    );
    let arbitrary = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentInit,
            witness,
            bucket.pcd.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap()
        .0;
    user.unspent_bind(rng, arbitrary, note)
}

#[test]
fn qr_summary_intake_starts_a_root_from_a_summary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let members: [Tachygram; 6] = array::from_fn(|_| Tachygram::random(rng));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .unwrap();
    let (_, _, anchor_end, acc_commit) = *summary.data();
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), discriminant),
            summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

    assert_eq!(
        *root.data(),
        (
            epoch,
            start,
            anchor_end,
            discriminant,
            QrProfile::ROOT,
            acc_commit
        )
    );
}

#[test]
fn qr_stamp_intake_seed_roots_an_intake_on_one_stamp() {
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::genesis_with(random_block(rng, 3, 1));
    let block = pool.block(BlockHeight(0));
    let entry = block.stamps.first().unwrap();
    let (anchor_prev, members, commit, anchor_end) = entry.clone();
    let (summary, _) = build_summary_pcd(rng, &pool, (anchor_prev, anchor_end));

    let discriminant = QrDiscriminant::random(rng);
    let stamp_root = seed_qr_stamp_intake(rng, &pool, entry, discriminant);
    assert_eq!(
        *stamp_root.pcd.data(),
        (
            EpochIndex::new(0),
            anchor_prev,
            anchor_end,
            discriminant,
            QrProfile::ROOT,
            commit
        )
    );
    assert_eq!(stamp_root.members, members);

    let (summary_root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), discriminant),
            summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    assert_eq!(*stamp_root.pcd.data(), *summary_root.data());
}

#[test]
fn qr_stamp_intake_seed_rejects_an_empty_stamp() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor_prev = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.seed(
        rng,
        qr::QrStampIntakeSeed,
        witness::qr_stamp_intake_seed(((), ()), anchor_prev, EpochIndex::new(3), discriminant, &[]),
    ) {
        assert_eq!(err.to_string(), "invalid anchor step");
    } else {
        panic!();
    }
}

#[test]
fn qr_intake_split_partitions_the_contents_by_class() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::random(rng));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .unwrap();
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), discriminant),
            summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

    let (residue, non_residue): (Vec<Tachygram>, Vec<Tachygram>) = members
        .iter()
        .copied()
        .partition(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0);
    assert!(!residue.is_empty() && !non_residue.is_empty());

    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

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
        )
    );
}

#[test]
fn qr_intake_split_rejects_a_forged_partition() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let members: [Tachygram; 8] = array::from_fn(|_| Tachygram::random(rng));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .unwrap();
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), discriminant),
            summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

    let (contents, non_residue, _residue) = witness::qr_intake_split((*root.data(), ()), &members);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        qr::QrIntakeSplit,
        (contents, non_residue.clone(), non_residue),
        root,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "QrIntakeSplit: the sides do not partition the contents"
        );
    } else {
        panic!();
    }
}

#[test]
fn qr_intake_split_checks_the_exceptional_value_at_its_depth() {
    let rng = &mut StdRng::seed_from_u64(0);
    for depth in [0, 1, 31] {
        let epoch = EpochIndex::new(3);
        let start = Anchor::random(rng);
        let discriminant = QrDiscriminant::random(rng);
        let value = -Fp::from(discriminant) - Fp::from(u64::from(depth));
        let exceptional = Tachygram::from(value);
        let members: Vec<Tachygram> = iter::repeat_with(|| Tachygram::random(rng))
            .take(8)
            .chain([exceptional])
            .collect();

        let (summary, ()) = PROOF_SYSTEM
            .seed(
                rng,
                summary::SummarySeed,
                witness::summary_seed(((), ()), start, epoch, &members),
            )
            .unwrap();
        let (root, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSummaryIntake,
                witness::qr_summary_intake((*summary.data(), ()), discriminant),
                summary,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();

        let mut intake = QrIntakeEntry { pcd: root, members };
        for level in 0..depth {
            let side = qr::classify(value, discriminant.at(level)).0;
            let (non_residue_side, residue_side) = split_qr_intake(rng, intake);
            intake = if side { residue_side } else { non_residue_side };
        }
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrIntakeSplit,
                witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members),
                intake.pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();

        let (residue, non_residue): (Vec<Tachygram>, Vec<Tachygram>) =
            intake.members.iter().copied().partition(|member| {
                *member != exceptional && qr::classify(Fp::from(*member), discriminant.at(depth)).0
            });
        let (contents, ..) = witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members);
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            qr::QrIntakeSplit,
            (
                contents,
                non_residue.iter().copied().collect(),
                residue.iter().copied().collect(),
            ),
            intake.pcd,
            Proof::bootstrap().carry::<()>(()),
        ) {
            assert_eq!(
                err.to_string(),
                "QrIntakeSplit: exceptional value claimed the non-residue class"
            );
        } else {
            panic!();
        }
    }
}

#[test]
fn qr_side_descend_carries_each_side_one_level_down() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::random(rng));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .unwrap();
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), discriminant),
            summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (_, _, anchor_end, ..) = *root.data();
    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

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
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        assert_eq!(
            *child.data(),
            (
                epoch,
                start,
                anchor_end,
                discriminant,
                QrProfile::ROOT.descend(side),
                side_members
                    .iter()
                    .copied()
                    .collect::<TachygramSetPoly>()
                    .commit()
            )
        );
    }
}

#[test]
fn qr_side_descend_rejects_foreign_witness_parts() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::random(rng));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .unwrap();
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), discriminant),
            summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*root.data(), ()), &members),
            root,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

    let (_, residue_sibling, residue_interpolant, residue_quotient) =
        witness::qr_side_descend((*split.data(), ()), &members, true);
    let (_, non_residue_sibling, non_residue_interpolant, non_residue_quotient) =
        witness::qr_side_descend((*split.data(), ()), &members, false);
    for (descend_witness, expected) in [
        (
            (
                true,
                non_residue_sibling.clone(),
                residue_interpolant.clone(),
                residue_quotient.clone(),
            ),
            "QrSideDescend: sibling does not match the header",
        ),
        (
            (
                true,
                residue_sibling.clone(),
                non_residue_interpolant.clone(),
                residue_quotient.clone(),
            ),
            "QrSideDescend: the sibling fails its class decomposition",
        ),
        (
            (
                false,
                non_residue_sibling.clone(),
                residue_interpolant.clone(),
                non_residue_quotient.clone(),
            ),
            "QrSideDescend: the sibling fails its class decomposition",
        ),
        (
            (
                true,
                residue_sibling,
                residue_interpolant,
                non_residue_quotient,
            ),
            "QrSideDescend: the sibling fails its class decomposition",
        ),
        (
            (
                false,
                non_residue_sibling,
                non_residue_interpolant,
                residue_quotient,
            ),
            "QrSideDescend: the sibling fails its class decomposition",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            qr::QrSideDescend,
            descend_witness,
            split.clone(),
            Proof::bootstrap().carry::<()>(()),
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }
}

#[test]
fn qr_side_descend_rejects_a_child_short_of_a_member() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::random(rng));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .unwrap();
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), discriminant),
            summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

    let (mut short_residue, mut padded_non_residue): (Vec<Tachygram>, Vec<Tachygram>) = members
        .iter()
        .copied()
        .partition(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0);
    let smuggled = short_residue.pop().unwrap();
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
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

    let (_, _, interpolant, quotient) =
        witness::qr_side_descend((*sides.data(), ()), &members, true);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        qr::QrSideDescend,
        (
            true,
            padded_non_residue.iter().copied().collect(),
            interpolant,
            quotient,
        ),
        sides.clone(),
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "QrSideDescend: the sibling fails its class decomposition"
        );
    } else {
        panic!();
    }

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
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (.., child_profile, child_contents) = *child.data();
    assert_eq!(child_profile, QrProfile::ROOT.descend(false));
    assert_eq!(
        child_contents,
        padded_non_residue
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit()
    );
}

#[test]
fn qr_side_descend_rejects_a_discriminant_solved_after_the_challenge() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let members: [Tachygram; 12] = array::from_fn(|_| Tachygram::random(rng));
    let (misfiled, non_residue) = members.split_at(6);

    let (honest_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .unwrap();
    let honest_discriminant = QrDiscriminant::random(rng);
    let (honest_root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*honest_summary.data(), ()), honest_discriminant),
            honest_summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (honest_split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*honest_root.data(), ()), &members),
            honest_root,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (_, _, interpolant, quotient) =
        witness::qr_side_descend((*honest_split.data(), ()), &members, false);

    let sibling = misfiled.iter().copied().collect::<TachygramSetPoly>();
    let z = unpinned_challenge(&[
        sibling.commit().into(),
        interpolant.commit().into(),
        quotient.commit().into(),
    ]);
    let solved = QrDiscriminant::from(
        interpolant.eval(z).square() - (sibling.eval(z) * quotient.eval(z)) - z,
    );
    assert!(
        misfiled
            .iter()
            .any(|&member| !qr::classify(Fp::from(member), solved.at(0)).0)
    );

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .unwrap();
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), solved),
            summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (contents, ..) = witness::qr_intake_split((*root.data(), ()), &members);
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            (
                contents,
                non_residue.iter().copied().collect(),
                sibling.clone(),
            ),
            root,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        qr::QrSideDescend,
        (false, sibling, interpolant, quotient),
        sides,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "QrSideDescend: the sibling fails its class decomposition"
        );
    } else {
        panic!();
    }
}

#[test]
fn qr_side_descend_refuses_a_full_register() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let members: [Tachygram; 2] = array::from_fn(|_| Tachygram::random(rng));

    let (summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &members),
        )
        .unwrap();
    let (root, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*summary.data(), ()), discriminant),
            summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

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
        }
    );

    let split_witness = witness::qr_intake_split((*intake.pcd.data(), ()), &intake.members);
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            intake.pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let descend_witness = witness::qr_side_descend((*sides.data(), ()), &intake.members, true);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        qr::QrSideDescend,
        descend_witness,
        sides,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "QrSideDescend: profile has no bit left for another side"
        );
    } else {
        panic!();
    }
}

#[test]
fn qr_intake_merge_joins_two_spans() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let discriminant = QrDiscriminant::random(rng);
    let start = Anchor::random(rng);
    let left_members: [Tachygram; 5] = array::from_fn(|_| Tachygram::random(rng));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::random(rng));

    let (left_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), start, epoch, &left_members),
        )
        .unwrap();
    let (_, _, junction, _) = *left_summary.data();
    let (right_summary, ()) = PROOF_SYSTEM
        .seed(
            rng,
            summary::SummarySeed,
            witness::summary_seed(((), ()), junction, epoch, &right_members),
        )
        .unwrap();
    let (_, _, end, _) = *right_summary.data();

    let (left, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*left_summary.data(), ()), discriminant),
            left_summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (right, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSummaryIntake,
            witness::qr_summary_intake((*right_summary.data(), ()), discriminant),
            right_summary,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();

    let witness =
        witness::qr_intake_merge((*left.data(), *right.data()), &left_members, &right_members);
    let (merged, ()) = PROOF_SYSTEM
        .fuse(rng, qr::QrIntakeMerge, witness, left, right)
        .unwrap();

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
        )
    );
}

#[test]
fn qr_intake_merge_rejects_mismatched_inputs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(3);
    let discriminant = QrDiscriminant::random(rng);
    let left_members: [Tachygram; 5] = array::from_fn(|_| Tachygram::random(rng));
    let right_members: [Tachygram; 4] = array::from_fn(|_| Tachygram::random(rng));
    let start = Anchor::random(rng);
    let (left, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &left_members),
        )
        .unwrap();
    let junction = left.data().2;

    for (anchor_prev, right_epoch, right_discriminant, expected) in [
        (
            Anchor::random(rng),
            epoch,
            discriminant,
            "QrIntakeMerge: left.anchor_end must equal right.anchor_prev",
        ),
        (
            junction,
            epoch.next().unwrap(),
            discriminant,
            "QrIntakeMerge: inputs cover different epochs",
        ),
        (
            junction,
            epoch,
            QrDiscriminant::random(rng),
            "QrIntakeMerge: inputs derive from different discriminants",
        ),
    ] {
        let (right, ()) = PROOF_SYSTEM
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(
                    ((), ()),
                    anchor_prev,
                    right_epoch,
                    right_discriminant,
                    &right_members,
                ),
            )
            .unwrap();
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            qr::QrIntakeMerge,
            witness::qr_intake_merge((*left.data(), *right.data()), &left_members, &right_members),
            left.clone(),
            right,
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }

    let (right, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), junction, epoch, discriminant, &right_members),
        )
        .unwrap();
    let (split, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*left.data(), ()), &left_members),
            left,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (deeper, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            witness::qr_side_descend((*split.data(), ()), &left_members, true),
            split,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let deeper_members: Vec<Tachygram> = left_members
        .iter()
        .copied()
        .filter(|&member| qr::classify(Fp::from(member), Fp::from(discriminant)).0)
        .collect();
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        qr::QrIntakeMerge,
        witness::qr_intake_merge(
            (*deeper.data(), *right.data()),
            &deeper_members,
            &right_members,
        ),
        deeper,
        right,
    ) {
        assert_eq!(
            err.to_string(),
            "QrIntakeMerge: inputs sit at different depths"
        );
    } else {
        panic!();
    }
}

#[test]
fn qr_partition_covers_the_epoch_by_profile() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let final_anchor = pool.block(pool.height()).anchor();
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
    let mut profiles: Vec<u32> = routed
        .iter()
        .map(|intake| {
            let (_, anchor_prev, anchor_end, _, profile, ..) = *intake.pcd.data();
            assert_eq!(profile.depth, 2);
            assert_eq!(anchor_prev, Anchor::default());
            assert_eq!(anchor_end, final_anchor);
            profile.bits
        })
        .collect();
    profiles.sort_unstable();
    assert_eq!(profiles, [0, 1, 2, 3]);

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
                .commit()
        );
        for &member in &intake.members {
            for level in 0..profile.depth {
                let side = ((profile.bits >> (profile.depth - 1 - level)) & 1) == 1;
                assert_eq!(
                    qr::classify(Fp::from(member), discriminant.at(level)).0,
                    side
                );
            }
        }
    }
}

#[test]
fn qr_partition_chunks_a_span_past_the_polynomial_capacity() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let final_anchor = pool.block(pool.height()).anchor();
    let discriminant = QrDiscriminant::random(rng);
    let published: Vec<Tachygram> = (0..=3)
        .flat_map(|height| {
            pool.block(BlockHeight(height))
                .stamps
                .iter()
                .map(|stamp| stamp.1.clone())
                .collect::<Vec<_>>()
        })
        .flatten()
        .collect();
    let capacity = 11;

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        capacity,
        1,
    );

    assert!(routed.len() > 2);
    let mut covered: Vec<Tachygram> = Vec::new();
    for side in [true, false] {
        let run: Vec<&QrIntakeEntry> = routed
            .iter()
            .filter(|intake| intake.pcd.data().4 == QrProfile::ROOT.descend(side))
            .collect();
        let first = run.first().unwrap();
        assert_eq!(first.pcd.data().1, Anchor::default());
        let mut cursor = first.pcd.data().2;
        for pair in run.windows(2) {
            assert_eq!(pair[1].pcd.data().1, cursor);
            assert!((pair[0].members.len() + pair[1].members.len()) > capacity);
            cursor = pair[1].pcd.data().2;
        }
        assert_eq!(cursor, final_anchor);
        for intake in run {
            covered.extend(intake.members.iter().copied());
        }
    }

    let sorted = |mut tgs: Vec<Tachygram>| {
        tgs.sort_unstable_by_key(|&tg| Fp::from(tg).to_bytes());
        tgs
    };
    assert_eq!(sorted(covered), sorted(published));
}

#[test]
fn qr_bucket_seal_seals_a_fully_routed_intake() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let final_anchor = pool.block(pool.height()).anchor();
    let discriminant = QrDiscriminant::random(rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        2,
    );
    let intake = routed.into_iter().next().unwrap();
    let (epoch, anchor_prev, _, _, profile, contents) = *intake.pcd.data();
    let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));

    assert_eq!(
        *bucket.pcd.data(),
        (
            epoch,
            anchor_prev,
            final_anchor.next_epoch(epoch.next().unwrap()).unwrap(),
            discriminant,
            profile,
            contents
        )
    );
}

#[test]
fn qr_bucket_seal_rejects_a_stamp_absorption_as_intake_start() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let final_anchor = pool.block(BlockHeight(2)).anchor();
    let discriminant = QrDiscriminant::random(rng);
    let start = pool.block(BlockHeight(0)).anchor();

    let routed = build_qr_partition(rng, &pool, (start, final_anchor), discriminant, 12, 1);
    let intake = routed.into_iter().next().unwrap();
    let witness = witness::qr_bucket_seal((*intake.pcd.data(), ()), Anchor::from(Fp::ZERO));
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        qr::QrBucketSeal,
        witness,
        intake.pcd,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "QrBucketSeal: witnessed boundary digest does not match intake's first anchor"
        );
    } else {
        panic!();
    }
}

#[test]
fn qr_bucket_seal_accepts_an_extent_short_of_the_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let final_anchor = pool.block(pool.height()).anchor();
    let discriminant = QrDiscriminant::random(rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        6,
        0,
    );
    let intake = routed.into_iter().next().unwrap();
    let (_, _, anchor_end, ..) = *intake.pcd.data();

    let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));
    assert_eq!(
        (bucket.pcd.data().2, bucket.pcd.data().3),
        (
            anchor_end.next_epoch(EpochIndex::new(1)).unwrap(),
            discriminant
        )
    );
}

#[test]
fn qr_unspent_segments_of_consecutive_epochs_fuse_directly() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let epoch2 = epoch1.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch1.first_block().0 + 1, |_| random_block(rng, 1, 1));
    let [nf0, nf1] = array::from_fn(|_| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))));

    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.anchor();
    let bucket0 = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), final0),
        EPOCH_MEMBERS,
        0,
        Fp::from(nf0),
        Anchor::from(Fp::ZERO),
    );
    let bucket1 = qr_bucket_for(
        rng,
        &pool,
        (pool.block(epoch1.first_block()).prev, final1),
        EPOCH_MEMBERS,
        0,
        Fp::from(nf1),
        final0,
    );

    let mut segment = |bucket: QrBucketEntry, nf: Nullifier| {
        let witness =
            witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                witness,
                bucket.pcd,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap()
            .0
    };
    let left = segment(bucket0, nf0);
    let right = segment(bucket1, nf1);
    let entry1 = final0.next_epoch(epoch1).unwrap();
    assert_eq!(left.data().4, entry1);
    assert_eq!(left.data().4, right.data().0);

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            UnspentFuse,
            witness::unspent_fuse((*left.data(), *right.data()), &[nf0], &[nf1]),
            left,
            right,
        )
        .unwrap();

    let (anchor_start, epoch_start, elapsed, epoch_next, anchor_next) = *fused.data();
    assert_eq!(anchor_start, Anchor::default());
    assert_eq!((epoch_start, epoch_next), (epoch0, epoch2));
    assert_eq!(anchor_next, final1.next_epoch(epoch2).unwrap());
    assert_eq!(elapsed, NfSeqPoly::new(epoch0, &[nf0, nf1]).commit());
}

fn empty_bucket(
    rng: &mut StdRng,
    anchor: Anchor,
    epoch: EpochIndex,
    anchor_final_prev: Anchor,
) -> QrBucketEntry {
    let discriminant = QrDiscriminant::random(rng);
    let intake = seed_qr_empty_intake(rng, anchor, epoch, discriminant);
    seal_qr_intake(rng, intake, anchor_final_prev)
}

#[test]
fn qr_empty_intake_seed_spans_a_stampless_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let epoch2 = epoch1.next().unwrap();
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
    pool.advance(epoch0.last_block().0, |_| random_block(rng, 1, 1));
    pool.advance(EPOCH_SIZE, |_| Vec::new());
    pool.mine(random_block(rng, 1, 1));
    let [nf0, nf1] = array::from_fn(|_| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))));

    let final0 = pool.block(epoch0.last_block()).anchor();
    let entry1 = pool.block(epoch1.first_block()).prev;
    let entry2 = pool.block(epoch2.first_block()).prev;
    assert_eq!(pool.block(epoch1.last_block()).anchor(), entry1);

    let bucket = empty_bucket(rng, entry1, epoch1, final0);
    let (epoch, anchor_start, anchor_next, _, profile, contents) = *bucket.pcd.data();
    assert_eq!((epoch, anchor_start, anchor_next), (epoch1, entry1, entry2));
    assert_eq!(
        (profile, contents),
        (
            QrProfile::ROOT,
            iter::empty().collect::<TachygramSetPoly>().commit()
        )
    );

    let left = {
        let bucket0 = qr_bucket_for(
            rng,
            &pool,
            (Anchor::default(), final0),
            EPOCH_MEMBERS,
            0,
            Fp::from(nf0),
            Anchor::from(Fp::ZERO),
        );
        let witness =
            witness::qr_unspent_init((*bucket0.pcd.data(), ()), nf0.into(), &bucket0.members);
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                witness,
                bucket0.pcd,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap()
            .0
    };
    let right = {
        let witness =
            witness::qr_unspent_init((*bucket.pcd.data(), ()), nf1.into(), &bucket.members);
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                witness,
                bucket.pcd,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap()
            .0
    };

    let (fused, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            UnspentFuse,
            witness::unspent_fuse((*left.data(), *right.data()), &[nf0], &[nf1]),
            left,
            right,
        )
        .unwrap();
    let (fused_anchor_start, _, elapsed, fused_epoch_next, fused_anchor_next) = *fused.data();
    assert_eq!(fused_anchor_start, Anchor::default());
    assert_eq!(fused_epoch_next, epoch2);
    assert_eq!(fused_anchor_next, entry2);
    assert_eq!(elapsed, NfSeqPoly::new(epoch0, &[nf0, nf1]).commit());
}

#[test]
fn qr_empty_intake_seed_over_a_stamped_epoch_leaves_the_chain() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (_pool, final_anchor) = small_epoch(rng);
    let epoch = EpochIndex::new(0);
    let bucket = empty_bucket(rng, Anchor::default(), epoch, Anchor::from(Fp::ZERO));
    assert_ne!(
        bucket.pcd.data().2,
        final_anchor.next_epoch(epoch.next().unwrap()).unwrap()
    );
}

#[test]
fn qr_spendable_init_starts_a_spendable_that_reaches_spend_bind() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(400);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let epoch0 = EpochIndex::new(0);
    let epoch1 = epoch0.next().unwrap();
    let epoch2 = epoch1.next().unwrap();
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.advance(epoch2.first_block().0, |_| random_block(rng, 1, 1));

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
        Fp::from(mk.derive_nullifier(epoch0)),
        Anchor::from(Fp::ZERO),
    );
    assert_ne!(bucket.pcd.data().4, nf_bucket.pcd.data().4);
    let (_, _, anchor_next, ..) = *bucket.pcd.data();
    assert_eq!(anchor_next, span.1.next_epoch(epoch1).unwrap());
    let unspent = qr_epoch_unspent(rng, &user, &note, &nf_bucket);

    let (spendable, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::QrSpendableInit,
            witness::qr_spendable_init((*unspent.data(), *bucket.pcd.data()), &bucket.members),
            unspent,
            bucket.pcd,
        )
        .unwrap();
    assert_eq!(*spendable.data(), (note.commitment(), epoch1, anchor_next));

    let lifted = user.lift_to_epoch(rng, &pool, &note, spendable, epoch2);
    let secret = user.secret_pcd(rng, note);
    let rcv = value::Trapdoor::random(rng);
    let (bind, ()) = PROOF_SYSTEM
        .fuse(rng, spend::SpendBind, (rcv,), lifted, secret)
        .unwrap();
    let (bind_cm, nf_current, nf_next, ..) = *bind.data();
    assert_eq!(bind_cm, note.commitment());
    assert_eq!(
        (nf_current, nf_next),
        (
            mk.derive_nullifier(epoch2),
            mk.derive_nullifier(EpochIndex::new(u32::from(epoch2) + 1))
        )
    );
}

#[test]
fn qr_short_bucket_yields_evidence_no_suffix_can_extend() {
    let rng = &mut StdRng::seed_from_u64(196);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch = EpochIndex::new(0);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    let short_anchor = pool.anchor();
    pool.mine(random_block(rng, 2, 1));
    let tip_anchor = pool.anchor();
    assert_ne!(short_anchor, tip_anchor);
    assert_eq!(pool.height().epoch(), epoch);

    let bucket = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), short_anchor),
        1,
        0,
        Fp::from(Tachygram::from(note.commitment())),
        Anchor::from(Fp::ZERO),
    );
    let epoch_next = epoch.next().unwrap();
    let unpublished = short_anchor.next_epoch(epoch_next).unwrap();
    assert_eq!(bucket.pcd.data().2, unpublished);
    let unspent = qr_epoch_unspent(rng, &user, &note, &bucket);
    let (spendable, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            spendable::QrSpendableInit,
            witness::qr_spendable_init((*unspent.data(), *bucket.pcd.data()), &bucket.members),
            unspent,
            bucket.pcd,
        )
        .unwrap();
    assert_eq!(
        *spendable.data(),
        (note.commitment(), epoch_next, unpublished)
    );
    assert!(
        pool.stamps_between(Anchor::default(), tip_anchor)
            .iter()
            .all(|entry| entry.3 != unpublished)
    );

    pool.advance(epoch_next.last_block().0 - pool.height().0, |_| {
        random_block(rng, 1, 1)
    });
    let next = build_unspent_pcd_over_epochs(
        rng,
        &pool,
        |covered| {
            user.pak
                .nk
                .derive_note_private(note.psi)
                .derive_nullifier(covered)
        },
        (epoch_next, epoch_next.next().unwrap()),
    );
    let bound_next = user.unspent_bind(rng, next, &note);
    assert_ne!(bound_next.data().1, unpublished);
    if let Err(ragu_core::Error::InvalidWitness(err)) =
        PROOF_SYSTEM.fuse(rng, spendable::SpendableLift, (), spendable, bound_next)
    {
        assert_eq!(
            err.to_string(),
            "SpendableLift: unspent not adjacent to spendable"
        );
    } else {
        panic!();
    }
}

#[test]
fn qr_spendable_init_rejects_a_bucket_that_does_not_match_the_segment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::from(note.commitment())]]);
    pool.advance(epoch1.last_block().0, |_| random_block(rng, 1, 1));
    let final0 = pool.block(epoch0.last_block()).anchor();
    let final1 = pool.block(epoch1.last_block()).anchor();

    let bucket0 = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), final0),
        EPOCH_MEMBERS,
        0,
        Fp::from(mk.derive_nullifier(epoch0)),
        Anchor::from(Fp::ZERO),
    );
    let unspent0 = qr_epoch_unspent(rng, &user, &note, &bucket0);
    let bucket1 = qr_bucket_for(
        rng,
        &pool,
        (final0.next_epoch(epoch1).unwrap(), final1),
        EPOCH_MEMBERS,
        0,
        Fp::from(mk.derive_nullifier(epoch1)),
        final0,
    );
    let unspent1 = qr_epoch_unspent(rng, &user, &note, &bucket1);

    let fake_anchor_final_prev = Anchor::from(Fp::ONE);
    let members = [Tachygram::from(note.commitment())];
    let discriminant = QrDiscriminant::random(rng);
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

    for (unspent, bucket, expected) in [
        (
            unspent0.clone(),
            qr_bucket_for(
                rng,
                &pool,
                (Anchor::default(), pool.block(BlockHeight(1)).anchor()),
                EPOCH_MEMBERS,
                0,
                Fp::from(Tachygram::from(note.commitment())),
                Anchor::from(Fp::ZERO),
            ),
            "QrSpendableInit: segment does not close where the bucket does",
        ),
        (
            unspent0,
            bucket1,
            "QrSpendableInit: segment does not start in the bucket's epoch",
        ),
        (
            unspent1,
            elsewhere,
            "QrSpendableInit: segment does not open where the bucket does",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            spendable::QrSpendableInit,
            witness::qr_spendable_init((*unspent.data(), *bucket.pcd.data()), &bucket.members),
            unspent,
            bucket.pcd,
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }
}

#[test]
fn qr_spendable_init_rejects_an_absent_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(300);
    let epoch0 = EpochIndex::new(0);
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

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        spendable::QrSpendableInit,
        witness::qr_spendable_init((*unspent.data(), *bucket.pcd.data()), &bucket.members),
        unspent,
        bucket.pcd,
    ) {
        assert_eq!(err.to_string(), "QrSpendableInit: commitment not in bucket");
    } else {
        panic!();
    }
}

#[test]
fn qr_unspent_init_rejects_a_published_nullifier() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let final_anchor = pool.block(pool.height()).anchor();
    let discriminant = QrDiscriminant::random(rng);

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        2,
    );
    let intake = routed
        .into_iter()
        .find(|intake| !intake.members.is_empty())
        .unwrap();
    let published = *intake.members.first().unwrap();
    let nf = Nullifier::from(Fp::from(published));
    let bucket = seal_qr_intake(rng, intake, Anchor::from(Fp::ZERO));

    let witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        qr::QrUnspentInit,
        witness,
        bucket.pcd,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "QrUnspentInit: found nullifier in the bucket"
        );
    } else {
        panic!();
    }
}

#[test]
fn qr_unspent_init_rejects_a_foreign_bucket() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    for _ in 0..3 {
        pool.mine(random_block(rng, 2, 3));
    }
    let final_anchor = pool.block(pool.height()).anchor();
    let discriminant = QrDiscriminant::random(rng);
    let nf = Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)));

    let routed = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        2,
    );
    let profile = qr_profile_of(Fp::from(nf), discriminant, 2);
    let foreign = routed
        .into_iter()
        .find(|intake| intake.pcd.data().4 != profile)
        .unwrap();
    let bucket = seal_qr_intake(rng, foreign, Anchor::from(Fp::ZERO));

    let witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        qr::QrUnspentInit,
        witness,
        bucket.pcd,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "QR profile: value does not take the bucket's profile"
        );
    } else {
        panic!();
    }
}

#[test]
fn qr_unspent_init_rejects_corrupted_inputs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let nf = Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let bucket = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        24,
        2,
        Fp::from(nf),
        Anchor::from(Fp::ZERO),
    );
    let (epoch, ..) = *bucket.pcd.data();
    let witness = witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);

    for (bucket_pcd, init_witness, expected) in [
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.1[0].1 += Fp::ONE;
                forged
            },
            "QR profile: root does not square to the claimed class",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.1[5].0 = !forged.1[5].0;
                forged
            },
            "QR profile: root does not square to the claimed class",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.2 = array::from_fn(|position| position == 0 || position == 2);
                forged
            },
            "QR profile: depth mask is not a prefix",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.2 = QrProfile { depth: 3, bits: 0 }.depth_mask();
                forged
            },
            "QR profile: depth mask does not match the bucket's depth",
        ),
        {
            let mut data = *bucket.pcd.data();
            data.0 = EpochIndex::new(EPOCH_MAX);
            (
                bucket.pcd.proof().clone().carry::<qr::QrBucket>(data),
                witness::qr_unspent_init((data, ()), nf.into(), &bucket.members),
                "QrUnspentInit: bucket has no next epoch",
            )
        },
        {
            let mut data = *bucket.pcd.data();
            data.4.depth = u32::BITS + 1;
            let mut forged = witness.clone();
            forged.2 = [true; QrProfile::MAX_DEPTH];
            (
                bucket.pcd.proof().clone().carry::<qr::QrBucket>(data),
                forged,
                "QR profile: depth mask does not match the bucket's depth",
            )
        },
        {
            let mut data = *bucket.pcd.data();
            data.4 = QrProfile { depth: 0, bits: 1 };
            let mut forged = witness.clone();
            forged.2 = QrProfile::ROOT.depth_mask();
            (
                bucket.pcd.proof().clone().carry::<qr::QrBucket>(data),
                forged,
                "QR profile: value does not take the bucket's profile",
            )
        },
        (
            bucket.pcd.clone(),
            witness::qr_unspent_init(
                (*bucket.pcd.data(), ()),
                Tachygram::from(Fp::ZERO),
                &bucket.members,
            ),
            "QrUnspentInit: tested value is zero",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.3 = NfSeqPoly::new(
                    epoch,
                    &[Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)))],
                );
                forged
            },
            "QrUnspentInit: sequence does not match the tested pair",
        ),
        (
            bucket.pcd.clone(),
            {
                let mut forged = witness.clone();
                forged.4 = iter::once(Tachygram::random(rng)).collect();
                forged
            },
            "QrUnspentInit: contents do not match the bucket",
        ),
    ] {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            qr::QrUnspentInit,
            init_witness,
            bucket_pcd,
            Proof::bootstrap().carry::<()>(()),
        ) {
            assert_eq!(err.to_string(), expected);
        } else {
            panic!("{expected}");
        }
    }
}

#[test]
fn qr_unspent_init_rejects_the_fixed_point_on_the_non_residue_side() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let discriminant = QrDiscriminant::random(rng);
    let position = 1;
    let value = -discriminant.at(position);
    assert_ne!(value, Fp::ZERO);
    let nf = Nullifier::from(value);

    let bucket = qr_bucket_at(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
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
            .any(|&member| Fp::from(member) == value)
    );
    let mut witness =
        witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
    let (_, honest_roots, ..) = witness;
    assert_eq!(
        honest_roots[usize::try_from(position).unwrap()],
        QrClassRoot(true, Fp::ZERO)
    );
    PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentInit,
            witness.clone(),
            bucket.pcd.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap()
        .0;

    let (_, ref mut roots, ..) = witness;
    let QrClassRoot(ref mut side, _) = roots[usize::try_from(position).unwrap()];
    *side = false;
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        qr::QrUnspentInit,
        witness,
        bucket.pcd,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "QR profile: exceptional discriminant claimed the non-residue class"
        );
    } else {
        panic!();
    }
}

#[test]
fn qr_bucket_seal_refuses_the_final_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let pool = PoolSim::genesis_with(random_block(rng, 2, 3));
    let discriminant = QrDiscriminant::random(rng);
    let intake = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), pool.anchor()),
        discriminant,
        24,
        0,
    )
    .into_iter()
    .next()
    .unwrap();
    let final_epoch = EpochIndex::new(EPOCH_MAX);
    let anchor_final_prev = Anchor::from(Fp::ONE);

    let mut data = *intake.pcd.data();
    data.0 = final_epoch;
    data.1 = anchor_final_prev.next_epoch(final_epoch).unwrap();
    let forged = intake.pcd.proof().clone().carry::<qr::QrIntake>(data);
    let witness = witness::qr_bucket_seal((data, ()), anchor_final_prev);
    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        qr::QrBucketSeal,
        witness,
        forged,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "QrBucketSeal: crossing past the final epoch"
        );
    } else {
        panic!();
    }
}

#[test]
fn qr_unspent_init_rejects_a_twin_value() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let nf = Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let bucket = qr_bucket_for(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        24,
        0,
        Fp::from(nf),
        Anchor::from(Fp::ZERO),
    );
    let (epoch, _, _, discriminant, ..) = *bucket.pcd.data();
    let mut witness =
        witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);

    let z = unpinned_challenge(&[witness.3.commit().into()]);
    let shift = (Fp::from(u64::from(epoch)) + Fp::ONE) * z;
    let twin = (Fp::ZETA * (Fp::from(nf) + shift)) - shift;
    assert_ne!(twin, Fp::from(nf));
    assert_eq!(
        (twin + shift).pow_u64(3) - Fp::from(2),
        (Fp::from(nf) + shift).pow_u64(3) - Fp::from(2)
    );
    witness.0 = Tachygram::from(twin);
    witness.1 = QrClassRoot::along(twin, discriminant);

    if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
        rng,
        qr::QrUnspentInit,
        witness,
        bucket.pcd,
        Proof::bootstrap().carry::<()>(()),
    ) {
        assert_eq!(
            err.to_string(),
            "QrUnspentInit: sequence does not match the tested pair"
        );
    } else {
        panic!();
    }
}

#[test]
fn qr_unspent_init_accepts_ragged_depths() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let epoch = BlockHeight(0).epoch();
    let epoch_next = epoch.next().unwrap();
    let discriminant = QrDiscriminant::random(rng);
    let shallow_value = Fp::random(|bytes| rng.fill_bytes(bytes));
    let shallow_side = qr::classify(shallow_value, discriminant.at(0)).0;
    let deep_value = iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
        .find(|&value| qr::classify(value, discriminant.at(0)).0 != shallow_side)
        .unwrap();

    let root = build_qr_partition(
        rng,
        &pool,
        (Anchor::default(), final_anchor),
        discriminant,
        24,
        0,
    )
    .pop()
    .unwrap();
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
        let witness =
            witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
        let unspent = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                witness,
                bucket.pcd,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap()
            .0;
        assert_eq!(
            *unspent.data(),
            (
                Anchor::default(),
                epoch,
                NfSeqPoly::new(epoch, &[nf]).commit(),
                epoch_next,
                final_anchor.next_epoch(epoch_next).unwrap()
            ),
            "the segment is the bucket's extent, ending on the crossing, at depth {depth}"
        );
    }
}

#[test]
fn qr_unspent_init_accepts_buckets_at_every_depth() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, final_anchor) = small_epoch(rng);
    let epoch = BlockHeight(0).epoch();
    let epoch_next = epoch.next().unwrap();
    let nf = Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)));

    for depth in [0, 1, 31, u32::BITS] {
        let bucket = qr_bucket_for(
            rng,
            &pool,
            (Anchor::default(), final_anchor),
            24,
            depth,
            Fp::from(nf),
            Anchor::from(Fp::ZERO),
        );
        let witness =
            witness::qr_unspent_init((*bucket.pcd.data(), ()), nf.into(), &bucket.members);
        let unspent = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                witness,
                bucket.pcd,
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap()
            .0;
        assert_eq!(
            *unspent.data(),
            (
                Anchor::default(),
                epoch,
                NfSeqPoly::new(epoch, &[nf]).commit(),
                epoch_next,
                final_anchor.next_epoch(epoch_next).unwrap()
            ),
            "the segment is the bucket's extent, ending on the crossing, at depth {depth}"
        );
    }
}

#[test]
fn unspent_lift_appends_one_epoch() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (epoch0, epoch1, epoch2) = (EpochIndex::new(0), EpochIndex::new(1), EpochIndex::new(2));
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(epoch2.first_block().0, |_| random_block(rng, 1, 2));
    let [nf0, nf1] = array::from_fn(|_| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))));
    let nf = |epoch: EpochIndex| if epoch == epoch0 { nf0 } else { nf1 };

    let first = epoch_bucket(rng, &pool, epoch0);
    let segment = qr_bucket_segment(rng, &first, nf);
    let bucket = epoch_bucket(rng, &pool, epoch1);
    let lift = witness::unspent_lift(
        (*segment.data(), *bucket.pcd.data()),
        nf1.into(),
        &[nf0],
        &bucket.members,
    );
    let lifted = PROOF_SYSTEM
        .fuse(rng, UnspentLift, lift, segment, bucket.pcd.clone())
        .unwrap()
        .0;

    let fused = build_unspent_pcd_over_epochs(rng, &pool, nf, (epoch0, epoch2));
    assert_eq!(*lifted.data(), *fused.data());
}

#[test]
fn unspent_lift_carries_a_spendable() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::new(shared_sk());
    let note = user.random_note(500);
    let mk = user.pak.nk.derive_note_private(note.psi);
    let (epoch1, epoch2, epoch3) = (EpochIndex::new(1), EpochIndex::new(2), EpochIndex::new(3));

    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 2));
    pool.advance(epoch3.first_block().0 - pool.height().0, |_| {
        random_block(rng, 1, 2)
    });

    let spendable = user.spendable_at(rng, &pool, &note, epoch1);
    let first = epoch_bucket(rng, &pool, epoch1);
    let segment = qr_bucket_segment(rng, &first, |epoch| mk.derive_nullifier(epoch));
    let bucket = epoch_bucket(rng, &pool, epoch2);
    let lift = witness::unspent_lift(
        (*segment.data(), *bucket.pcd.data()),
        mk.derive_nullifier(epoch2).into(),
        &[mk.derive_nullifier(epoch1)],
        &bucket.members,
    );
    let lifted = PROOF_SYSTEM
        .fuse(rng, UnspentLift, lift, segment, bucket.pcd.clone())
        .unwrap()
        .0;

    let carried = user.lift(rng, spendable, lifted, &note);
    assert_eq!(
        *carried.data(),
        (
            note.commitment(),
            epoch3,
            pool.block(epoch3.first_block()).prev
        )
    );
}

#[test]
fn unspent_lift_rejects_invalid_extensions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (epoch0, epoch1, epoch2) = (EpochIndex::new(0), EpochIndex::new(1), EpochIndex::new(2));
    let mut pool = PoolSim::genesis_with(random_block(rng, 1, 50));
    pool.advance(EpochIndex::new(3).first_block().0, |_| {
        random_block(rng, 1, 2)
    });
    let [nf0, nf1] = array::from_fn(|_| Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))));
    let nf = |epoch: EpochIndex| if epoch == epoch0 { nf0 } else { nf1 };

    let first = epoch_bucket(rng, &pool, epoch0);
    let segment = qr_bucket_segment(rng, &first, nf);
    let bucket = epoch_bucket(rng, &pool, epoch1);
    let past = epoch_bucket(rng, &pool, epoch2);
    let honest = |value: Tachygram, elapsed: &[Nullifier]| {
        witness::unspent_lift(
            (*segment.data(), *bucket.pcd.data()),
            value,
            elapsed,
            &bucket.members,
        )
    };

    let (value, classes, mask, elapsed_seq, _extended, contents) = honest(nf1.into(), &[nf0]);
    let forged_extended = NfSeqPoly::new(
        epoch0,
        &[
            nf0,
            Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes))),
        ],
    );
    let (_, _, _, discriminant, ..) = *bucket.pcd.data();
    let other = Fp::random(|bytes| rng.fill_bytes(bytes));

    let cases = [
        (
            "a bucket past the segment's end",
            &past,
            honest(nf1.into(), &[nf0]),
            "UnspentLift: the bucket does not start where the segment ends",
        ),
        (
            "the value in the bucket",
            &bucket,
            honest(bucket.members[0], &[nf0]),
            "UnspentLift: found nullifier in the bucket",
        ),
        (
            "elapsed off the header",
            &bucket,
            honest(nf1.into(), &[nf1]),
            "UnspentLift: elapsed does not match header",
        ),
        (
            "extended not elapsed with the pair",
            &bucket,
            (
                value,
                classes,
                mask,
                elapsed_seq.clone(),
                forged_extended,
                contents.clone(),
            ),
            "UnspentLift: extended is not elapsed with the tested pair",
        ),
        (
            "classes for another value",
            &bucket,
            (
                value,
                QrClassRoot::along(other, discriminant),
                mask,
                elapsed_seq,
                honest(nf1.into(), &[nf0]).4,
                contents,
            ),
            "QR profile: root does not square to the claimed class",
        ),
    ];

    for (label, lift_bucket, lift, expected) in cases {
        if let Err(ragu_core::Error::InvalidWitness(err)) = PROOF_SYSTEM.fuse(
            rng,
            UnspentLift,
            lift,
            segment.clone(),
            lift_bucket.pcd.clone(),
        ) {
            assert_eq!(err.to_string(), expected, "{label}");
        } else {
            panic!("{label}");
        }
    }
}
