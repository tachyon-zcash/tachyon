extern crate alloc;

use alloc::vec::Vec;
use core::{array, iter};

use ragu::{Pcd, Proof};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetPoly,
    constants::EPOCH_MAX,
    nullifier::Nullifier,
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, qr, summary},
    witness,
};

use crate::fixtures::{
    PoolSim, QrBucketEntry, QrIntakeEntry, build_qr_partition, mine_sparse, qr_bucket_at,
    split_qr_intake, unpinned_challenge,
};

fn classed_members(rng: &mut StdRng, shift: Fp) -> (Vec<Tachygram>, Vec<Tachygram>, Tachygram) {
    let non_square = (2u64..=64)
        .map(Fp::from)
        .find(|&candidate| !qr::classify(candidate, Fp::ZERO).0)
        .unwrap();
    let mut residue = Vec::new();
    let mut non_residue = Vec::new();
    for _ in 0..2 {
        let residue_root = Fp::random(|bytes| rng.fill_bytes(bytes));
        residue.push(Tachygram::from(residue_root.square() - shift));
        let non_residue_root = Fp::random(|bytes| rng.fill_bytes(bytes));
        non_residue.push(Tachygram::from(
            non_square * non_residue_root.square() - shift,
        ));
    }
    (residue, non_residue, Tachygram::from(-shift))
}

#[test]
fn intakes_root_on_summaries_and_stamps() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (epoch_index, size) in [(0, 1), (EPOCH_MAX, 6)] {
        let epoch = EpochIndex::new(epoch_index);
        let case = format!("{size} tachygrams at epoch {epoch:?}");
        let start = Anchor::random(rng);
        let discriminant = QrDiscriminant::random(rng);
        let members: Vec<Tachygram> = iter::repeat_with(|| Tachygram::random(rng))
            .take(size)
            .collect();
        let contents = members
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit();
        let end = start.next_stamp(epoch, &contents).unwrap();

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
                qr::QrSummaryIntake,
                witness::qr_summary_intake((*summary.data(), ()), discriminant),
                summary,
                Proof::bootstrap().carry::<()>(()),
            )
            .expect("QrSummaryIntake");
        assert_eq!(
            *root.data(),
            (epoch, start, end, discriminant, QrProfile::ROOT, contents),
            "{case}: the summary's root"
        );
        let (stamp_root, ()) = PROOF_SYSTEM
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &members),
            )
            .unwrap();
        assert_eq!(*stamp_root.data(), *root.data(), "{case}: the stamp's root");

        let (empty, ()) = PROOF_SYSTEM
            .seed(
                rng,
                qr::QrEmptyIntakeSeed,
                witness::qr_empty_intake_seed(((), ()), start, epoch, discriminant),
            )
            .unwrap();
        assert_eq!(
            *empty.data(),
            (
                epoch,
                start,
                start,
                discriminant,
                QrProfile::ROOT,
                iter::empty().collect::<TachygramSetPoly>().commit()
            ),
            "{case}: the empty intake"
        );
    }

    let (start, discriminant) = (Anchor::random(rng), QrDiscriminant::random(rng));
    let empty_stamp = PROOF_SYSTEM.seed(
        rng,
        qr::QrStampIntakeSeed,
        witness::qr_stamp_intake_seed(((), ()), start, EpochIndex::new(0), discriminant, &[]),
    );
    assert_eq!(
        empty_stamp.map(drop).unwrap_err().to_string(),
        "invalid witness: invalid anchor step"
    );
}

#[test]
fn partition_routes_every_member_by_profile() {
    let rng = &mut StdRng::seed_from_u64(0);
    let rows: [(&[&[usize]], u64, u32, usize, u32); 2] = [
        (&[&[3, 3], &[2]], 8, 3, 1, 2),
        (&[&[1, 2], &[3], &[2, 2], &[1]], 4, 2, 5, 1),
    ];
    for (blocks, consecutive, depth, capacity, level) in rows {
        let case = format!("blocks of {blocks:?} to depth {depth}");
        let discriminant = QrDiscriminant::random(rng);
        let base = Fp::random(|bytes| rng.fill_bytes(bytes));
        let special: Vec<Tachygram> = (0..consecutive)
            .map(|offset| Tachygram::from(base + Fp::from(offset)))
            .chain([Tachygram::from(-discriminant.at(level))])
            .collect();
        let mut pool = PoolSim::genesis_with([special].to_vec());
        for sizes in blocks {
            pool.mine(
                sizes
                    .iter()
                    .map(|&size| {
                        iter::repeat_with(|| Tachygram::random(rng))
                            .take(size)
                            .collect()
                    })
                    .collect(),
            );
        }
        let end = pool.block(pool.height()).anchor();
        let stamps: Vec<Vec<Tachygram>> = (0..=pool.height().0)
            .flat_map(|height| {
                pool.block(BlockHeight(height))
                    .stamps
                    .iter()
                    .map(|stamp| stamp.1.clone())
            })
            .collect();

        let routed = build_qr_partition(
            rng,
            &pool,
            (Anchor::default(), end),
            discriminant,
            capacity,
            depth,
        );
        for intake in &routed {
            let (intake_epoch, _, _, intake_discriminant, profile, contents) = *intake.pcd.data();
            assert_eq!(intake_epoch, EpochIndex::new(0), "{case}: the epoch");
            assert_eq!(
                intake_discriminant, discriminant,
                "{case}: the discriminant"
            );
            assert_eq!(profile.depth, depth, "{case}: the depth");
            assert_eq!(
                contents,
                intake
                    .members
                    .iter()
                    .copied()
                    .collect::<TachygramSetPoly>()
                    .commit(),
                "{case}: the contents"
            );
            for &member in &intake.members {
                assert_eq!(
                    (0..depth).fold(QrProfile::ROOT, |member_profile, member_level| {
                        member_profile.descend(
                            qr::classify(Fp::from(member), discriminant.at(member_level)).0,
                        )
                    }),
                    profile,
                    "{case}: a member's profile"
                );
            }
        }
        for bits in 0..1u32 << depth {
            let mut cursor = Anchor::default();
            for intake in routed
                .iter()
                .filter(|intake| intake.pcd.data().4 == QrProfile { depth, bits })
            {
                assert_eq!(
                    intake.pcd.data().1,
                    cursor,
                    "{case}: profile {bits} is adjacent"
                );
                cursor = intake.pcd.data().2;
            }
            assert_eq!(cursor, end, "{case}: profile {bits} reaches the end");
        }

        let sorted = |mut members: Vec<Tachygram>| {
            members.sort_unstable_by_key(|&member| Fp::from(member).to_bytes());
            members
        };
        let held = routed
            .iter()
            .flat_map(|intake| intake.members.iter().copied())
            .collect();
        assert_eq!(
            sorted(held),
            sorted(stamps.concat()),
            "{case}: the members held"
        );
    }
}

#[test]
fn intake_split_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(0);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let (residue, non_residue, exceptional) = classed_members(rng, discriminant.at(0));
    let residue_class: Vec<Tachygram> = residue.iter().copied().chain([exceptional]).collect();
    let members: Vec<Tachygram> = residue_class.iter().chain(&non_residue).copied().collect();
    let (intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &members),
        )
        .unwrap();

    let honest = witness::qr_intake_split((*intake.data(), ()), &members);
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            honest.clone(),
            intake.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    assert_eq!(
        *sides.data(),
        (
            epoch,
            start,
            intake.data().2,
            discriminant,
            QrProfile::ROOT,
            non_residue
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit(),
            residue_class
                .iter()
                .copied()
                .collect::<TachygramSetPoly>()
                .commit()
        )
    );
    let (contents, honest_non_residue, honest_residue) = honest;
    let strangers = iter::repeat_with(|| Tachygram::random(rng))
        .take(2)
        .collect::<TachygramSetPoly>();
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrIntakeSplit,
                (strangers, honest_non_residue.clone(), honest_residue),
                intake.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrIntakeSplit: contents do not match header",
    );
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrIntakeSplit,
                (
                    contents.clone(),
                    honest_non_residue.clone(),
                    honest_non_residue,
                ),
                intake.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrIntakeSplit: the sides do not partition the contents",
    );
    let misfiled = (
        contents,
        non_residue.iter().copied().chain([exceptional]).collect(),
        residue.iter().copied().collect(),
    );
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrIntakeSplit,
                misfiled,
                intake.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrIntakeSplit: exceptional value claimed the non-residue class",
    );

    let deepest = Tachygram::from(-discriminant.at(u32::BITS - 1));
    let mut deep_data = *intake.data();
    deep_data.4 = QrProfile {
        depth: u32::BITS - 1,
        bits: 0,
    };
    deep_data.5 = iter::once(deepest).collect::<TachygramSetPoly>().commit();
    let deep = intake.proof().clone().carry::<qr::QrIntake>(deep_data);
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrIntakeSplit,
                (
                    iter::once(deepest).collect(),
                    iter::once(deepest).collect(),
                    iter::empty().collect(),
                ),
                deep,
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrIntakeSplit: exceptional value claimed the non-residue class",
    );
}

#[test]
fn side_descend_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(0);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let (residue, non_residue, exceptional) = classed_members(rng, discriminant.at(0));
    let residue_class: Vec<Tachygram> = residue.iter().copied().chain([exceptional]).collect();
    let members: Vec<Tachygram> = residue_class.iter().chain(&non_residue).copied().collect();
    let (intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &members),
        )
        .unwrap();
    let anchor_end = intake.data().2;
    let honest = witness::qr_intake_split((*intake.data(), ()), &members);
    let contents = honest.0.clone();
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            honest,
            intake.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let residue_child = witness::qr_side_descend((*sides.data(), ()), &members, true);
    let non_residue_child = witness::qr_side_descend((*sides.data(), ()), &members, false);

    let smuggled = residue[0];
    let padded: TachygramSetPoly = non_residue.iter().copied().chain([smuggled]).collect();
    let short: TachygramSetPoly = residue_class
        .iter()
        .copied()
        .filter(|&member| member != smuggled)
        .collect();
    let (misfiled, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            (contents, padded.clone(), short),
            intake,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (_, _, short_interpolant, short_quotient) =
        witness::qr_side_descend((*misfiled.data(), ()), &members, true);
    let unsmuggled: Vec<Tachygram> = members
        .iter()
        .copied()
        .filter(|&member| member != smuggled)
        .collect();
    let (impure, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            witness::qr_side_descend((*misfiled.data(), ()), &unsmuggled, false),
            misfiled.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    assert_eq!(
        *impure.data(),
        (
            epoch,
            start,
            anchor_end,
            discriminant,
            QrProfile::ROOT.descend(false),
            padded.commit()
        )
    );

    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                (
                    true,
                    non_residue_child.1.clone(),
                    residue_child.2.clone(),
                    residue_child.3.clone(),
                ),
                sides.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrSideDescend: sibling does not match the header",
    );
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                (
                    true,
                    residue_child.1.clone(),
                    non_residue_child.2.clone(),
                    residue_child.3.clone(),
                ),
                sides.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrSideDescend: the sibling fails its class decomposition",
    );
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                (
                    false,
                    non_residue_child.1.clone(),
                    residue_child.2.clone(),
                    non_residue_child.3.clone(),
                ),
                sides.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrSideDescend: the sibling fails its class decomposition",
    );
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                (
                    true,
                    residue_child.1.clone(),
                    residue_child.2.clone(),
                    non_residue_child.3.clone(),
                ),
                sides.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrSideDescend: the sibling fails its class decomposition",
    );
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                (
                    false,
                    non_residue_child.1,
                    non_residue_child.2,
                    residue_child.3.clone(),
                ),
                sides.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrSideDescend: the sibling fails its class decomposition",
    );
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                (true, padded, short_interpolant, short_quotient),
                misfiled,
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrSideDescend: the sibling fails its class decomposition",
    );

    let mut spent_data = *sides.data();
    spent_data.4 = QrProfile {
        depth: u32::BITS,
        bits: 0,
    };
    let spent = sides.proof().clone().carry::<qr::QrIntakeSides>(spent_data);
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                residue_child,
                spent,
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrSideDescend: profile has no bit left for another side",
    );
}

#[test]
fn side_descend_binds_the_discriminant() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(0);
    let start = Anchor::random(rng);
    let discriminant = QrDiscriminant::random(rng);
    let (residue, non_residue, exceptional) = classed_members(rng, discriminant.at(0));
    let members: Vec<Tachygram> = residue
        .iter()
        .chain(&non_residue)
        .copied()
        .chain([exceptional])
        .collect();
    let sibling: TachygramSetPoly = members.iter().copied().collect();
    let (intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &members),
        )
        .unwrap();
    let (sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            witness::qr_intake_split((*intake.data(), ()), &members),
            intake,
            Proof::bootstrap().carry::<()>(()),
        )
        .expect("QrIntakeSplit");
    let (_, _, interpolant, quotient) =
        witness::qr_side_descend((*sides.data(), ()), &members, false);

    // The witness is solved against a challenge that omits the discriminant.
    let challenge = unpinned_challenge(&[
        sibling.commit().into(),
        interpolant.commit().into(),
        quotient.commit().into(),
    ]);
    let solved = QrDiscriminant::from(
        interpolant.eval(challenge).square()
            - (sibling.eval(challenge) * quotient.eval(challenge))
            - challenge,
    );
    assert!(
        members
            .iter()
            .any(|&member| !qr::classify(Fp::from(member), solved.at(0)).0)
    );

    let (solved_intake, ()) = PROOF_SYSTEM
        .seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, solved, &members),
        )
        .unwrap();
    let (solved_sides, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            (sibling.clone(), iter::empty().collect(), sibling.clone()),
            solved_intake,
            Proof::bootstrap().carry::<()>(()),
        )
        .expect("the split's product does not read the discriminant");
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrSideDescend,
                (false, sibling, interpolant, quotient),
                solved_sides,
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrSideDescend: the sibling fails its class decomposition",
    );
}

#[test]
fn intake_merge_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(0);
    let start = Anchor::random(rng);
    let [discriminant, other_discriminant] = [(); 2].map(|()| QrDiscriminant::random(rng));
    let (left_members, right_members) = (
        iter::repeat_with(|| Tachygram::random(rng))
            .take(2)
            .collect::<Vec<_>>(),
        iter::repeat_with(|| Tachygram::random(rng))
            .take(3)
            .collect::<Vec<_>>(),
    );
    let left = QrIntakeEntry {
        pcd: PROOF_SYSTEM
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &left_members),
            )
            .unwrap()
            .0,
        members: left_members.clone(),
    };
    let junction = left.pcd.data().2;
    let right = QrIntakeEntry {
        pcd: PROOF_SYSTEM
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(
                    ((), ()),
                    junction,
                    epoch,
                    discriminant,
                    &right_members,
                ),
            )
            .unwrap()
            .0,
        members: right_members.clone(),
    };
    let merge =
        |merge_rng: &mut StdRng, merge_witness, halves: (&QrIntakeEntry, &QrIntakeEntry)| {
            PROOF_SYSTEM
                .fuse(
                    merge_rng,
                    qr::QrIntakeMerge,
                    merge_witness,
                    halves.0.pcd.clone(),
                    halves.1.pcd.clone(),
                )
                .map(|(merged, ())| merged)
        };
    let honest = |halves: (&QrIntakeEntry, &QrIntakeEntry)| {
        witness::qr_intake_merge(
            (*halves.0.pcd.data(), *halves.1.pcd.data()),
            &halves.0.members,
            &halves.1.members,
        )
    };

    let merged = merge(rng, honest((&left, &right)), (&left, &right)).unwrap();
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
            right.pcd.data().2,
            discriminant,
            QrProfile::ROOT,
            union.commit()
        )
    );

    let gap = Anchor::random(rng);
    let gapped = QrIntakeEntry {
        pcd: PROOF_SYSTEM
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(((), ()), gap, epoch, discriminant, &right_members),
            )
            .unwrap()
            .0,
        members: right_members.clone(),
    };
    assert_eq!(
        merge(rng, honest((&left, &gapped)), (&left, &gapped))
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrIntakeMerge: left.anchor_end must equal right.anchor_prev",
    );
    let later = QrIntakeEntry {
        pcd: PROOF_SYSTEM
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(
                    ((), ()),
                    junction,
                    epoch.next().unwrap(),
                    discriminant,
                    &right_members,
                ),
            )
            .unwrap()
            .0,
        members: right_members.clone(),
    };
    assert_eq!(
        merge(rng, honest((&left, &later)), (&left, &later))
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrIntakeMerge: inputs cover different epochs",
    );
    let foreign = QrIntakeEntry {
        pcd: PROOF_SYSTEM
            .seed(
                rng,
                qr::QrStampIntakeSeed,
                witness::qr_stamp_intake_seed(
                    ((), ()),
                    junction,
                    epoch,
                    other_discriminant,
                    &right_members,
                ),
            )
            .unwrap()
            .0,
        members: right_members.clone(),
    };
    assert_eq!(
        merge(rng, honest((&left, &foreign)), (&left, &foreign))
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrIntakeMerge: inputs derive from different discriminants",
    );
    let (_, left_residue) = split_qr_intake(
        rng,
        QrIntakeEntry {
            pcd: left.pcd.clone(),
            members: left.members.clone(),
        },
    );
    let (right_non_residue, _) = split_qr_intake(
        rng,
        QrIntakeEntry {
            pcd: right.pcd.clone(),
            members: right.members.clone(),
        },
    );
    assert_eq!(
        merge(
            rng,
            honest((&left_residue, &right)),
            (&left_residue, &right),
        )
        .map(drop)
        .unwrap_err()
        .to_string(),
        "invalid witness: QrIntakeMerge: inputs sit at different depths",
    );
    assert_eq!(
        merge(
            rng,
            honest((&left_residue, &right_non_residue)),
            (&left_residue, &right_non_residue),
        )
        .map(drop)
        .unwrap_err()
        .to_string(),
        "invalid witness: QrIntakeMerge: inputs sit at different profiles",
    );

    let (left_contents, right_contents, merged_contents) = honest((&left, &right));
    let stranger = iter::once(Tachygram::random(rng)).collect::<TachygramSetPoly>();
    assert_eq!(
        merge(
            rng,
            (
                stranger.clone(),
                right_contents.clone(),
                merged_contents.clone(),
            ),
            (&left, &right),
        )
        .map(drop)
        .unwrap_err()
        .to_string(),
        "invalid witness: QrIntakeMerge: left contents do not match header",
    );
    assert_eq!(
        merge(
            rng,
            (left_contents.clone(), stranger, merged_contents),
            (&left, &right),
        )
        .map(drop)
        .unwrap_err()
        .to_string(),
        "invalid witness: QrIntakeMerge: right contents do not match header",
    );
    assert_eq!(
        merge(
            rng,
            (left_contents.clone(), right_contents, left_contents),
            (&left, &right),
        )
        .map(drop)
        .unwrap_err()
        .to_string(),
        "invalid witness: QrIntakeMerge: merged contents are not the union of the inputs",
    );
}

#[test]
fn bucket_seal_crosses_the_boundary() {
    let rng = &mut StdRng::seed_from_u64(0);
    let rows: [(u32, &[&[usize]], u32, usize); 2] =
        [(0, &[&[1]], 0, 1), (1, &[&[3, 3], &[2], &[1, 3]], 2, 3)];
    for (epoch_index, blocks, depth, capacity) in rows {
        let epoch = EpochIndex::new(epoch_index);
        let next = epoch.next().unwrap();
        for silent in [true, false] {
            let published_or_not = if silent { "silent" } else { "published" };
            let case = format!("epoch {epoch_index} {published_or_not}");
            let mut pool = PoolSim::genesis_with(Vec::new());
            mine_sparse(rng, &mut pool, epoch, None);
            if !silent {
                for sizes in blocks {
                    pool.mine(
                        sizes
                            .iter()
                            .map(|&size| {
                                iter::repeat_with(|| Tachygram::random(rng))
                                    .take(size)
                                    .collect()
                            })
                            .collect(),
                    );
                }
            }
            mine_sparse(rng, &mut pool, next, silent.then_some(epoch));
            let entry = pool.block(epoch.first_block()).prev;
            let final_anchor = pool.block(epoch.last_block()).anchor();
            let published = pool.block(next.first_block()).prev;
            let anchor_final_prev = epoch_index.checked_sub(1).map_or_else(
                || Anchor::from(Fp::ZERO),
                |prev| pool.block(EpochIndex::new(prev).last_block()).anchor(),
            );
            let discriminant = QrDiscriminant::random(rng);

            let (empty_intake, ()) = PROOF_SYSTEM
                .seed(
                    rng,
                    qr::QrEmptyIntakeSeed,
                    witness::qr_empty_intake_seed(((), ()), entry, epoch, discriminant),
                )
                .unwrap();
            let (empty, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    qr::QrBucketSeal,
                    witness::qr_bucket_seal((*empty_intake.data(), ()), anchor_final_prev),
                    empty_intake,
                    Proof::bootstrap().carry::<()>(()),
                )
                .unwrap();
            assert_eq!(
                *empty.data(),
                (
                    epoch,
                    entry,
                    entry.next_epoch(next).unwrap(),
                    discriminant,
                    QrProfile::ROOT,
                    iter::empty().collect::<TachygramSetPoly>().commit()
                ),
                "{case}: the empty bucket"
            );
            assert_eq!(
                empty.data().2 == published,
                silent,
                "{case}: the empty bucket's crossing"
            );

            if !silent {
                for intake in build_qr_partition(
                    rng,
                    &pool,
                    (entry, final_anchor),
                    discriminant,
                    capacity,
                    depth,
                )
                .into_iter()
                .filter(|intake| intake.pcd.data().1 == entry)
                {
                    let (_, _, anchor_end, _, profile, contents) = *intake.pcd.data();
                    let (bucket, ()) = PROOF_SYSTEM
                        .fuse(
                            rng,
                            qr::QrBucketSeal,
                            witness::qr_bucket_seal((*intake.pcd.data(), ()), anchor_final_prev),
                            intake.pcd,
                            Proof::bootstrap().carry::<()>(()),
                        )
                        .unwrap();
                    assert_eq!(
                        *bucket.data(),
                        (
                            epoch,
                            entry,
                            anchor_end.next_epoch(next).unwrap(),
                            discriminant,
                            profile,
                            contents
                        ),
                        "{case}: the bucket of {profile:?}"
                    );
                    assert_eq!(
                        bucket.data().2 == published,
                        anchor_end == final_anchor,
                        "{case}: the crossing of {profile:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn bucket_seal_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
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
    let root = |root_rng: &mut StdRng, start: Anchor| {
        build_qr_partition(root_rng, &pool, (start, end), discriminant, 24, 0)
            .pop()
            .unwrap()
            .pcd
    };
    let whole = root(rng, Anchor::default());
    let inner = root(rng, pool.block(BlockHeight(0)).anchor());
    let seal = |seal_rng: &mut StdRng, intake: &Pcd<qr::QrIntake>, anchor_final_prev: Anchor| {
        PROOF_SYSTEM
            .fuse(
                seal_rng,
                qr::QrBucketSeal,
                witness::qr_bucket_seal((*intake.data(), ()), anchor_final_prev),
                intake.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
    };
    let final_epoch = EpochIndex::new(EPOCH_MAX);
    let predecessor = Anchor::random(rng);
    let mut last_data = *whole.data();
    last_data.0 = final_epoch;
    last_data.1 = predecessor.next_epoch(final_epoch).unwrap();
    let last = whole.proof().clone().carry::<qr::QrIntake>(last_data);

    assert_eq!(
        seal(rng, &inner, Anchor::from(Fp::ZERO))
            .unwrap_err()
            .to_string(),
        "invalid witness: QrBucketSeal: witnessed boundary digest does not match intake's first anchor",
    );
    assert_eq!(
        seal(rng, &whole, predecessor).unwrap_err().to_string(),
        "invalid witness: QrBucketSeal: witnessed boundary digest does not match intake's first anchor",
    );
    assert_eq!(
        seal(rng, &last, predecessor).unwrap_err().to_string(),
        "invalid witness: QrBucketSeal: crossing past the final epoch",
    );
}

#[test]
fn unspent_init_admits_absent_values() {
    let rng = &mut StdRng::seed_from_u64(0);
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
    let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
    let crossing = end.next_epoch(epoch1).unwrap();
    let discriminant = QrDiscriminant::random(rng);
    let shallow_value = Fp::random(|bytes| rng.fill_bytes(bytes));
    let shallow_side = qr::classify(shallow_value, discriminant.at(0)).0;
    let deep_value = iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
        .take(1024)
        .find(|&value| qr::classify(value, discriminant.at(0)).0 != shallow_side)
        .unwrap();

    let root = build_qr_partition(rng, &pool, (Anchor::default(), end), discriminant, 24, 0)
        .pop()
        .expect("one root");
    let (root_seal, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness::qr_bucket_seal((*root.pcd.data(), ()), Anchor::from(Fp::ZERO)),
            root.pcd.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let root_bucket = QrBucketEntry {
        pcd: root_seal,
        members: root.members.clone(),
    };
    let (non_residue, residue) = split_qr_intake(rng, root);
    let (shallow, other_side) = if shallow_side {
        (residue, non_residue)
    } else {
        (non_residue, residue)
    };
    let (shallow_seal, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness::qr_bucket_seal((*shallow.pcd.data(), ()), Anchor::from(Fp::ZERO)),
            shallow.pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let shallow_bucket = QrBucketEntry {
        pcd: shallow_seal,
        members: shallow.members,
    };
    let deepest = u32::BITS;
    let mut deep = other_side;
    for level in deep.pcd.data().4.depth..deepest {
        let (deeper_non_residue, deeper_residue) = split_qr_intake(rng, deep);
        deep = if qr::classify(deep_value, discriminant.at(level)).0 {
            deeper_residue
        } else {
            deeper_non_residue
        };
    }
    let (deep_seal, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrBucketSeal,
            witness::qr_bucket_seal((*deep.pcd.data(), ()), Anchor::from(Fp::ZERO)),
            deep.pcd,
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let deep_bucket = QrBucketEntry {
        pcd: deep_seal,
        members: deep.members,
    };

    for (bucket, value, depth) in [
        (root_bucket, shallow_value, 0),
        (shallow_bucket, shallow_value, 1),
        (deep_bucket, deep_value, deepest),
    ] {
        assert_eq!(
            bucket.pcd.data().4,
            (0..depth).fold(QrProfile::ROOT, |profile, level| {
                profile.descend(qr::classify(value, discriminant.at(level)).0)
            }),
            "the profile at depth {depth}"
        );
        let init_witness = witness::qr_unspent_init(
            (*bucket.pcd.data(), ()),
            Nullifier::from(value).into(),
            &bucket.members,
        );
        let (segment, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                init_witness,
                bucket.pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .unwrap();
        assert_eq!(
            *segment.data(),
            (
                Anchor::default(),
                epoch0,
                NfSeqPoly::new(epoch0, &[Nullifier::from(value)]).commit(),
                epoch1,
                crossing
            ),
            "the segment at depth {depth}"
        );
    }
}

#[test]
fn unspent_init_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
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
    let bucket_for = |bucket_rng: &mut StdRng, value: Fp, depth: u32| {
        qr_bucket_at(
            bucket_rng,
            &pool,
            (Anchor::default(), end),
            (discriminant, 24, depth),
            value,
            Anchor::from(Fp::ZERO),
        )
    };
    let honest = |value: Tachygram, target: &QrBucketEntry| {
        witness::qr_unspent_init((*target.pcd.data(), ()), value, &target.members)
    };

    let nf = Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let bucket = bucket_for(rng, Fp::from(nf), 2);
    let root = bucket_for(rng, Fp::from(nf), 0);
    let witness = honest(Tachygram::from(nf), &bucket);
    let (epoch, .., profile, _) = *bucket.pcd.data();
    let other = iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
        .take(1024)
        .find(|&value| {
            (0..2).fold(QrProfile::ROOT, |value_profile, level| {
                value_profile.descend(qr::classify(value, discriminant.at(level)).0)
            }) != profile
        })
        .unwrap();

    let mut stranger_contents = witness.clone();
    stranger_contents.4 = iter::once(Tachygram::random(rng)).collect();
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                stranger_contents,
                bucket.pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrUnspentInit: contents do not match the bucket",
    );
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                honest(Tachygram::from(Fp::ZERO), &bucket),
                bucket.pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrUnspentInit: tested value is zero",
    );
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                honest(root.members[0], &root),
                root.pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrUnspentInit: found nullifier in the bucket",
    );
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                honest(Tachygram::from(other), &bucket),
                bucket.pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QR profile: value does not take the bucket's profile",
    );
    let mut shifted_root = witness.clone();
    shifted_root.1[0].1 += Fp::ONE;
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                shifted_root,
                bucket.pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QR profile: root does not square to the claimed class",
    );
    for past in [2, QrProfile::MAX_DEPTH - 1] {
        let mut flipped_class = witness.clone();
        flipped_class.1[past].0 = !flipped_class.1[past].0;
        assert_eq!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    qr::QrUnspentInit,
                    flipped_class,
                    bucket.pcd.clone(),
                    Proof::bootstrap().carry::<()>(()),
                )
                .map(drop)
                .unwrap_err()
                .to_string(),
            "invalid witness: QR profile: root does not square to the claimed class",
        );
    }

    for level in [0, 1] {
        let fixed_value = -discriminant.at(level);
        let fixed = bucket_for(rng, fixed_value, 2);
        let fixed_witness = honest(Tachygram::from(fixed_value), &fixed);
        let index = usize::try_from(level).unwrap();
        assert_eq!(
            fixed_witness.1[index],
            QrClassRoot(true, Fp::ZERO),
            "the fixed point's class root at level {level}"
        );
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                fixed_witness.clone(),
                fixed.pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .expect("the fixed point passes on the residue side");
        let mut misclassed = fixed_witness;
        misclassed.1[index].0 = false;
        assert_eq!(
            PROOF_SYSTEM
                .fuse(
                    rng,
                    qr::QrUnspentInit,
                    misclassed,
                    fixed.pcd,
                    Proof::bootstrap().carry::<()>(()),
                )
                .map(drop)
                .unwrap_err()
                .to_string(),
            "invalid witness: QR profile: exceptional discriminant claimed the non-residue class",
        );
    }

    let mut gapped_mask = witness.clone();
    gapped_mask.2 = array::from_fn(|position| position == 0 || position == 2);
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                gapped_mask,
                bucket.pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QR profile: depth mask is not a prefix",
    );
    let mut deeper_mask = witness.clone();
    deeper_mask.2 = QrProfile { depth: 3, bits: 0 }.depth_mask();
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                deeper_mask,
                bucket.pcd.clone(),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QR profile: depth mask does not match the bucket's depth",
    );
    let mut deepest_data = *bucket.pcd.data();
    deepest_data.4.depth = u32::BITS + 1;
    let mut full_mask = witness.clone();
    full_mask.2 = [true; QrProfile::MAX_DEPTH];
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                full_mask,
                bucket
                    .pcd
                    .proof()
                    .clone()
                    .carry::<qr::QrBucket>(deepest_data),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QR profile: depth mask does not match the bucket's depth",
    );
    let mut stray_bit_data = *bucket.pcd.data();
    stray_bit_data.4 = QrProfile { depth: 0, bits: 1 };
    let mut root_mask = witness.clone();
    root_mask.2 = QrProfile::ROOT.depth_mask();
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                root_mask,
                bucket
                    .pcd
                    .proof()
                    .clone()
                    .carry::<qr::QrBucket>(stray_bit_data),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QR profile: value does not take the bucket's profile",
    );
    let mut overflowing_data = *bucket.pcd.data();
    overflowing_data.4.bits |= 1 << 2;
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                witness.clone(),
                bucket
                    .pcd
                    .proof()
                    .clone()
                    .carry::<qr::QrBucket>(overflowing_data),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QR profile: value does not take the bucket's profile",
    );
    let mut last_data = *bucket.pcd.data();
    last_data.0 = EpochIndex::new(EPOCH_MAX);
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                witness.clone(),
                bucket.pcd.proof().clone().carry::<qr::QrBucket>(last_data),
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrUnspentInit: bucket has no next epoch",
    );
    let mut foreign_sequence = witness;
    foreign_sequence.3 = NfSeqPoly::new(epoch, &[Nullifier::from(other)]);
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                foreign_sequence,
                bucket.pcd,
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrUnspentInit: sequence does not match the tested pair",
    );
}

#[test]
fn unspent_init_binds_the_value() {
    let rng = &mut StdRng::seed_from_u64(0);
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
    let nf = Nullifier::from(Fp::random(|bytes| rng.fill_bytes(bytes)));
    let root = qr_bucket_at(
        rng,
        &pool,
        (Anchor::default(), end),
        (discriminant, 24, 0),
        Fp::from(nf),
        Anchor::from(Fp::ZERO),
    );
    let epoch = root.pcd.data().0;
    let witness =
        witness::qr_unspent_init((*root.pcd.data(), ()), Tachygram::from(nf), &root.members);

    // The witness is solved against a challenge that omits the value.
    let challenge = unpinned_challenge(&[witness.3.commit().into()]);
    // A member whose factor (m + (i+1)X)^3 - 2 matches the nullifier's at the
    // challenge.
    let shift = (Fp::from(u64::from(epoch)) + Fp::ONE) * challenge;
    let twin = (Fp::ZETA * (Fp::from(nf) + shift)) - shift;
    assert_eq!(
        NfSeqPoly::new(epoch, &[Nullifier::from(twin)]).eval(challenge),
        witness.3.eval(challenge)
    );
    let mut twinned = witness;
    twinned.0 = Tachygram::from(twin);
    twinned.1 = QrClassRoot::along(twin, discriminant);
    assert_eq!(
        PROOF_SYSTEM
            .fuse(
                rng,
                qr::QrUnspentInit,
                twinned,
                root.pcd,
                Proof::bootstrap().carry::<()>(()),
            )
            .map(drop)
            .unwrap_err()
            .to_string(),
        "invalid witness: QrUnspentInit: sequence does not match the tested pair",
    );
}
