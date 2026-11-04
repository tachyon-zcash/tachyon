extern crate alloc;

use alloc::vec::Vec;
use core::{array, iter};

use ragu::{Pcd, Proof};
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field as _;
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrInterpolantPoly,
    QrProfile, QrQuotientPoly, Tachygram, TachygramSetPoly,
    constants::EPOCH_MAX,
    nullifier::Nullifier,
    pasta::Fp,
    stamp::proof::{PROOF_SYSTEM, qr, summary},
    witness,
};

use crate::fixtures::{
    PoolSim, QrBucketEntry, QrIntakeEntry, assert_rejected, build_qr_partition, cube_root_twin,
    mine_sparse, qr_bucket_at, qr_bucket_segment, qr_profile_of, recarry, seal_qr_intake,
    seed_qr_empty_intake, small_epoch, split_qr_intake, tachygrams, unpinned_challenge,
};

fn altered<T: Clone>(value: &T, alter: impl FnOnce(&mut T)) -> T {
    let mut altered = value.clone();
    alter(&mut altered);
    altered
}

fn set(members: &[Tachygram]) -> TachygramSetPoly {
    members.iter().copied().collect()
}

fn stamp_intake(
    rng: &mut StdRng,
    anchor_prev: Anchor,
    epoch: EpochIndex,
    discriminant: QrDiscriminant,
    members: &[Tachygram],
) -> QrIntakeEntry {
    let witness =
        witness::qr_stamp_intake_seed(((), ()), anchor_prev, epoch, discriminant, members);
    let (pcd, ()) = PROOF_SYSTEM
        .seed(rng, qr::QrStampIntakeSeed, witness)
        .expect("QrStampIntakeSeed");
    QrIntakeEntry {
        pcd,
        members: members.to_vec(),
    }
}

fn descend_along(
    rng: &mut StdRng,
    mut intake: QrIntakeEntry,
    value: Fp,
    depth: u32,
) -> QrIntakeEntry {
    let (.., discriminant, profile, _) = *intake.pcd.data();
    for level in profile.depth..depth {
        let (non_residue, residue) = split_qr_intake(rng, intake);
        intake = if qr::classify(value, discriminant.at(level)).0 {
            residue
        } else {
            non_residue
        };
    }
    intake
}

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

fn split(
    rng: &mut StdRng,
    split_witness: (TachygramSetPoly, TachygramSetPoly, TachygramSetPoly),
    parent: &Pcd<qr::QrIntake>,
) -> ragu_core::Result<Pcd<qr::QrIntakeSides>> {
    PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrIntakeSplit,
            split_witness,
            parent.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .map(|(sides, ())| sides)
}

fn descend(
    rng: &mut StdRng,
    descend_witness: (bool, TachygramSetPoly, QrInterpolantPoly, QrQuotientPoly),
    sides: &Pcd<qr::QrIntakeSides>,
) -> ragu_core::Result<Pcd<qr::QrIntake>> {
    PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrSideDescend,
            descend_witness,
            sides.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .map(|(child, ())| child)
}

fn unspent_init(
    rng: &mut StdRng,
    bucket: &Pcd<qr::QrBucket>,
    init_witness: (
        Tachygram,
        [QrClassRoot; QrProfile::MAX_DEPTH],
        [bool; QrProfile::MAX_DEPTH],
        NfSeqPoly,
        TachygramSetPoly,
    ),
) -> ragu_core::Result<()> {
    PROOF_SYSTEM
        .fuse(
            rng,
            qr::QrUnspentInit,
            init_witness,
            bucket.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .map(drop)
}

#[test]
fn intakes_root_on_summaries_and_stamps() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (epoch_index, size) in [(0, 1), (EPOCH_MAX, 6)] {
        let epoch = EpochIndex::new(epoch_index);
        let case = format!("{size} tachygrams at epoch {epoch:?}");
        let start = Anchor::random(rng);
        let discriminant = QrDiscriminant::random(rng);
        let members = tachygrams(rng, size);
        let contents = set(&members).commit();
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
        let stamp_root = stamp_intake(rng, start, epoch, discriminant, &members);
        assert_eq!(
            *stamp_root.pcd.data(),
            *root.data(),
            "{case}: the stamp's root"
        );

        let empty = seed_qr_empty_intake(rng, start, epoch, discriminant);
        assert_eq!(
            *empty.pcd.data(),
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
    assert_rejected(empty_stamp.map(drop), "invalid anchor step");
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
            pool.mine(sizes.iter().map(|&size| tachygrams(rng, size)).collect());
        }
        let end = pool.anchor();
        let stamps: Vec<Vec<Tachygram>> = (0..=pool.height().0)
            .flat_map(|height| pool.block(BlockHeight(height)).tachygrams())
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
                set(&intake.members).commit(),
                "{case}: the contents"
            );
            for &member in &intake.members {
                assert_eq!(
                    qr_profile_of(Fp::from(member), discriminant, depth),
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
    let intake = stamp_intake(rng, start, epoch, discriminant, &members);

    let honest = witness::qr_intake_split((*intake.pcd.data(), ()), &members);
    let sides = split(rng, honest.clone(), &intake.pcd).unwrap();
    assert_eq!(
        *sides.data(),
        (
            epoch,
            start,
            intake.pcd.data().2,
            discriminant,
            QrProfile::ROOT,
            set(&non_residue).commit(),
            set(&residue_class).commit()
        )
    );
    let (contents, honest_non_residue, honest_residue) = honest;
    let strangers = set(&tachygrams(rng, 2));
    assert_rejected(
        split(
            rng,
            (strangers, honest_non_residue.clone(), honest_residue),
            &intake.pcd,
        )
        .map(drop),
        "QrIntakeSplit: contents do not match header",
    );
    assert_rejected(
        split(
            rng,
            (
                contents.clone(),
                honest_non_residue.clone(),
                honest_non_residue,
            ),
            &intake.pcd,
        )
        .map(drop),
        "QrIntakeSplit: the sides do not partition the contents",
    );
    let misfiled = (
        contents,
        non_residue.iter().copied().chain([exceptional]).collect(),
        set(&residue),
    );
    assert_rejected(
        split(rng, misfiled, &intake.pcd).map(drop),
        "QrIntakeSplit: exceptional value claimed the non-residue class",
    );

    let deepest = Tachygram::from(-discriminant.at(u32::BITS - 1));
    let deep = recarry(&intake.pcd, |data| {
        data.4 = QrProfile {
            depth: u32::BITS - 1,
            bits: 0,
        };
        data.5 = set(&[deepest]).commit();
    });
    assert_rejected(
        split(rng, (set(&[deepest]), set(&[deepest]), set(&[])), &deep).map(drop),
        "QrIntakeSplit: exceptional value claimed the non-residue class",
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
    let intake = stamp_intake(rng, start, epoch, discriminant, &members);
    let anchor_end = intake.pcd.data().2;
    let honest = witness::qr_intake_split((*intake.pcd.data(), ()), &members);
    let contents = honest.0.clone();
    let sides = split(rng, honest, &intake.pcd).unwrap();
    let residue_child = witness::qr_side_descend((*sides.data(), ()), &members, true);
    let non_residue_child = witness::qr_side_descend((*sides.data(), ()), &members, false);

    let smuggled = residue[0];
    let padded: Vec<Tachygram> = non_residue.iter().copied().chain([smuggled]).collect();
    let short: Vec<Tachygram> = residue_class
        .iter()
        .copied()
        .filter(|&member| member != smuggled)
        .collect();
    let misfiled = split(rng, (contents, set(&padded), set(&short)), &intake.pcd).unwrap();
    let (_, _, short_interpolant, short_quotient) =
        witness::qr_side_descend((*misfiled.data(), ()), &members, true);
    let unsmuggled: Vec<Tachygram> = members
        .iter()
        .copied()
        .filter(|&member| member != smuggled)
        .collect();
    let impure = descend(
        rng,
        witness::qr_side_descend((*misfiled.data(), ()), &unsmuggled, false),
        &misfiled,
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
            set(&padded).commit()
        )
    );

    assert_rejected(
        descend(
            rng,
            (
                true,
                non_residue_child.1.clone(),
                residue_child.2.clone(),
                residue_child.3.clone(),
            ),
            &sides,
        )
        .map(drop),
        "QrSideDescend: sibling does not match the header",
    );
    assert_rejected(
        descend(
            rng,
            (
                true,
                residue_child.1.clone(),
                non_residue_child.2.clone(),
                residue_child.3.clone(),
            ),
            &sides,
        )
        .map(drop),
        "QrSideDescend: the sibling fails its class decomposition",
    );
    assert_rejected(
        descend(
            rng,
            (
                false,
                non_residue_child.1.clone(),
                residue_child.2.clone(),
                non_residue_child.3.clone(),
            ),
            &sides,
        )
        .map(drop),
        "QrSideDescend: the sibling fails its class decomposition",
    );
    assert_rejected(
        descend(
            rng,
            (
                true,
                residue_child.1.clone(),
                residue_child.2.clone(),
                non_residue_child.3.clone(),
            ),
            &sides,
        )
        .map(drop),
        "QrSideDescend: the sibling fails its class decomposition",
    );
    assert_rejected(
        descend(
            rng,
            (
                false,
                non_residue_child.1,
                non_residue_child.2,
                residue_child.3.clone(),
            ),
            &sides,
        )
        .map(drop),
        "QrSideDescend: the sibling fails its class decomposition",
    );
    assert_rejected(
        descend(
            rng,
            (true, set(&padded), short_interpolant, short_quotient),
            &misfiled,
        )
        .map(drop),
        "QrSideDescend: the sibling fails its class decomposition",
    );

    let spent = recarry(&sides, |data| {
        data.4 = QrProfile {
            depth: u32::BITS,
            bits: 0,
        };
    });
    assert_rejected(
        descend(rng, residue_child, &spent).map(drop),
        "QrSideDescend: profile has no bit left for another side",
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
    let sibling = set(&members);
    let intake = stamp_intake(rng, start, epoch, discriminant, &members);
    let sides = split(
        rng,
        witness::qr_intake_split((*intake.pcd.data(), ()), &members),
        &intake.pcd,
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

    let solved_intake = stamp_intake(rng, start, epoch, solved, &members);
    let solved_sides = split(
        rng,
        (sibling.clone(), set(&[]), sibling.clone()),
        &solved_intake.pcd,
    )
    .expect("the split's product does not read the discriminant");
    assert_rejected(
        descend(rng, (false, sibling, interpolant, quotient), &solved_sides).map(drop),
        "QrSideDescend: the sibling fails its class decomposition",
    );
}

#[test]
fn intake_merge_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let epoch = EpochIndex::new(0);
    let start = Anchor::random(rng);
    let [discriminant, other_discriminant] = [(); 2].map(|()| QrDiscriminant::random(rng));
    let (left_members, right_members) = (tachygrams(rng, 2), tachygrams(rng, 3));
    let left = stamp_intake(rng, start, epoch, discriminant, &left_members);
    let junction = left.pcd.data().2;
    let right = stamp_intake(rng, junction, epoch, discriminant, &right_members);
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
    let gapped = stamp_intake(rng, gap, epoch, discriminant, &right_members);
    assert_rejected(
        merge(rng, honest((&left, &gapped)), (&left, &gapped)).map(drop),
        "QrIntakeMerge: left.anchor_end must equal right.anchor_prev",
    );
    let later = stamp_intake(
        rng,
        junction,
        epoch.next().unwrap(),
        discriminant,
        &right_members,
    );
    assert_rejected(
        merge(rng, honest((&left, &later)), (&left, &later)).map(drop),
        "QrIntakeMerge: inputs cover different epochs",
    );
    let foreign = stamp_intake(rng, junction, epoch, other_discriminant, &right_members);
    assert_rejected(
        merge(rng, honest((&left, &foreign)), (&left, &foreign)).map(drop),
        "QrIntakeMerge: inputs derive from different discriminants",
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
    assert_rejected(
        merge(
            rng,
            honest((&left_residue, &right)),
            (&left_residue, &right),
        )
        .map(drop),
        "QrIntakeMerge: inputs sit at different depths",
    );
    assert_rejected(
        merge(
            rng,
            honest((&left_residue, &right_non_residue)),
            (&left_residue, &right_non_residue),
        )
        .map(drop),
        "QrIntakeMerge: inputs sit at different profiles",
    );

    let (left_contents, right_contents, merged_contents) = honest((&left, &right));
    let stranger = set(&tachygrams(rng, 1));
    assert_rejected(
        merge(
            rng,
            (
                stranger.clone(),
                right_contents.clone(),
                merged_contents.clone(),
            ),
            (&left, &right),
        )
        .map(drop),
        "QrIntakeMerge: left contents do not match header",
    );
    assert_rejected(
        merge(
            rng,
            (left_contents.clone(), stranger, merged_contents),
            (&left, &right),
        )
        .map(drop),
        "QrIntakeMerge: right contents do not match header",
    );
    assert_rejected(
        merge(
            rng,
            (left_contents.clone(), right_contents, left_contents),
            (&left, &right),
        )
        .map(drop),
        "QrIntakeMerge: merged contents are not the union of the inputs",
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
                    pool.mine(sizes.iter().map(|&size| tachygrams(rng, size)).collect());
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

            let empty_intake = seed_qr_empty_intake(rng, entry, epoch, discriminant);
            let empty = seal_qr_intake(rng, empty_intake, anchor_final_prev);
            assert_eq!(
                *empty.pcd.data(),
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
                empty.pcd.data().2 == published,
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
                    let bucket = seal_qr_intake(rng, intake, anchor_final_prev);
                    assert_eq!(
                        *bucket.pcd.data(),
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
                        bucket.pcd.data().2 == published,
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
    let (pool, end) = small_epoch(rng);
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
    let last = recarry(&whole, |data| {
        data.0 = final_epoch;
        data.1 = predecessor.next_epoch(final_epoch).unwrap();
    });

    assert_rejected(
        seal(rng, &inner, Anchor::from(Fp::ZERO)),
        "QrBucketSeal: witnessed boundary digest does not match intake's first anchor",
    );
    assert_rejected(
        seal(rng, &whole, predecessor),
        "QrBucketSeal: witnessed boundary digest does not match intake's first anchor",
    );
    assert_rejected(
        seal(rng, &last, predecessor),
        "QrBucketSeal: crossing past the final epoch",
    );
}

#[test]
fn unspent_init_admits_absent_values() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, end) = small_epoch(rng);
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
    let root_bucket = seal_qr_intake(
        rng,
        QrIntakeEntry {
            pcd: root.pcd.clone(),
            members: root.members.clone(),
        },
        Anchor::from(Fp::ZERO),
    );
    let (non_residue, residue) = split_qr_intake(rng, root);
    let (shallow, other_side) = if shallow_side {
        (residue, non_residue)
    } else {
        (non_residue, residue)
    };
    let shallow_bucket = seal_qr_intake(rng, shallow, Anchor::from(Fp::ZERO));
    let deepest = u32::BITS;
    let deep = descend_along(rng, other_side, deep_value, deepest);
    let deep_bucket = seal_qr_intake(rng, deep, Anchor::from(Fp::ZERO));

    for (bucket, value, depth) in [
        (root_bucket, shallow_value, 0),
        (shallow_bucket, shallow_value, 1),
        (deep_bucket, deep_value, deepest),
    ] {
        assert_eq!(
            bucket.pcd.data().4,
            qr_profile_of(value, discriminant, depth),
            "the profile at depth {depth}"
        );
        let segment = qr_bucket_segment(rng, &bucket, |_| Nullifier::from(value));
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
    let (pool, end) = small_epoch(rng);
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
        .find(|&value| qr_profile_of(value, discriminant, 2) != profile)
        .unwrap();

    let stranger = set(&tachygrams(rng, 1));
    assert_rejected(
        unspent_init(
            rng,
            &bucket.pcd,
            altered(&witness, |forged| forged.4 = stranger),
        ),
        "QrUnspentInit: contents do not match the bucket",
    );
    assert_rejected(
        unspent_init(rng, &bucket.pcd, honest(Tachygram::from(Fp::ZERO), &bucket)),
        "QrUnspentInit: tested value is zero",
    );
    assert_rejected(
        unspent_init(rng, &root.pcd, honest(root.members[0], &root)),
        "QrUnspentInit: found nullifier in the bucket",
    );
    assert_rejected(
        unspent_init(rng, &bucket.pcd, honest(Tachygram::from(other), &bucket)),
        "QR profile: value does not take the bucket's profile",
    );
    assert_rejected(
        unspent_init(
            rng,
            &bucket.pcd,
            altered(&witness, |forged| forged.1[0].1 += Fp::ONE),
        ),
        "QR profile: root does not square to the claimed class",
    );
    for past in [2, QrProfile::MAX_DEPTH - 1] {
        assert_rejected(
            unspent_init(
                rng,
                &bucket.pcd,
                altered(&witness, |forged| forged.1[past].0 = !forged.1[past].0),
            ),
            "QR profile: root does not square to the claimed class",
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
        unspent_init(rng, &fixed.pcd, fixed_witness.clone())
            .expect("the fixed point passes on the residue side");
        assert_rejected(
            unspent_init(
                rng,
                &fixed.pcd,
                altered(&fixed_witness, |forged| forged.1[index].0 = false),
            ),
            "QR profile: exceptional discriminant claimed the non-residue class",
        );
    }

    assert_rejected(
        unspent_init(
            rng,
            &bucket.pcd,
            altered(&witness, |forged| {
                forged.2 = array::from_fn(|position| position == 0 || position == 2);
            }),
        ),
        "QR profile: depth mask is not a prefix",
    );
    assert_rejected(
        unspent_init(
            rng,
            &bucket.pcd,
            altered(&witness, |forged| {
                forged.2 = QrProfile { depth: 3, bits: 0 }.depth_mask();
            }),
        ),
        "QR profile: depth mask does not match the bucket's depth",
    );
    let deepest = recarry(&bucket.pcd, |data| data.4.depth = u32::BITS + 1);
    assert_rejected(
        unspent_init(
            rng,
            &deepest,
            altered(&witness, |forged| {
                forged.2 = [true; QrProfile::MAX_DEPTH];
            }),
        ),
        "QR profile: depth mask does not match the bucket's depth",
    );
    let stray_bit = recarry(&bucket.pcd, |data| data.4 = QrProfile { depth: 0, bits: 1 });
    assert_rejected(
        unspent_init(
            rng,
            &stray_bit,
            altered(&witness, |forged| {
                forged.2 = QrProfile::ROOT.depth_mask();
            }),
        ),
        "QR profile: value does not take the bucket's profile",
    );
    let overflowing = recarry(&bucket.pcd, |data| data.4.bits |= 1 << 2);
    assert_rejected(
        unspent_init(rng, &overflowing, witness.clone()),
        "QR profile: value does not take the bucket's profile",
    );
    let last = recarry(&bucket.pcd, |data| data.0 = EpochIndex::new(EPOCH_MAX));
    assert_rejected(
        unspent_init(rng, &last, witness.clone()),
        "QrUnspentInit: bucket has no next epoch",
    );
    assert_rejected(
        unspent_init(
            rng,
            &bucket.pcd,
            altered(&witness, |forged| {
                forged.3 = NfSeqPoly::new(epoch, &[Nullifier::from(other)]);
            }),
        ),
        "QrUnspentInit: sequence does not match the tested pair",
    );
}

#[test]
fn unspent_init_binds_the_value() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (pool, end) = small_epoch(rng);
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
    let twin = cube_root_twin(epoch, Fp::from(nf), challenge);
    assert_eq!(
        NfSeqPoly::new(epoch, &[Nullifier::from(twin)]).eval(challenge),
        witness.3.eval(challenge)
    );
    assert_rejected(
        unspent_init(
            rng,
            &root.pcd,
            altered(&witness, |forged| {
                forged.0 = Tachygram::from(twin);
                forged.1 = QrClassRoot::along(twin, discriminant);
            }),
        ),
        "QrUnspentInit: sequence does not match the tested pair",
    );
}
