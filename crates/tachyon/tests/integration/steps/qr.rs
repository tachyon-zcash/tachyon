//! QR routing: `QrSummaryIntake`, `QrStampIntakeSeed`, `QrEmptyIntakeSeed`,
//! `QrIntakeMerge`, `QrIntakeSplit`, `QrSideDescend`, `QrBucketSeal` and
//! `QrUnspentInit`.
//!
//! Some corruptions recarry an honest proof under an altered header. Mock
//! ragu does not authenticate a header against its proof, so the step's own
//! constraint is what rejects them; a real proof would not carry the altered
//! header at all.

extern crate alloc;

use alloc::vec::Vec;
use core::{array, iter};

use ff::{Field as _, PrimeField as _};
use pasta_curves::Fp;
use proptest::{collection::vec, prelude::*, sample::Index};
use ragu::{Pcd, Proof};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    Anchor, BlockHeight, EpochIndex, NfSeqPoly, QrClassRoot, QrDiscriminant, QrProfile, Tachygram,
    TachygramSetPoly,
    constants::EPOCH_MAX,
    nullifier::Nullifier,
    stamp::proof::{PROOF_SYSTEM, qr, spendable, summary},
    witness,
};

use crate::{
    fixtures::{
        PoolSim, QrBucketEntry, QrIntakeEntry, WalletSim, build_qr_partition, cube_root_twin,
        indexed_factor, mine_sparse, qr_bucket_at, qr_bucket_segment, qr_epoch_unspent,
        qr_profile_of, random_block, random_block_with, recarry, seal_qr_intake,
        seed_qr_empty_intake, shared_sk, small_epoch, split_qr_intake, unpinned_challenge,
    },
    strategies::{assert_rejections, check, epoch, tachygrams},
};

/// `value` with `alter` applied.
fn altered<T: Clone>(value: &T, alter: impl FnOnce(&mut T)) -> T {
    let mut altered = value.clone();
    alter(&mut altered);
    altered
}

/// The root intake over one stamp of `members`.
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

/// `intake` split level by level down to `depth`, keeping `value`'s side.
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

/// A root intake over a summary carries the summary's epoch, span and
/// contents at depth zero under any discriminant, and one rooted on a single
/// stamp is the root over that stamp's summary. An empty intake runs from its
/// anchor to itself and holds nothing. An empty stamp roots no intake.
#[test]
fn intakes_root_on_summaries_and_stamps() {
    let strategy = (any::<u64>(), epoch(), 1usize..=6);
    check(64, strategy, |(seed, epoch, size)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let start = Anchor::from(Fp::random(&mut *rng));
        let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
        let members = tachygrams(rng, size);
        let contents = members
            .iter()
            .copied()
            .collect::<TachygramSetPoly>()
            .commit();
        let end = start
            .next_stamp(epoch, &contents)
            .expect("a nonempty stamp folds");

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
                Proof::trivial().carry::<()>(()),
            )
            .expect("QrSummaryIntake");
        prop_assert_eq!(
            *root.data(),
            (epoch, start, end, discriminant, QrProfile::ROOT, contents)
        );
        let stamp_root = stamp_intake(rng, start, epoch, discriminant, &members);
        prop_assert_eq!(*stamp_root.pcd.data(), *root.data());

        let empty = seed_qr_empty_intake(rng, start, epoch, discriminant);
        prop_assert_eq!(
            *empty.pcd.data(),
            (
                epoch,
                start,
                start,
                discriminant,
                QrProfile::ROOT,
                iter::empty().collect::<TachygramSetPoly>().commit()
            )
        );

        let empty_stamp = PROOF_SYSTEM.seed(
            rng,
            qr::QrStampIntakeSeed,
            witness::qr_stamp_intake_seed(((), ()), start, epoch, discriminant, &[]),
        );
        assert_rejections([(
            "an empty stamp",
            empty_stamp.map(drop),
            "invalid anchor step",
        )]);
        Ok(())
    });
}

/// Routing an epoch's tachygrams to any depth over intakes of any capacity
/// leaves each profile of that depth as a run of intakes from the span's
/// start to its end, adjacent and merged as far as the capacity allows, none
/// past the capacity unless one stamp is. Each intake commits exactly the
/// members it holds, each member's side at every level is its intake's path,
/// and together the intakes hold every published tachygram once, a run of
/// consecutive values and a value exceptional at one level included.
#[test]
fn partition_routes_every_member_by_profile() {
    let strategy = (
        any::<u64>(),
        vec(vec(1usize..=3, 1..=2), 1..=4),
        0u64..=8,
        0u32..=3,
        1usize..=24,
        any::<Index>(),
    );
    check(
        32,
        strategy,
        |(seed, blocks, consecutive, depth, capacity, split)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
            let base = Fp::random(&mut *rng);
            let level = u32::try_from(split.index(usize::try_from(depth.max(1)).unwrap())).unwrap();
            let special: Vec<Tachygram> = (0..consecutive)
                .map(|offset| Tachygram::from(base + Fp::from(offset)))
                .chain([Tachygram::from(-discriminant.at(level))])
                .collect();
            let mut pool = PoolSim::genesis_with([special].to_vec());
            for sizes in &blocks {
                pool.mine(sizes.iter().map(|&size| tachygrams(rng, size)).collect());
            }
            let end = pool.anchor();
            let stamps: Vec<Vec<Tachygram>> = (0..=pool.height().0)
                .flat_map(|height| pool.block(BlockHeight(height)).tachygrams())
                .collect();
            let largest = stamps.iter().map(Vec::len).max().expect("a stamp");

            let routed = build_qr_partition(
                rng,
                &pool,
                (Anchor::default(), end),
                discriminant,
                capacity,
                depth,
            );
            for intake in &routed {
                let (intake_epoch, _, _, intake_discriminant, profile, contents) =
                    *intake.pcd.data();
                prop_assert_eq!(intake_epoch, EpochIndex::new(0));
                prop_assert_eq!(intake_discriminant, discriminant);
                prop_assert_eq!(profile.depth, depth);
                prop_assert!(intake.members.len() <= capacity.max(largest));
                prop_assert_eq!(
                    contents,
                    intake
                        .members
                        .iter()
                        .copied()
                        .collect::<TachygramSetPoly>()
                        .commit()
                );
                for &member in &intake.members {
                    prop_assert_eq!(
                        qr_profile_of(Fp::from(member), discriminant, depth),
                        profile
                    );
                }
            }
            for bits in 0..1u32 << depth {
                let run: Vec<&QrIntakeEntry> = routed
                    .iter()
                    .filter(|intake| intake.pcd.data().4 == QrProfile { depth, bits })
                    .collect();
                let mut cursor = Anchor::default();
                for intake in &run {
                    prop_assert_eq!(intake.pcd.data().1, cursor);
                    cursor = intake.pcd.data().2;
                }
                prop_assert_eq!(cursor, end);
                for (left, right) in run.iter().zip(run.iter().skip(1)) {
                    prop_assert!(left.members.len() + right.members.len() > capacity);
                }
            }

            let sorted = |mut members: Vec<Tachygram>| {
                members.sort_unstable_by_key(|&member| Fp::from(member).to_repr());
                members
            };
            let held = routed
                .iter()
                .flat_map(|intake| intake.members.iter().copied())
                .collect();
            prop_assert_eq!(sorted(held), sorted(stamps.concat()));
            Ok(())
        },
    );
}

/// An honest split of an intake on any path emits each class of its members
/// as its own set. `QrIntakeSplit` refuses contents other than the header's,
/// sides that do not partition them, and the value exceptional at the
/// intake's depth on the non-residue side, at depth 31 too. `QrSideDescend`
/// refuses a sibling other than the header's, the other side's interpolant
/// or quotient for either child, a child short of a member its sibling holds,
/// a discriminant solved after the challenge, and a profile with no bit left.
/// A child padded with a member of its sibling's class is extracted with the
/// stray member.
#[test]
fn split_and_descend_reject_corruptions() {
    let strategy = (any::<u64>(), epoch(), 0u32..=2, 2usize..=4);
    check(12, strategy, |(seed, epoch, depth, per_side)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let start = Anchor::from(Fp::random(&mut *rng));
        let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
        let exceptional = Tachygram::from(-discriminant.at(depth));
        let path = qr_profile_of(Fp::from(exceptional), discriminant, depth);
        let (mut residue, mut non_residue) = (Vec::new(), Vec::new());
        while residue.len() < per_side || non_residue.len() < per_side {
            let candidate = Fp::random(&mut *rng);
            let class = if qr::classify(candidate, discriminant.at(depth)).0 {
                &mut residue
            } else {
                &mut non_residue
            };
            if class.len() < per_side && qr_profile_of(candidate, discriminant, depth) == path {
                class.push(Tachygram::from(candidate));
            }
        }
        let residue_class: Vec<Tachygram> = residue.iter().copied().chain([exceptional]).collect();
        let members: Vec<Tachygram> = residue_class.iter().chain(&non_residue).copied().collect();
        let set = |tgs: &[Tachygram]| tgs.iter().copied().collect::<TachygramSetPoly>();

        let root = stamp_intake(rng, start, epoch, discriminant, &members);
        let intake = descend_along(rng, root, Fp::from(exceptional), depth);
        let anchor_end = intake.pcd.data().2;
        let split = |split_rng: &mut StdRng, split_witness, parent: &Pcd<qr::QrIntake>| {
            PROOF_SYSTEM
                .fuse(
                    split_rng,
                    qr::QrIntakeSplit,
                    split_witness,
                    parent.clone(),
                    Proof::trivial().carry::<()>(()),
                )
                .map(|(sides, ())| sides)
        };
        let descend =
            |descend_rng: &mut StdRng, descend_witness, sides: &Pcd<qr::QrIntakeSides>| {
                PROOF_SYSTEM
                    .fuse(
                        descend_rng,
                        qr::QrSideDescend,
                        descend_witness,
                        sides.clone(),
                        Proof::trivial().carry::<()>(()),
                    )
                    .map(|(child, ())| child)
            };

        let honest = witness::qr_intake_split((*intake.pcd.data(), ()), &members);
        let sides = split(rng, honest.clone(), &intake.pcd).expect("QrIntakeSplit");
        prop_assert_eq!(
            *sides.data(),
            (
                epoch,
                start,
                anchor_end,
                discriminant,
                path,
                set(&non_residue).commit(),
                set(&residue_class).commit()
            )
        );
        let (contents, honest_non_residue, honest_residue) = honest;
        let misfiled_exceptional = (
            contents.clone(),
            non_residue.iter().copied().chain([exceptional]).collect(),
            set(&residue),
        );
        let [non_residue_child, residue_child] =
            [false, true].map(|bit| witness::qr_side_descend((*sides.data(), ()), &members, bit));

        let smuggled = residue[0];
        let padded: Vec<Tachygram> = non_residue.iter().copied().chain([smuggled]).collect();
        let short: Vec<Tachygram> = residue_class
            .iter()
            .copied()
            .filter(|&member| member != smuggled)
            .collect();
        let misfiled = split(
            rng,
            (contents.clone(), set(&padded), set(&short)),
            &intake.pcd,
        )
        .expect("the split's product holds for a misfiled member");
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
        .expect("an impure child is complete for its class");
        prop_assert_eq!(
            *impure.data(),
            (
                epoch,
                start,
                anchor_end,
                discriminant,
                path.descend(false),
                set(&padded).commit()
            )
        );

        let (_, _, interpolant, quotient) = non_residue_child.clone();
        let sibling = set(&members);
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
        let solved_root = stamp_intake(rng, start, epoch, solved, &members);
        let solved_sides = split(
            rng,
            (contents.clone(), set(&[]), sibling.clone()),
            &solved_root.pcd,
        )
        .expect("the split's product does not read the discriminant");

        let deep_value = Tachygram::from(-discriminant.at(31));
        let deep_root = stamp_intake(rng, start, epoch, discriminant, &[deep_value]);
        let deep = descend_along(rng, deep_root, Fp::from(deep_value), 31);
        let deep_misfiled = split(
            rng,
            (set(&[deep_value]), set(&[deep_value]), set(&[])),
            &deep.pcd,
        );
        let (_, register) = split_qr_intake(rng, deep);
        let register_sides = split(
            rng,
            witness::qr_intake_split((*register.pcd.data(), ()), &register.members),
            &register.pcd,
        )
        .expect("QrIntakeSplit at the maximum depth");
        let full = descend(
            rng,
            witness::qr_side_descend((*register_sides.data(), ()), &register.members, true),
            &register_sides,
        );

        let strangers = tachygrams(rng, 2);

        assert_rejections([
            (
                "contents other than the header's",
                split(
                    rng,
                    (set(&strangers), honest_non_residue.clone(), honest_residue),
                    &intake.pcd,
                )
                .map(drop),
                "QrIntakeSplit: contents do not match header",
            ),
            (
                "one side twice",
                split(
                    rng,
                    (contents, honest_non_residue.clone(), honest_non_residue),
                    &intake.pcd,
                )
                .map(drop),
                "QrIntakeSplit: the sides do not partition the contents",
            ),
            (
                "the exceptional value on the non-residue side",
                split(rng, misfiled_exceptional, &intake.pcd).map(drop),
                "QrIntakeSplit: exceptional value claimed the non-residue class",
            ),
            (
                "the exceptional value on the non-residue side at depth 31",
                deep_misfiled.map(drop),
                "QrIntakeSplit: exceptional value claimed the non-residue class",
            ),
            (
                "a sibling other than the header's",
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
            ),
            (
                "the other side's interpolant for the residue child",
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
            ),
            (
                "the other side's interpolant for the non-residue child",
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
            ),
            (
                "the other side's quotient for the residue child",
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
            ),
            (
                "the other side's quotient for the non-residue child",
                descend(
                    rng,
                    (
                        false,
                        non_residue_child.1,
                        non_residue_child.2,
                        residue_child.3,
                    ),
                    &sides,
                )
                .map(drop),
                "QrSideDescend: the sibling fails its class decomposition",
            ),
            (
                "a child short of a member its sibling holds",
                descend(
                    rng,
                    (true, set(&padded), short_interpolant, short_quotient),
                    &misfiled,
                )
                .map(drop),
                "QrSideDescend: the sibling fails its class decomposition",
            ),
            (
                "a discriminant solved after the challenge",
                descend(rng, (false, sibling, interpolant, quotient), &solved_sides).map(drop),
                "QrSideDescend: the sibling fails its class decomposition",
            ),
            (
                "a profile with no bit left",
                full.map(drop),
                "QrSideDescend: profile has no bit left for another side",
            ),
        ]);
        Ok(())
    });
}

/// An honest merge of two adjacent intakes of one profile spans both and
/// holds their union. `QrIntakeMerge` refuses inputs of different epochs,
/// discriminants, depths or sides, inputs with a gap between them, contents
/// other than either header's, and a merged set other than the union.
#[test]
fn intake_merge_rejects_corruptions() {
    let strategy = (any::<u64>(), 0..EPOCH_MAX, 1usize..=4, 1usize..=4);
    check(
        32,
        strategy,
        |(seed, epoch_index, left_size, right_size)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let epoch = EpochIndex::new(epoch_index);
            let start = Anchor::from(Fp::random(&mut *rng));
            let [discriminant, other_discriminant] =
                [(); 2].map(|()| QrDiscriminant::from(Fp::random(&mut *rng)));
            let (left_members, right_members) =
                (tachygrams(rng, left_size), tachygrams(rng, right_size));
            let left = stamp_intake(rng, start, epoch, discriminant, &left_members);
            let junction = left.pcd.data().2;
            let right = stamp_intake(rng, junction, epoch, discriminant, &right_members);
            let merge = |merge_rng: &mut StdRng,
                         merge_witness,
                         halves: (&QrIntakeEntry, &QrIntakeEntry)| {
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

            let merged =
                merge(rng, honest((&left, &right)), (&left, &right)).expect("QrIntakeMerge");
            let union = left_members
                .iter()
                .chain(&right_members)
                .copied()
                .collect::<TachygramSetPoly>();
            prop_assert_eq!(
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

            let gap = Anchor::from(Fp::random(&mut *rng));
            let gapped = stamp_intake(rng, gap, epoch, discriminant, &right_members);
            let later = stamp_intake(
                rng,
                junction,
                epoch.next().expect("an epoch before the final"),
                discriminant,
                &right_members,
            );
            let foreign = stamp_intake(rng, junction, epoch, other_discriminant, &right_members);
            let (_, left_residue) = split_qr_intake(rng, left.clone());
            let (right_non_residue, _) = split_qr_intake(rng, right.clone());
            let (left_contents, right_contents, merged_contents) = honest((&left, &right));
            let stranger = tachygrams(rng, 1).into_iter().collect::<TachygramSetPoly>();

            assert_rejections([
                (
                    "a gap between the inputs",
                    merge(rng, honest((&left, &gapped)), (&left, &gapped)).map(drop),
                    "QrIntakeMerge: left.anchor_end must equal right.anchor_prev",
                ),
                (
                    "inputs of different epochs",
                    merge(rng, honest((&left, &later)), (&left, &later)).map(drop),
                    "QrIntakeMerge: inputs cover different epochs",
                ),
                (
                    "inputs of different discriminants",
                    merge(rng, honest((&left, &foreign)), (&left, &foreign)).map(drop),
                    "QrIntakeMerge: inputs derive from different discriminants",
                ),
                (
                    "inputs at different depths",
                    merge(
                        rng,
                        honest((&left_residue, &right)),
                        (&left_residue, &right),
                    )
                    .map(drop),
                    "QrIntakeMerge: inputs sit at different depths",
                ),
                (
                    "inputs on different sides",
                    merge(
                        rng,
                        honest((&left_residue, &right_non_residue)),
                        (&left_residue, &right_non_residue),
                    )
                    .map(drop),
                    "QrIntakeMerge: inputs sit at different profiles",
                ),
                (
                    "left contents other than the header's",
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
                ),
                (
                    "right contents other than the header's",
                    merge(
                        rng,
                        (left_contents.clone(), stranger, merged_contents),
                        (&left, &right),
                    )
                    .map(drop),
                    "QrIntakeMerge: right contents do not match header",
                ),
                (
                    "a merged set without the right input",
                    merge(
                        rng,
                        (left_contents.clone(), right_contents, left_contents),
                        (&left, &right),
                    )
                    .map(drop),
                    "QrIntakeMerge: merged contents are not the union of the inputs",
                ),
            ]);
            Ok(())
        },
    );
}

/// A bucket sealed over any intake that opens on its epoch's entry anchor
/// keeps the intake's epoch, opening, discriminant, profile and contents, and
/// ends on the crossing out of the intake's own end: the next epoch's
/// published entry anchor exactly when the intake runs to the epoch's final
/// anchor. An empty intake from the entry anchor seals onto the published
/// crossing only over an epoch that published no stamp.
#[test]
fn bucket_seal_crosses_the_boundary() {
    let strategy = (
        any::<u64>(),
        0u32..=2,
        any::<bool>(),
        vec(vec(1usize..=3, 1..=2), 1..=3),
        0u32..=2,
        1usize..=12,
    );
    check(
        32,
        strategy,
        |(seed, epoch_index, silent, blocks, depth, capacity)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let epoch = EpochIndex::new(epoch_index);
            let next = epoch.next().expect("an early epoch has a successor");
            let mut pool = PoolSim::genesis_with(Vec::new());
            mine_sparse(rng, &mut pool, epoch, None);
            if !silent {
                for sizes in &blocks {
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
            let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));

            let empty_intake = seed_qr_empty_intake(rng, entry, epoch, discriminant);
            let empty = seal_qr_intake(rng, empty_intake, anchor_final_prev);
            prop_assert_eq!(
                *empty.pcd.data(),
                (
                    epoch,
                    entry,
                    entry.next_epoch(next).unwrap(),
                    discriminant,
                    QrProfile::ROOT,
                    iter::empty().collect::<TachygramSetPoly>().commit()
                )
            );
            prop_assert_eq!(empty.pcd.data().2 == published, silent);

            if !silent {
                let opening: Vec<QrIntakeEntry> = build_qr_partition(
                    rng,
                    &pool,
                    (entry, final_anchor),
                    discriminant,
                    capacity,
                    depth,
                )
                .into_iter()
                .filter(|intake| intake.pcd.data().1 == entry)
                .collect();
                prop_assert_eq!(opening.len(), 1 << depth);
                for intake in opening {
                    let (_, _, anchor_end, _, profile, contents) = *intake.pcd.data();
                    let bucket = seal_qr_intake(rng, intake, anchor_final_prev);
                    prop_assert_eq!(
                        *bucket.pcd.data(),
                        (
                            epoch,
                            entry,
                            anchor_end.next_epoch(next).unwrap(),
                            discriminant,
                            profile,
                            contents
                        )
                    );
                    prop_assert_eq!(bucket.pcd.data().2 == published, anchor_end == final_anchor);
                }
            }
            Ok(())
        },
    );
}

/// `QrBucketSeal` refuses an intake that does not open on the boundary
/// digest of the witnessed predecessor, whether the intake opens on a
/// stamp's anchor or the predecessor is another anchor, and an intake in the
/// final epoch.
#[test]
fn bucket_seal_rejects_corruptions() {
    check(16, any::<u64>(), |seed| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let (pool, end) = small_epoch(rng);
        let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
        let root = |root_rng: &mut StdRng, start: Anchor| {
            build_qr_partition(root_rng, &pool, (start, end), discriminant, 24, 0)
                .pop()
                .expect("one root")
                .pcd
        };
        let whole = root(rng, Anchor::default());
        let inner = root(rng, pool.block(BlockHeight(0)).anchor());
        let seal =
            |seal_rng: &mut StdRng, intake: &Pcd<qr::QrIntake>, anchor_final_prev: Anchor| {
                PROOF_SYSTEM
                    .fuse(
                        seal_rng,
                        qr::QrBucketSeal,
                        witness::qr_bucket_seal((*intake.data(), ()), anchor_final_prev),
                        intake.clone(),
                        Proof::trivial().carry::<()>(()),
                    )
                    .map(drop)
            };
        let final_epoch = EpochIndex::new(EPOCH_MAX);
        let predecessor = Anchor::from(Fp::random(&mut *rng));
        let last = recarry(&whole, |data| {
            data.0 = final_epoch;
            data.1 = predecessor.next_epoch(final_epoch).unwrap();
        });

        assert_rejections([
            (
                "an intake opening on a stamp's anchor",
                seal(rng, &inner, Anchor::from(Fp::ZERO)),
                "QrBucketSeal: witnessed boundary digest does not match intake's first anchor",
            ),
            (
                "another predecessor",
                seal(rng, &whole, predecessor),
                "QrBucketSeal: witnessed boundary digest does not match intake's first anchor",
            ),
            (
                "an intake in the final epoch",
                seal(rng, &last, predecessor),
                "QrBucketSeal: crossing past the final epoch",
            ),
        ]);
        Ok(())
    });
}

/// A value absent from an epoch is admitted against the bucket of its own
/// profile at any depth up to the maximum, in a ragged trie whose first
/// split's other side is routed deeper, under any first discriminant. The
/// segment runs over the bucket's epoch from its entry anchor to the
/// crossing, with the value as its one member. Bound to a note, a segment
/// from one bucket pairs with the bucket holding the note's commitment at
/// another depth.
#[test]
fn unspent_init_admits_absent_values() {
    let strategy = (any::<u64>(), prop_oneof![1u32..=3, Just(31), Just(32)]);
    check(8, strategy, |(seed, deep_depth)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::new(shared_sk());
        let note = wallet.random_note(300);
        let (epoch0, epoch1) = (EpochIndex::new(0), EpochIndex::new(1));
        let mut pool =
            PoolSim::genesis_with(random_block_with(rng, &[[note.commitment()].to_vec()], 2));
        for _ in 0..3 {
            pool.mine(random_block(rng, 3, 2));
        }
        let end = pool.anchor();
        let crossing = end.next_epoch(epoch1).unwrap();
        let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
        let nf = Fp::from(wallet.nf_at(&note, epoch0));
        let shallow_side = qr::classify(nf, discriminant.at(0)).0;
        let deep_value = iter::repeat_with(|| Fp::random(&mut *rng))
            .find(|&value| qr::classify(value, discriminant.at(0)).0 != shallow_side)
            .expect("a value on the other side");

        let root = build_qr_partition(rng, &pool, (Anchor::default(), end), discriminant, 24, 0)
            .pop()
            .expect("one root");
        let root_bucket = seal_qr_intake(rng, root.clone(), Anchor::from(Fp::ZERO));
        let (non_residue, residue) = split_qr_intake(rng, root);
        let (shallow, other_side) = if shallow_side {
            (residue, non_residue)
        } else {
            (non_residue, residue)
        };
        let shallow_bucket = seal_qr_intake(rng, shallow, Anchor::from(Fp::ZERO));
        let deep = descend_along(rng, other_side, deep_value, deep_depth);
        let deep_bucket = seal_qr_intake(rng, deep, Anchor::from(Fp::ZERO));

        for (bucket, value, depth) in [
            (&root_bucket, nf, 0),
            (&shallow_bucket, nf, 1),
            (&deep_bucket, deep_value, deep_depth),
        ] {
            prop_assert_eq!(
                bucket.pcd.data().4,
                qr_profile_of(value, discriminant, depth)
            );
            let segment = qr_bucket_segment(rng, bucket, |_| Nullifier::from(value));
            prop_assert_eq!(
                *segment.data(),
                (
                    Anchor::default(),
                    epoch0,
                    NfSeqPoly::new(epoch0, &[Nullifier::from(value)]).commit(),
                    epoch1,
                    crossing
                )
            );
        }

        let unspent = qr_epoch_unspent(rng, &wallet, &note, &shallow_bucket);
        let (spendable, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                spendable::QrSpendableInit,
                witness::qr_spendable_init(
                    (*unspent.data(), *root_bucket.pcd.data()),
                    &root_bucket.members,
                ),
                unspent,
                root_bucket.pcd,
            )
            .expect("QrSpendableInit");
        prop_assert_eq!(*spendable.data(), (note.commitment(), epoch1, crossing));
        Ok(())
    });
}

/// `QrUnspentInit` refuses contents other than the bucket's, a zero value, a
/// value the bucket holds, a value of another profile, a class root off its
/// class, a side flipped past the bucket's depth, the exceptional value on
/// the non-residue side within the bucket's depth, a mask that is not a
/// prefix or of another depth, a depth past the maximum, a set bit past the
/// depth, a bucket in the final epoch, a sequence naming another value, and
/// a cube-root twin of the value.
#[test]
fn unspent_init_rejects_corruptions() {
    let strategy = (any::<u64>(), 0u32..2, 2usize..QrProfile::MAX_DEPTH);
    check(12, strategy, |(seed, fixed_position, past_position)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let (pool, end) = small_epoch(rng);
        let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
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
        let nf = Nullifier::from(Fp::random(&mut *rng));
        let bucket = bucket_for(rng, Fp::from(nf), 2);
        let root = bucket_for(rng, Fp::from(nf), 0);
        let fixed_value = -discriminant.at(fixed_position);
        let fixed = bucket_for(rng, fixed_value, 2);
        let init = |init_rng: &mut StdRng, target: &Pcd<qr::QrBucket>, init_witness| {
            PROOF_SYSTEM
                .fuse(
                    init_rng,
                    qr::QrUnspentInit,
                    init_witness,
                    target.clone(),
                    Proof::trivial().carry::<()>(()),
                )
                .map(drop)
        };
        let honest = |value: Tachygram, target: &QrBucketEntry| {
            witness::qr_unspent_init((*target.pcd.data(), ()), value, &target.members)
        };
        let witness = honest(Tachygram::from(nf), &bucket);
        let (epoch, .., profile, _) = *bucket.pcd.data();
        let other = iter::repeat_with(|| Fp::random(&mut *rng))
            .find(|&value| qr_profile_of(value, discriminant, 2) != profile)
            .expect("a value of another profile");

        let fixed_index = usize::try_from(fixed_position).unwrap();
        let fixed_witness = honest(Tachygram::from(fixed_value), &fixed);
        prop_assert_eq!(fixed_witness.1[fixed_index], QrClassRoot(true, Fp::ZERO));
        init(rng, &fixed.pcd, fixed_witness.clone())
            .expect("the fixed point passes on the residue side");

        let root_witness = honest(Tachygram::from(nf), &root);
        let challenge = unpinned_challenge(&[root_witness.3.commit().into()]);
        let twin = cube_root_twin(epoch, Fp::from(nf), challenge);
        prop_assert_eq!(
            indexed_factor(epoch, twin, challenge),
            indexed_factor(epoch, Fp::from(nf), challenge)
        );

        let full_mask = altered(&witness, |forged| {
            forged.2 = [true; QrProfile::MAX_DEPTH];
        });
        let deepest = recarry(&bucket.pcd, |data| data.4.depth = u32::BITS + 1);
        let saturated = recarry(&bucket.pcd, |data| data.4.depth = u32::MAX);
        let stray_bit = recarry(&bucket.pcd, |data| data.4 = QrProfile { depth: 0, bits: 1 });
        let overflowing = recarry(&bucket.pcd, |data| data.4.bits |= 1 << 2);
        let last = recarry(&bucket.pcd, |data| data.0 = EpochIndex::new(EPOCH_MAX));
        let stranger = tachygrams(rng, 1).into_iter().collect::<TachygramSetPoly>();

        assert_rejections([
            (
                "contents other than the bucket's",
                init(
                    rng,
                    &bucket.pcd,
                    altered(&witness, |forged| forged.4 = stranger),
                ),
                "QrUnspentInit: contents do not match the bucket",
            ),
            (
                "a zero value",
                init(rng, &bucket.pcd, honest(Tachygram::from(Fp::ZERO), &bucket)),
                "QrUnspentInit: tested value is zero",
            ),
            (
                "a value the bucket holds",
                init(rng, &root.pcd, honest(root.members[0], &root)),
                "QrUnspentInit: found nullifier in the bucket",
            ),
            (
                "a value of another profile",
                init(rng, &bucket.pcd, honest(Tachygram::from(other), &bucket)),
                "QR profile: value does not take the bucket's profile",
            ),
            (
                "a class root off its class",
                init(
                    rng,
                    &bucket.pcd,
                    altered(&witness, |forged| forged.1[0].1 += Fp::ONE),
                ),
                "QR profile: root does not square to the claimed class",
            ),
            (
                "a side flipped past the bucket's depth",
                init(
                    rng,
                    &bucket.pcd,
                    altered(&witness, |forged| {
                        forged.1[past_position].0 = !forged.1[past_position].0;
                    }),
                ),
                "QR profile: root does not square to the claimed class",
            ),
            (
                "the exceptional value on the non-residue side",
                init(
                    rng,
                    &fixed.pcd,
                    altered(&fixed_witness, |forged| forged.1[fixed_index].0 = false),
                ),
                "QR profile: exceptional discriminant claimed the non-residue class",
            ),
            (
                "a mask that is not a prefix",
                init(
                    rng,
                    &bucket.pcd,
                    altered(&witness, |forged| {
                        forged.2 = array::from_fn(|position| position == 0 || position == 2);
                    }),
                ),
                "QR profile: depth mask is not a prefix",
            ),
            (
                "a mask of another depth",
                init(
                    rng,
                    &bucket.pcd,
                    altered(&witness, |forged| {
                        forged.2 = QrProfile { depth: 3, bits: 0 }.depth_mask();
                    }),
                ),
                "QR profile: depth mask does not match the bucket's depth",
            ),
            (
                "a depth past the maximum",
                init(rng, &deepest, full_mask.clone()),
                "QR profile: depth mask does not match the bucket's depth",
            ),
            (
                "a saturated depth",
                init(rng, &saturated, full_mask),
                "QR profile: depth mask does not match the bucket's depth",
            ),
            (
                "a set bit at depth zero",
                init(
                    rng,
                    &stray_bit,
                    altered(&witness, |forged| {
                        forged.2 = QrProfile::ROOT.depth_mask();
                    }),
                ),
                "QR profile: value does not take the bucket's profile",
            ),
            (
                "a set bit past the depth",
                init(rng, &overflowing, witness.clone()),
                "QR profile: value does not take the bucket's profile",
            ),
            (
                "a bucket in the final epoch",
                init(rng, &last, witness.clone()),
                "QrUnspentInit: bucket has no next epoch",
            ),
            (
                "a sequence naming another value",
                init(
                    rng,
                    &bucket.pcd,
                    altered(&witness, |forged| {
                        forged.3 = NfSeqPoly::new(epoch, &[Nullifier::from(other)]);
                    }),
                ),
                "QrUnspentInit: sequence does not match the tested pair",
            ),
            (
                "a cube-root twin of the value",
                init(
                    rng,
                    &root.pcd,
                    altered(&root_witness, |forged| {
                        forged.0 = Tachygram::from(twin);
                        forged.1 = QrClassRoot::along(twin, discriminant);
                    }),
                ),
                "QrUnspentInit: sequence does not match the tested pair",
            ),
        ]);
        Ok(())
    });
}
