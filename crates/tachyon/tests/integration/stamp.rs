//! Proof stamps: `stamp::Plan::prove`, `ProofStamp::merge` and `lift`, and
//! what `verify_proof` accepts.

extern crate alloc;

use alloc::{boxed::Box, collections::BTreeSet, vec, vec::Vec};
use core::iter;

use ff::Field as _;
use pasta_curves::Fp;
use proptest::{option, prelude::*, sample::Index};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, Anchor, BlockHeight, ProofStamp, Tachygram, TachygramSetPoly, action,
    constants::{EPOCH_SIZE, MAX_MONEY},
    entropy::ActionEntropy,
    fee,
    note::Note,
    stamp::{self, ProveError},
    value,
};

use crate::{
    fixtures::{
        PoolSim, WalletSim, build_lift_span, build_output_plan, build_output_stamp, fee_digests,
        forge_overlapping_merge, random_block, random_block_with, shared_sk, stamp_coverage,
    },
    strategies::{check, invalid_witness, tachygrams},
};

/// The fee descriptor of `fee` out of `max_fee_note`.
fn fee_descriptor(max_fee_note: &Note, fee: value::Positive) -> fee::Descriptor {
    fee::Descriptor {
        max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
        value: fee,
    }
}

/// The digests a verifier reconstructs from `descriptors` and `fees`.
fn digests_of<'desc>(
    descriptors: impl IntoIterator<Item = &'desc action::Descriptor>,
    fees: impl IntoIterator<Item = fee::Descriptor>,
) -> Vec<ActionDigest> {
    descriptors
        .into_iter()
        .map(|desc| desc.digest().expect("action digest"))
        .chain(fee_digests(fees))
        .collect()
}

/// The coverage digest of `descriptors` and `fees`, as multisets.
fn coverage_of<'desc>(
    descriptors: impl IntoIterator<Item = &'desc action::Descriptor>,
    fees: &[fee::Descriptor],
) -> [u8; 32] {
    let mut bytes: Vec<[u8; 64]> = descriptors.into_iter().copied().collect();
    bytes.sort_unstable();
    stamp_coverage(&bytes, fees)
}

/// The descriptor of an output no stamp covers.
fn foreign_descriptor(rng: &mut StdRng) -> action::Descriptor {
    let note = WalletSim::random(rng).random_note(400);
    build_output_plan(rng, note).2.descriptor()
}

/// A stamp of `count` fresh outputs at `anchor` paying `fee` out of a max
/// fee note of `max_fee`, with its descriptors and fee descriptor.
fn output_stamp(
    rng: &mut StdRng,
    anchor: Anchor,
    count: usize,
    (max_fee, fee_amount): (u64, u64),
) -> (ProofStamp, BTreeSet<action::Descriptor>, fee::Descriptor) {
    let outputs: Vec<(action::Descriptor, ActionEntropy, Note, value::Trapdoor)> =
        iter::repeat_with(|| {
            let note = WalletSim::random(rng).random_note(200);
            let (rcv, theta, plan) = build_output_plan(rng, note);
            (plan.descriptor(), theta, note, rcv)
        })
        .take(count)
        .collect();
    let descriptors = outputs.iter().map(|&(desc, ..)| desc).collect();
    let max_fee_note = WalletSim::random(rng).random_note(max_fee);
    let fee = value::Positive::try_from(fee_amount).unwrap();
    // An output-only plan never reads the proof authorizing key.
    let stamp = stamp::Plan::new(vec![], outputs, anchor, max_fee_note, fee)
        .prove(rng, &WalletSim::new(shared_sk()).pak, vec![])
        .expect("an output stamp");
    (stamp, descriptors, fee_descriptor(&max_fee_note, fee))
}

/// A maximum fee and a fee within it.
fn fees() -> impl Strategy<Value = (u64, u64)> {
    (0..=MAX_MONEY).prop_flat_map(|max_fee| (Just(max_fee), 0..=max_fee))
}

/// A plan of spends and outputs, the empty plan included, proves a stamp at
/// the plan's anchor that covers exactly its actions and fee. A spend whose
/// spendable rests earlier in the epoch lifts to the anchor along one span or
/// two, abutting or overlapping. The stamp publishes the actions' tachygrams
/// and the fee change note under a commitment to exactly them, and keeps the
/// planned fee.
#[test]
fn plan_proves_the_planned_actions() {
    let strategy = (
        any::<u64>(),
        0usize..=2,
        0usize..=2,
        0u32..=3,
        (0u8..=2, any::<Index>()),
        fees(),
    );
    check(
        10,
        strategy,
        |(seed, spends, outputs, lift_blocks, (layout, split), drawn_fees)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let wallet = WalletSim::new(shared_sk());
            let (max_fee, fee_amount) = if spends + outputs == 0 {
                (0, 0)
            } else {
                drawn_fees
            };
            let spent: Vec<Note> = iter::repeat_with(|| wallet.random_note(300))
                .take(spends)
                .collect();
            let mut pool = PoolSim::genesis(rng);
            let cms: Vec<_> = spent.iter().map(Note::commitment).collect();
            let cm_block = if cms.is_empty() {
                random_block(rng, 1, 1)
            } else {
                random_block_with(rng, &[cms], 1)
            };
            pool.mine(cm_block);
            let cm_height = pool.height();
            for _ in 0..lift_blocks {
                pool.mine(random_block(rng, 1, 2));
            }
            let plan_height = pool.height();
            let plan_anchor = pool.anchor();
            let split_offset = split.index(usize::try_from(lift_blocks.max(1)).unwrap());
            let split_height = BlockHeight(cm_height.0 + u32::try_from(split_offset).unwrap());
            let spans = |span_rng: &mut StdRng| match (lift_blocks, layout) {
                (0, _) => vec![],
                (_, 0) => vec![build_lift_span(span_rng, &pool, cm_height..=plan_height)],
                (_, 1) => vec![
                    build_lift_span(span_rng, &pool, cm_height..=split_height),
                    build_lift_span(span_rng, &pool, split_height.next().unwrap()..=plan_height),
                ],
                _ => vec![
                    build_lift_span(span_rng, &pool, cm_height..=split_height),
                    build_lift_span(span_rng, &pool, split_height..=plan_height),
                ],
            };

            let mut spend_plans = Vec::new();
            let mut spend_pcds = Vec::new();
            let mut descriptors = BTreeSet::new();
            for note in &spent {
                let spendable = wallet.fresh_spend(rng, &pool, cm_height, note);
                prop_assert_eq!(spendable.data().2, pool.block(cm_height).anchor());
                let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
                let plan = action::Plan::spend(*note, theta, rcv, |alpha| {
                    wallet.pak.ak.derive_action_public(&alpha)
                });
                descriptors.insert(plan.descriptor());
                spend_plans.push((plan.descriptor(), theta, rcv));
                let secret = wallet.secret_pcd(rng, *note);
                let lift = spans(rng);
                spend_pcds.push((secret, spendable, lift));
            }
            let mut output_plans = Vec::new();
            let mut output_cms = Vec::new();
            for _ in 0..outputs {
                let note = WalletSim::random(rng).random_note(200);
                let (rcv, theta, plan) = build_output_plan(rng, note);
                descriptors.insert(plan.descriptor());
                output_cms.push(Tachygram::from(note.commitment()));
                output_plans.push((plan.descriptor(), theta, note, rcv));
            }
            let max_fee_note = wallet.random_note(max_fee);
            let fee = value::Positive::try_from(fee_amount).unwrap();
            let change = Note {
                value: value::Positive::try_from(max_fee - fee_amount).unwrap(),
                ..max_fee_note
            };

            let proved =
                stamp::Plan::new(spend_plans, output_plans, plan_anchor, max_fee_note, fee)
                    .prove(rng, &wallet.pak, spend_pcds)
                    .expect("the plan proves");
            let fee_desc = fee_descriptor(&max_fee_note, fee);
            prop_assert_eq!(proved.anchor, plan_anchor);
            prop_assert_eq!(proved.fee, fee);
            prop_assert_eq!(proved.tachygrams.len(), 2 * (spends + outputs) + 1);
            prop_assert!(
                proved
                    .tachygrams
                    .contains(&Tachygram::from(change.commitment()))
            );
            prop_assert!(output_cms.iter().all(|cm| proved.tachygrams.contains(cm)));
            prop_assert_eq!(
                proved.tachygram_set,
                TachygramSetPoly::from_iter(proved.tachygrams.iter().copied()).commit()
            );
            prop_assert!(proved.is_covering(descriptors.iter().copied(), [fee_desc]));
            prop_assert!(
                proved
                    .verify_proof(rng, digests_of(&descriptors, [fee_desc]))
                    .expect("proof system verification")
            );
            Ok(())
        },
    );
}

/// Spend inputs paired with the wrong planned spend still prove, but the
/// stamp does not verify as the plan's actions: two same-value notes'
/// secrets swapped, or a spend planned under another wallet's `ak`.
#[test]
fn misassigned_spend_inputs_never_verify() {
    check(4, (any::<u64>(), 0..=MAX_MONEY), |(seed, amount)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::new(shared_sk());
        let stranger = WalletSim::random(rng);
        let notes = [wallet.random_note(amount), wallet.random_note(amount)];
        let mut pool = PoolSim::genesis(rng);
        pool.mine(random_block_with(
            rng,
            &[notes.iter().map(Note::commitment).collect()],
            2,
        ));
        let height = pool.height();
        let inputs: Vec<_> = notes
            .iter()
            .map(|note| {
                (
                    wallet.secret_pcd(rng, *note),
                    wallet.fresh_spend(rng, &pool, height, note),
                    vec![],
                )
            })
            .collect();
        let anchor = inputs[0].1.data().2;
        let witnesses: Vec<(ActionEntropy, value::Trapdoor)> = notes
            .iter()
            .map(|_| (ActionEntropy::random(rng), value::Trapdoor::random(rng)))
            .collect();
        let plan_under = |owner: &WalletSim, index: usize| {
            let (theta, rcv) = witnesses[index];
            action::Plan::spend(notes[index], theta, rcv, |alpha| {
                owner.pak.ak.derive_action_public(&alpha)
            })
        };
        let max_fee_note = wallet.random_note(0);
        let fee_desc = fee_descriptor(&max_fee_note, value::Positive::ZERO);
        let prove_and_verify = |prove_rng: &mut StdRng, plans: &[action::Plan<_>], pcds| {
            let spends = plans
                .iter()
                .zip(&witnesses)
                .map(|(plan, &(theta, rcv))| (plan.descriptor(), theta, rcv))
                .collect();
            let proved =
                stamp::Plan::new(spends, vec![], anchor, max_fee_note, value::Positive::ZERO)
                    .prove(prove_rng, &wallet.pak, pcds)
                    .expect("misassigned inputs still prove");
            let descriptors: Vec<action::Descriptor> =
                plans.iter().map(action::Plan::descriptor).collect();
            proved
                .verify_proof(prove_rng, digests_of(&descriptors, [fee_desc]))
                .expect("proof system verification")
        };

        let planned = [plan_under(&wallet, 0), plan_under(&wallet, 1)];
        let swapped = vec![inputs[1].clone(), inputs[0].clone()];
        prop_assert!(prove_and_verify(rng, &planned, inputs.clone()));
        prop_assert!(!prove_and_verify(rng, &planned, swapped));
        prop_assert!(!prove_and_verify(
            rng,
            &[plan_under(&stranger, 0)],
            vec![inputs[0].clone()]
        ));
        Ok(())
    });
}

/// Two stamps merge exactly when they share an anchor. The merge stays at
/// that anchor, keeps the receiver's fee, publishes the union of the
/// tachygrams, covers the union of the descriptors and fees whichever side
/// receives, and verifies against them. Merged under descriptors the other
/// stamp does not cover, it still proves, and does not verify.
#[test]
fn merge_requires_a_shared_anchor_and_covers_the_union() {
    let heights = (0..EPOCH_SIZE, option::of(0..EPOCH_SIZE));
    let strategy = (
        any::<u64>(),
        heights,
        1usize..=2,
        1usize..=2,
        fees(),
        fees(),
    );
    check(
        8,
        strategy,
        |(seed, (left_height, distinct_height), left_count, right_count, left_fees, right_fees)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let right_height = distinct_height.unwrap_or(left_height);
            let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
            while pool.height().0 < left_height.max(right_height) {
                pool.mine(random_block(rng, 1, 1));
            }
            let anchor_at = |height| pool.block(BlockHeight(height)).anchor();
            let (left, left_desc, left_fee) =
                output_stamp(rng, anchor_at(left_height), left_count, left_fees);
            let (right, right_desc, right_fee) =
                output_stamp(rng, anchor_at(right_height), right_count, right_fees);
            let merge = |merge_rng: &mut StdRng,
                         (receiver, receiver_desc, receiver_fee): (
                &ProofStamp,
                &BTreeSet<action::Descriptor>,
                fee::Descriptor,
            ),
                         (other, other_desc, other_fee): (
                &ProofStamp,
                &BTreeSet<action::Descriptor>,
                fee::Descriptor,
            )| {
                receiver.clone().merge(
                    merge_rng,
                    (receiver_desc.clone(), BTreeSet::from([receiver_fee])),
                    (
                        other.clone(),
                        other_desc.clone(),
                        BTreeSet::from([other_fee]),
                    ),
                )
            };
            let left_side = (&left, &left_desc, left_fee);
            let right_side = (&right, &right_desc, right_fee);

            if left_height != right_height {
                let Err(ProveError::ProofFailed(err)) = merge(rng, left_side, right_side) else {
                    panic!("stamps at different anchors merged");
                };
                prop_assert_eq!(invalid_witness(err), "StampMerge: anchors must match");
                return Ok(());
            }

            let merged = merge(rng, left_side, right_side).expect("merge");
            let reversed = merge(rng, right_side, left_side).expect("merge");
            let fees = [left_fee, right_fee];
            let union = || left_desc.union(&right_desc);
            prop_assert_eq!(merged.anchor, left.anchor);
            prop_assert_eq!(merged.fee, left.fee);
            prop_assert_eq!(reversed.fee, right.fee);
            prop_assert_eq!(merged.coverage, coverage_of(union(), &fees));
            prop_assert_eq!(reversed.coverage, merged.coverage);
            prop_assert_eq!(
                &merged.tachygrams,
                &left
                    .tachygrams
                    .union(&right.tachygrams)
                    .copied()
                    .collect::<BTreeSet<Tachygram>>()
            );
            prop_assert!(
                merged
                    .verify_proof(rng, digests_of(union(), fees))
                    .expect("proof system verification")
            );

            let foreign = BTreeSet::from([foreign_descriptor(rng)]);
            let mismatched = merge(rng, left_side, (&right, &foreign, right_fee))
                .expect("merge performs no coverage check");
            prop_assert!(
                !mismatched
                    .verify_proof(rng, digests_of(union(), fees))
                    .expect("proof system verification")
            );
            Ok(())
        },
    );
}

/// A merge forced over stamps that overlap proves a multiset union, and never
/// verifies once published: a note output twice, a note spent twice and an
/// action counted twice each double a tachygram, which the published set
/// holds once.
#[test]
fn overlapping_merges_never_verify() {
    check(4, any::<u64>(), |seed| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::new(shared_sk());
        let forged_verifies = |forge_rng: &mut StdRng,
                               (left, left_desc, left_fees): (
            &ProofStamp,
            Vec<action::Descriptor>,
            Vec<fee::Descriptor>,
        ),
                               (right, right_desc, right_fees): (
            &ProofStamp,
            Vec<action::Descriptor>,
            Vec<fee::Descriptor>,
        )| {
            let pcd = forge_overlapping_merge(
                forge_rng,
                (left, &left_desc, &left_fees),
                (right, &right_desc, &right_fees),
            );
            let descriptors: Vec<action::Descriptor> =
                left_desc.iter().chain(&right_desc).copied().collect();
            let fees: Vec<fee::Descriptor> = left_fees.iter().chain(&right_fees).copied().collect();
            let tachygrams: BTreeSet<Tachygram> =
                left.tachygrams.union(&right.tachygrams).copied().collect();
            let published = ProofStamp {
                coverage: coverage_of(&descriptors, &fees),
                anchor: pcd.data().2,
                tachygram_set: TachygramSetPoly::from_iter(tachygrams.iter().copied()).commit(),
                tachygrams,
                proof: Box::new(pcd.proof().clone()),
                fee: left.fee,
            };
            published
                .verify_proof(forge_rng, digests_of(&descriptors, fees))
                .expect("proof system verification")
        };

        let anchor = PoolSim::genesis(rng).anchor();
        let note = wallet.random_note(200);
        let (first, first_plan, first_fee) = build_output_stamp(rng, anchor, note);
        let (again, again_plan, again_fee) = build_output_stamp(rng, anchor, note);
        prop_assert!(!forged_verifies(
            rng,
            (&first, vec![first_plan.descriptor()], vec![first_fee]),
            (&again, vec![again_plan.descriptor()], vec![again_fee]),
        ));
        prop_assert!(!forged_verifies(
            rng,
            (&first, vec![first_plan.descriptor()], vec![first_fee]),
            (&first, vec![first_plan.descriptor()], vec![first_fee]),
        ));

        let spent = wallet.random_note(1000);
        let mut pool = PoolSim::genesis(rng);
        pool.mine(random_block_with(rng, &[vec![spent.commitment()]], 2));
        let height = pool.height();
        let spend_twice = |spend_rng: &mut StdRng| {
            let spendable = wallet.fresh_spend(spend_rng, &pool, height, &spent);
            let spend_anchor = spendable.data().2;
            let output = wallet.random_note(600);
            let bundle = wallet.autonome(
                spend_rng,
                spend_anchor,
                vec![(spent, spendable)],
                vec![output],
            );
            let descriptors: Vec<action::Descriptor> = bundle.descriptors().collect();
            (
                bundle.stamp.clone(),
                descriptors,
                vec![bundle.fee_descriptor()],
            )
        };
        let (left, left_desc, left_fees) = spend_twice(rng);
        let (right, right_desc, right_fees) = spend_twice(rng);
        prop_assert!(!left.tachygrams.is_disjoint(&right.tachygrams));
        prop_assert!(!forged_verifies(
            rng,
            (&left, left_desc, left_fees),
            (&right, right_desc, right_fees),
        ));
        Ok(())
    });
}

/// `verify_proof` reconstructs the action set from the digests it is handed,
/// as a multiset: the covered digests verify in any order, and dropping,
/// repeating, adding or substituting a digest does not.
#[test]
fn verify_proof_is_exact_on_the_action_multiset() {
    let strategy = (
        any::<u64>(),
        1usize..=3,
        any::<Index>(),
        any::<bool>(),
        any::<Index>(),
    );
    check(8, strategy, |(seed, count, rotation, reversed, at)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let anchor = Anchor::from(Fp::random(&mut *rng));
        let (proved, descriptors, fee_desc) = output_stamp(rng, anchor, count, (300, 100));
        let digests = digests_of(&descriptors, [fee_desc]);
        let foreign = digests_of(&[foreign_descriptor(rng)], [])[0];
        let verifies = |verify_rng: &mut StdRng, handed: Vec<ActionDigest>| {
            proved
                .verify_proof(verify_rng, handed)
                .expect("proof system verification")
        };
        let index = at.index(digests.len());

        let mut permuted = digests.clone();
        permuted.rotate_left(rotation.index(digests.len()));
        if reversed {
            permuted.reverse();
        }
        let mut dropped = digests.clone();
        dropped.remove(index);
        let repeated: Vec<ActionDigest> = digests.iter().copied().chain([digests[index]]).collect();
        let extended: Vec<ActionDigest> = digests.iter().copied().chain([foreign]).collect();
        let mut substituted = digests;
        substituted[index] = foreign;

        prop_assert!(verifies(rng, permuted));
        prop_assert!(!verifies(rng, dropped));
        prop_assert!(!verifies(rng, repeated));
        prop_assert!(!verifies(rng, extended));
        prop_assert!(!verifies(rng, substituted));
        Ok(())
    });
}

/// The proof binds the stamp's tachygram set commitment, not its published
/// list: a commitment to other tachygrams does not verify, while a list
/// tampered under the honest commitment does, which is what
/// `Bundle::verify_tachygrams` is for.
#[test]
fn proof_binds_the_set_commitment() {
    let strategy = (any::<u64>(), 1usize..=3, any::<Index>());
    check(8, strategy, |(seed, foreign_count, at)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let anchor = Anchor::from(Fp::random(&mut *rng));
        let (honest, descriptors, fee_desc) = output_stamp(rng, anchor, 1, (300, 100));
        let digests = digests_of(&descriptors, [fee_desc]);
        let recommitted = ProofStamp {
            tachygram_set: TachygramSetPoly::from_iter(tachygrams(rng, foreign_count)).commit(),
            ..honest.clone()
        };
        let mut retold = honest.tachygrams.clone();
        let replaced = *retold
            .iter()
            .nth(at.index(retold.len()))
            .expect("a published tachygram");
        retold.remove(&replaced);
        retold.extend(tachygrams(rng, 1));
        let tampered = ProofStamp {
            tachygrams: retold,
            ..honest.clone()
        };

        prop_assert!(
            honest
                .verify_proof(rng, digests.clone())
                .expect("proof system verification")
        );
        prop_assert!(
            !recommitted
                .verify_proof(rng, digests.clone())
                .expect("proof system verification")
        );
        prop_assert!(
            tampered
                .verify_proof(rng, digests)
                .expect("proof system verification")
        );
        Ok(())
    });
}

/// A lift moves a stamp's anchor to the span's end and leaves its coverage,
/// tachygrams and fee alone. The lifted stamp verifies against the actions it
/// covers, and merges with a stamp proved at its new anchor, which it could
/// not before the lift. Lifted under descriptors it does not cover, it still
/// proves, and does not verify.
#[test]
fn lift_moves_the_anchor_and_keeps_the_proof_valid() {
    let strategy = (any::<u64>(), 0u32..=3, 1u32..=4, fees());
    check(8, strategy, |(seed, stamped_at, distance, stamp_fees)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 2));
        for _ in 0..stamped_at + distance {
            pool.mine(random_block(rng, 1, 2));
        }
        let stamped_height = BlockHeight(stamped_at);
        let (proved, descriptors, fee_desc) =
            output_stamp(rng, pool.block(stamped_height).anchor(), 1, stamp_fees);
        let fees = BTreeSet::from([fee_desc]);
        let mut span =
            || build_lift_span(rng, &pool, stamped_height.next().unwrap()..=pool.height());
        let lift_span = span();
        let foreign_span = span();
        let (later, later_desc, later_fee) = output_stamp(rng, pool.anchor(), 1, (0, 0));
        let later_side = (later, later_desc.clone(), BTreeSet::from([later_fee]));

        let Err(ProveError::ProofFailed(err)) =
            proved
                .clone()
                .merge(rng, (descriptors.clone(), fees.clone()), later_side.clone())
        else {
            panic!("a stamp merged with one at a later anchor");
        };
        prop_assert_eq!(invalid_witness(err), "StampMerge: anchors must match");

        let lifted = proved
            .clone()
            .lift(rng, &descriptors, &fees, vec![lift_span])
            .expect("lift");
        prop_assert_eq!(lifted.anchor, pool.anchor());
        prop_assert_eq!(lifted.coverage, proved.coverage);
        prop_assert_eq!(lifted.tachygram_set, proved.tachygram_set);
        prop_assert_eq!(&lifted.tachygrams, &proved.tachygrams);
        prop_assert_eq!(lifted.fee, proved.fee);
        prop_assert!(
            lifted
                .verify_proof(rng, digests_of(&descriptors, [fee_desc]))
                .expect("proof system verification")
        );

        let merged = lifted
            .merge(rng, (descriptors.clone(), fees.clone()), later_side)
            .expect("a lifted stamp merges at its new anchor");
        prop_assert!(
            merged
                .verify_proof(
                    rng,
                    digests_of(descriptors.iter().chain(&later_desc), [fee_desc, later_fee])
                )
                .expect("proof system verification")
        );

        let foreign = BTreeSet::from([foreign_descriptor(rng)]);
        let misdescribed = proved
            .lift(rng, &foreign, &fees, vec![foreign_span])
            .expect("a lift cannot see the descriptors");
        prop_assert!(
            !misdescribed
                .verify_proof(rng, digests_of(&descriptors, [fee_desc]))
                .expect("proof system verification")
        );
        Ok(())
    });
}

/// A strictly increasing tachygram sequence is unaffected by the
/// distinctness check.
#[test]
fn read_accepts_distinct_sorted_tachygrams() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let note = wallet.random_note(200);
    let (stamp, _plan, _) = build_output_stamp(rng, pool.anchor(), note);

    let mut buf = Vec::new();
    stamp.write(&mut buf).expect("write");
    ProofStamp::read(&*buf).expect("distinct sorted tachygrams must be accepted");
}

/// `hStampCoverageTachyon` and the fee survive a `write`/`read` round-trip.
#[test]
fn covered_actions_round_trip() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let pool = PoolSim::genesis(rng);
    let note = wallet.random_note(200);
    let (stamp, _plan, _) = build_output_stamp(rng, pool.anchor(), note);

    let mut buf: Vec<u8> = Vec::new();
    stamp.write(&mut buf).expect("write");
    let decoded = ProofStamp::read(&*buf).expect("read");

    assert_eq!(decoded.fee, stamp.fee);
    assert_eq!(decoded.coverage, stamp.coverage);
    assert_eq!(decoded.anchor, stamp.anchor);
    assert_eq!(decoded.tachygram_set, stamp.tachygram_set);
    assert_eq!(decoded.tachygrams, stamp.tachygrams);
}
