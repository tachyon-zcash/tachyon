extern crate alloc;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use core::iter;

use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, Anchor, BlockHeight, ProofStamp, Tachygram, TachygramSetPoly, action,
    bundle::{self, PlanError},
    constants::MAX_MONEY,
    entropy::ActionEntropy,
    fee,
    note::Note,
    stamp::{self, ProveError},
    value,
};

use crate::fixtures::{
    PoolSim, WalletSim, build_lift_span, build_output_plan, build_output_stamp, fee_digests,
    forge_overlapping_merge, random_block, random_block_with, stamp_coverage, tachygrams,
};

fn fee_descriptor(max_fee_note: &Note, fee: value::Positive) -> fee::Descriptor {
    fee::Descriptor {
        max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
        value: fee,
    }
}

fn digests_of<'desc>(
    descriptors: impl IntoIterator<Item = &'desc action::Descriptor>,
    fees: impl IntoIterator<Item = fee::Descriptor>,
) -> Vec<ActionDigest> {
    descriptors
        .into_iter()
        .map(|desc| desc.digest().unwrap())
        .chain(fee_digests(fees))
        .collect()
}

fn coverage_of<'desc>(
    descriptors: impl IntoIterator<Item = &'desc action::Descriptor>,
    fees: &[fee::Descriptor],
) -> [u8; 32] {
    let mut bytes: Vec<[u8; 64]> = descriptors.into_iter().copied().collect();
    bytes.sort_unstable();
    stamp_coverage(&bytes, fees)
}

fn foreign_descriptor(rng: &mut StdRng) -> action::Descriptor {
    let note = WalletSim::random(rng).random_note(400);
    build_output_plan(rng, note).2.descriptor()
}

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
    let wallet = WalletSim::random(rng);
    let max_fee_note = wallet.random_note(max_fee);
    let fee = value::Positive::try_from(fee_amount).unwrap();
    // An output-only plan never reads the proof authorizing key.
    let stamp = stamp::Plan::new(vec![], outputs, anchor, max_fee_note, fee)
        .prove(rng, &wallet.pak, vec![])
        .unwrap();
    (stamp, descriptors, fee_descriptor(&max_fee_note, fee))
}

fn assert_plan_proves_its_actions(
    rng: &mut StdRng,
    label: &str,
    (spends, outputs): (usize, usize),
    spans: &[(u32, u32)],
    (max_fee, fee_amount): (u64, u64),
) {
    let wallet = WalletSim::random(rng);
    let spent: Vec<Note> = iter::repeat_with(|| wallet.random_note(300))
        .take(spends)
        .collect();
    let mut pool = PoolSim::genesis(rng);
    pool.mine(random_block_with(
        rng,
        &[spent.iter().map(Note::commitment).collect()],
        1,
    ));
    let cm_height = pool.height();
    let lift_blocks = spans.last().map_or(0, |&(_, end)| end);
    for _ in 0..lift_blocks {
        pool.mine(random_block(rng, 1, 2));
    }
    let plan_anchor = pool.anchor();
    let lift: Vec<_> = spans
        .iter()
        .map(|&(start, end)| {
            build_lift_span(
                rng,
                &pool,
                BlockHeight(cm_height.0 + start)..=BlockHeight(cm_height.0 + end),
            )
        })
        .collect();

    let mut spend_plans = Vec::new();
    let mut spend_pcds = Vec::new();
    let mut descriptors = BTreeSet::new();
    for note in &spent {
        let spendable = wallet.fresh_spend(rng, &pool, cm_height, note);
        assert_eq!(
            spendable.data().2,
            pool.block(cm_height).anchor(),
            "{label}"
        );
        let (rcv, theta) = (value::Trapdoor::random(rng), ActionEntropy::random(rng));
        let plan = action::Plan::spend(*note, theta, rcv, |alpha| {
            wallet.pak.ak.derive_action_public(&alpha)
        });
        descriptors.insert(plan.descriptor());
        spend_plans.push((plan.descriptor(), theta, rcv));
        let secret = wallet.secret_pcd(rng, *note);
        spend_pcds.push((secret, spendable, lift.clone()));
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

    let proved = stamp::Plan::new(spend_plans, output_plans, plan_anchor, max_fee_note, fee)
        .prove(rng, &wallet.pak, spend_pcds)
        .unwrap_or_else(|err| panic!("{label}: the plan proves: {err:?}"));
    let fee_desc = fee_descriptor(&max_fee_note, fee);
    assert_eq!(proved.anchor, plan_anchor, "{label}");
    assert_eq!(proved.fee, fee, "{label}");
    assert_eq!(
        proved.tachygrams.len(),
        2 * (spends + outputs) + 1,
        "{label}"
    );
    assert!(
        proved
            .tachygrams
            .contains(&Tachygram::from(change.commitment())),
        "{label}: the fee change note is published"
    );
    assert!(
        output_cms.iter().all(|cm| proved.tachygrams.contains(cm)),
        "{label}: the output commitments are published"
    );
    assert_eq!(
        proved.tachygram_set,
        TachygramSetPoly::from_iter(proved.tachygrams.iter().copied()).commit(),
        "{label}"
    );
    assert!(
        proved.is_covering(descriptors.iter().copied(), [fee_desc]),
        "{label}: the stamp covers its actions and fee"
    );
    assert!(
        proved
            .verify_proof(rng, digests_of(&descriptors, [fee_desc]))
            .expect("proof system verification"),
        "{label}: the stamp verifies"
    );
}

#[test]
fn anchored_plan_proves_the_planned_actions() {
    let rng = &mut StdRng::seed_from_u64(0);
    assert_plan_proves_its_actions(
        rng,
        "two spends and two outputs",
        (2, 2),
        &[],
        (MAX_MONEY, MAX_MONEY),
    );
}

#[test]
fn lifted_plan_proves_the_planned_actions() {
    let rng = &mut StdRng::seed_from_u64(0);
    for (label, shape, spans) in [
        ("one span over a block", (1, 0), [(0, 1)].as_slice()),
        ("one span over three blocks", (2, 2), &[(0, 3)]),
        (
            "abutting spans split after the spendables' block",
            (1, 1),
            &[(0, 0), (1, 2)],
        ),
        (
            "abutting spans split before the anchor's block",
            (2, 0),
            &[(0, 2), (3, 3)],
        ),
        (
            "overlapping spans sharing the spendables' block",
            (1, 2),
            &[(0, 0), (0, 2)],
        ),
        (
            "overlapping spans sharing the block before the anchor",
            (2, 1),
            &[(0, 2), (2, 3)],
        ),
    ] {
        assert_plan_proves_its_actions(rng, label, shape, spans, (MAX_MONEY, MAX_MONEY / 2));
    }
}

#[test]
fn misassigned_spend_inputs_never_verify() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let stranger = WalletSim::random(rng);
    let notes = [wallet.random_note(300), wallet.random_note(300)];
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
        let proved = stamp::Plan::new(spends, vec![], anchor, max_fee_note, value::Positive::ZERO)
            .prove(prove_rng, &wallet.pak, pcds)
            .unwrap();
        let descriptors: Vec<action::Descriptor> =
            plans.iter().map(action::Plan::descriptor).collect();
        proved
            .verify_proof(prove_rng, digests_of(&descriptors, [fee_desc]))
            .unwrap()
    };

    let planned = [plan_under(&wallet, 0), plan_under(&wallet, 1)];
    let swapped = vec![inputs[1].clone(), inputs[0].clone()];
    assert!(prove_and_verify(rng, &planned, inputs.clone()));
    assert!(!prove_and_verify(rng, &planned, swapped));
    assert!(!prove_and_verify(
        rng,
        &[plan_under(&stranger, 0)],
        vec![inputs[0].clone()]
    ));
}

#[test]
fn merge_requires_a_shared_anchor_and_covers_the_union() {
    let rng = &mut StdRng::seed_from_u64(0);
    let (shared, elsewhere) = (Anchor::random(rng), Anchor::random(rng));
    let (left, left_desc, left_fee) = output_stamp(rng, shared, 2, (MAX_MONEY, MAX_MONEY / 2));
    let (right, right_desc, right_fee) = output_stamp(rng, shared, 1, (1000, 1));
    let (apart, apart_desc, apart_fee) = output_stamp(rng, elsewhere, 1, (1000, 1));
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

    let refused = merge(rng, left_side, (&apart, &apart_desc, apart_fee)).map(drop);
    let Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner))) = refused else {
        panic!("expected InvalidWitness at different anchors, got {refused:?}");
    };
    assert_eq!(inner.to_string(), "StampMerge: anchors must match");

    let merged = merge(rng, left_side, right_side).unwrap();
    let reversed = merge(rng, right_side, left_side).unwrap();
    let fees = [left_fee, right_fee];
    let union = || left_desc.union(&right_desc);
    assert_eq!(merged.anchor, shared);
    assert_eq!(merged.fee, left.fee);
    assert_eq!(reversed.fee, right.fee);
    assert_eq!(merged.coverage, coverage_of(union(), &fees));
    assert_eq!(reversed.coverage, merged.coverage);
    assert_eq!(
        &merged.tachygrams,
        &left
            .tachygrams
            .union(&right.tachygrams)
            .copied()
            .collect::<BTreeSet<Tachygram>>(),
    );
    assert!(
        merged
            .verify_proof(rng, digests_of(union(), fees))
            .expect("proof system verification")
    );

    let foreign = BTreeSet::from([foreign_descriptor(rng)]);
    let mismatched = merge(rng, left_side, (&right, &foreign, right_fee)).unwrap();
    assert!(
        !mismatched
            .verify_proof(rng, digests_of(union(), fees))
            .expect("proof system verification")
    );
}

#[test]
fn overlapping_merges_never_verify() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let forged_verifies =
        |forge_rng: &mut StdRng,
         left: &(ProofStamp, Vec<action::Descriptor>, Vec<fee::Descriptor>),
         right: &(ProofStamp, Vec<action::Descriptor>, Vec<fee::Descriptor>)| {
            let pcd = forge_overlapping_merge(
                forge_rng,
                (&left.0, &left.1, &left.2),
                (&right.0, &right.1, &right.2),
            );
            let descriptors: Vec<action::Descriptor> =
                left.1.iter().chain(&right.1).copied().collect();
            let fees: Vec<fee::Descriptor> = left.2.iter().chain(&right.2).copied().collect();
            let tachygrams: BTreeSet<Tachygram> = left
                .0
                .tachygrams
                .union(&right.0.tachygrams)
                .copied()
                .collect();
            let published = ProofStamp {
                coverage: coverage_of(&descriptors, &fees),
                anchor: pcd.data().2,
                tachygram_set: TachygramSetPoly::from_iter(tachygrams.iter().copied()).commit(),
                tachygrams,
                proof: Box::new(pcd.proof().clone()),
                fee: left.0.fee,
            };
            published
                .verify_proof(forge_rng, digests_of(&descriptors, fees))
                .unwrap()
        };

    let anchor = PoolSim::genesis(rng).anchor();
    let note = wallet.random_note(200);
    let (first, first_plan, first_fee) = build_output_stamp(rng, anchor, note);
    let (again, again_plan, again_fee) = build_output_stamp(rng, anchor, note);
    let output_first = (first, vec![first_plan.descriptor()], vec![first_fee]);
    let output_again = (again, vec![again_plan.descriptor()], vec![again_fee]);

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
    let spend_left = spend_twice(rng);
    let spend_right = spend_twice(rng);
    assert!(
        !spend_left
            .0
            .tachygrams
            .is_disjoint(&spend_right.0.tachygrams),
        "same-note spends share their nullifiers"
    );

    for (label, left, right, refusal) in [
        (
            "a note output twice",
            &output_first,
            &output_again,
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        ),
        (
            "an action counted twice",
            &output_first,
            &output_first,
            "StampMerge: merged action set must be the product of left and right action sets",
        ),
        (
            "a note spent twice",
            &spend_left,
            &spend_right,
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets",
        ),
    ] {
        let honest = left
            .0
            .clone()
            .merge(
                rng,
                (
                    left.1.iter().copied().collect(),
                    left.2.iter().copied().collect(),
                ),
                (
                    right.0.clone(),
                    right.1.iter().copied().collect(),
                    right.2.iter().copied().collect(),
                ),
            )
            .map(drop);
        let Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner))) = honest else {
            panic!("{label}: expected InvalidWitness from the honest merge, got {honest:?}");
        };
        assert_eq!(inner.to_string(), refusal, "{label}");
        assert!(
            !forged_verifies(rng, left, right),
            "{label}: the forged merge verified"
        );
    }
}

#[test]
fn verify_proof_is_exact_on_the_action_multiset() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let (proved, descriptors, fee_desc) = output_stamp(rng, anchor, 3, (300, 100));
    let digests = digests_of(&descriptors, [fee_desc]);
    let foreign = digests_of(&[foreign_descriptor(rng)], [])[0];
    let verifies = |verify_rng: &mut StdRng, handed: Vec<ActionDigest>| {
        proved.verify_proof(verify_rng, handed).unwrap()
    };

    let mut rotated = digests.clone();
    rotated.rotate_left(1);
    let mut reversed = digests.clone();
    reversed.reverse();
    for (label, permuted) in [("rotated", rotated), ("reversed", reversed)] {
        assert!(verifies(rng, permuted), "the {label} digests verify");
    }
    let extended: Vec<ActionDigest> = digests.iter().copied().chain([foreign]).collect();
    assert!(!verifies(rng, extended));
    for index in [0, digests.len() - 1] {
        let mut dropped = digests.clone();
        dropped.remove(index);
        let repeated: Vec<ActionDigest> = digests.iter().copied().chain([digests[index]]).collect();
        let mut substituted = digests.clone();
        substituted[index] = foreign;
        for (label, handed) in [
            ("dropped", dropped),
            ("repeated", repeated),
            ("substituted", substituted),
        ] {
            assert!(!verifies(rng, handed), "digest {index} {label} verified");
        }
    }
}

/// `Bundle::verify_tachygrams`, not the proof, checks the published list.
#[test]
fn proof_binds_the_set_commitment() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let (honest, descriptors, fee_desc) = output_stamp(rng, anchor, 1, (300, 100));
    let digests = digests_of(&descriptors, [fee_desc]);
    assert!(
        honest
            .verify_proof(rng, digests.clone())
            .expect("proof system verification")
    );
    let recommitted = ProofStamp {
        tachygram_set: TachygramSetPoly::from_iter(tachygrams(rng, 3)).commit(),
        ..honest.clone()
    };
    assert!(
        !recommitted
            .verify_proof(rng, digests.clone())
            .expect("proof system verification")
    );
    let mut retold = honest.tachygrams.clone();
    retold.pop_first();
    retold.extend(tachygrams(rng, 1));
    let tampered = ProofStamp {
        tachygrams: retold,
        ..honest
    };
    assert!(
        tampered
            .verify_proof(rng, digests)
            .expect("proof system verification")
    );
}

#[test]
fn lift_moves_the_anchor_and_keeps_the_proof_valid() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut unrelated = PoolSim::genesis(rng);
    for _ in 0..3 {
        unrelated.mine(random_block(rng, 1, 4));
    }
    for (label, stamped_at, distance) in
        [("from genesis by a block", 0, 1), ("by four blocks", 3, 4)]
    {
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 2));
        for _ in 0..stamped_at + distance {
            pool.mine(random_block(rng, 1, 2));
        }
        let stamped_height = BlockHeight(stamped_at);
        let (proved, descriptors, fee_desc) = output_stamp(
            rng,
            pool.block(stamped_height).anchor(),
            1,
            (MAX_MONEY, MAX_MONEY / 2),
        );
        let fees = BTreeSet::from([fee_desc]);
        let mut span =
            || build_lift_span(rng, &pool, stamped_height.next().unwrap()..=pool.height());
        let lift_span = span();
        let foreign_span = span();
        let (later, later_desc, later_fee) = output_stamp(rng, pool.anchor(), 1, (0, 0));
        let later_side = (later, later_desc.clone(), BTreeSet::from([later_fee]));

        let unrelated_span = build_lift_span(rng, &unrelated, BlockHeight(1)..=unrelated.height());
        let refused = proved
            .clone()
            .lift(rng, &descriptors, &fees, vec![unrelated_span])
            .map(drop);
        let Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner))) = refused else {
            panic!("{label}: expected InvalidWitness along an unrelated span, got {refused:?}");
        };
        assert_eq!(
            inner.to_string(),
            "StampLift: stamp anchor is neither the span's start nor a member",
            "{label}"
        );

        let lifted = proved
            .clone()
            .lift(rng, &descriptors, &fees, vec![lift_span])
            .expect("lift");
        assert_eq!(lifted.anchor, pool.anchor(), "{label}");
        assert_eq!(lifted.coverage, proved.coverage, "{label}");
        assert_eq!(lifted.tachygram_set, proved.tachygram_set, "{label}");
        assert_eq!(&lifted.tachygrams, &proved.tachygrams, "{label}");
        assert_eq!(lifted.fee, proved.fee, "{label}");
        assert!(
            lifted
                .verify_proof(rng, digests_of(&descriptors, [fee_desc]))
                .expect("proof system verification"),
            "{label}: the lifted stamp verifies"
        );

        let merged = lifted
            .merge(rng, (descriptors.clone(), fees.clone()), later_side)
            .unwrap();
        assert!(
            merged
                .verify_proof(
                    rng,
                    digests_of(descriptors.iter().chain(&later_desc), [fee_desc, later_fee])
                )
                .expect("proof system verification"),
            "{label}: the merge after the lift verifies"
        );

        let foreign = BTreeSet::from([foreign_descriptor(rng)]);
        let misdescribed = proved
            .lift(rng, &foreign, &fees, vec![foreign_span])
            .unwrap();
        assert!(
            !misdescribed
                .verify_proof(rng, digests_of(&descriptors, [fee_desc]))
                .expect("proof system verification"),
            "{label}: a lift under foreign descriptors verified"
        );
    }
}

#[test]
fn planners_refuse_inputs_that_cannot_make_the_stamp() {
    let rng = &mut StdRng::seed_from_u64(243);
    let wallet = WalletSim::random(rng);
    let ask = wallet.sk.derive_auth_private();
    let sighash = [0u8; 32];
    let spend = |plan_rng: &mut StdRng, note| {
        action::Plan::spend(
            note,
            ActionEntropy::random(plan_rng),
            value::Trapdoor::random(plan_rng),
            |alpha| wallet.pak.ak.derive_action_public(&alpha),
        )
    };
    let output = |plan_rng: &mut StdRng, note| {
        action::Plan::output(
            note,
            ActionEntropy::random(plan_rng),
            value::Trapdoor::random(plan_rng),
        )
    };

    let spent_twice = vec![
        spend(rng, wallet.random_note(MAX_MONEY)),
        spend(rng, wallet.random_note(MAX_MONEY)),
    ];
    let paid_twice = vec![
        output(rng, wallet.random_note(MAX_MONEY)),
        output(rng, wallet.random_note(MAX_MONEY)),
    ];
    for overflowing in [
        bundle::Plan::new(spent_twice, vec![], wallet.random_note(0)),
        bundle::Plan::new(vec![], paid_twice, wallet.random_note(0)),
    ] {
        assert_eq!(overflowing.value_balance(), Err(value::OutOfRange));
        assert_eq!(overflowing.commitment(), Err(value::OutOfRange));
        let Err(err) = overflowing.sign(rng, &sighash, &ask) else {
            panic!("an overflowing plan signed");
        };
        assert_eq!(err, PlanError::BalanceOverflow);
    }

    let planned = bundle::Plan::new(
        vec![spend(rng, wallet.random_note(300))],
        vec![output(rng, wallet.random_note(200))],
        wallet.random_note(100),
    );
    let signed = planned.sign(rng, &sighash, &ask).unwrap();
    let signatures: BTreeMap<action::Descriptor, action::Signature> = signed
        .actions
        .iter()
        .map(|action| (action.descriptor(), action.sig))
        .collect();
    let mut missing = signatures.clone();
    missing.pop_first();
    let mut extra = signatures;
    extra.insert(foreign_descriptor(rng), signed.actions[0].sig);
    for authorized in [missing, extra] {
        let Err(err) = planned.apply_signatures(rng, &sighash, authorized) else {
            panic!("signatures for other actions applied");
        };
        assert_eq!(err, PlanError::ActionSigMismatch);
    }

    let mut pool = PoolSim::genesis(rng);
    let note = wallet.random_note(300);
    pool.mine(random_block_with(rng, &[vec![note.commitment()]], 1));
    let cm_height = pool.height();
    let spendable = wallet.fresh_spend(rng, &pool, cm_height, &note);
    let anchor = spendable.data().2;
    for _ in 0..2 {
        pool.mine(random_block(rng, 1, 2));
    }
    let middle = cm_height.next().unwrap();
    let (plan, _, inputs) =
        wallet.signed(rng, vec![(note, spendable)], vec![], wallet.random_note(0));
    let prove = |prove_rng: &mut StdRng, at, spend_inputs| {
        plan.stamp_plan(at, value::Positive::ZERO)
            .prove(prove_rng, &wallet.pak, spend_inputs)
            .map(drop)
    };
    let (secret, lifting, _) = inputs[0].clone();
    let along = |spans| vec![(secret.clone(), lifting.clone(), spans)];
    let short = vec![build_lift_span(rng, &pool, cm_height..=middle)];
    let gapped = vec![
        build_lift_span(rng, &pool, cm_height..=cm_height),
        build_lift_span(rng, &pool, pool.height()..=pool.height()),
    ];
    let twice = [inputs[0].clone(), inputs[0].clone()].to_vec();
    let elsewhere = Anchor::random(rng);
    let lift = wallet
        .autonome(rng, anchor, vec![], vec![wallet.random_note(200)])
        .lift(rng, &[], vec![])
        .map(drop);
    for (label, result, expected) in [
        (
            "no spend inputs",
            prove(rng, anchor, vec![]),
            "cannot prove 1 spend actions with 0 spendbind inputs",
        ),
        (
            "an extra spend input",
            prove(rng, anchor, twice),
            "cannot prove 1 spend actions with 2 spendbind inputs",
        ),
        (
            "a spend resting at another anchor",
            prove(rng, elsewhere, inputs),
            "spend 0 does not reach the plan's anchor",
        ),
        (
            "a spend lifted along a span ending short",
            prove(rng, pool.anchor(), along(short)),
            "spend 0 does not reach the plan's anchor",
        ),
        (
            "a lift along no span",
            lift,
            "no anchor span proof for no anchor advance",
        ),
    ] {
        let Err(ProveError::MissingPcd(reason)) = result else {
            panic!("{label}: expected MissingPcd, got {result:?}");
        };
        assert_eq!(reason.to_string(), expected, "{label}");
    }

    let gapped_lift = prove(rng, pool.anchor(), along(gapped));
    let Err(ProveError::ProofFailed(ragu_core::Error::InvalidWitness(inner))) = gapped_lift else {
        panic!("spans with a gap: expected InvalidWitness, got {gapped_lift:?}");
    };
    assert_eq!(
        inner.to_string(),
        "ActionLift: actions anchor is neither the span's start nor a member"
    );
}
