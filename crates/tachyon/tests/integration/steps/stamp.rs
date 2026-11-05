extern crate alloc;

use alloc::{collections::BTreeSet, vec::Vec};
use core::iter;

use ragu::{Pcd, Proof};
use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{
    ActionDigest, ActionSetPoly, Anchor, AnchorSetPoly, BlockHeight, EpochIndex, Tachygram,
    TachygramSetPoly, action,
    constants::{EPOCH_SIZE, MAX_MONEY},
    entropy::ActionEntropy,
    fee,
    note::Note,
    stamp::proof::{PROOF_SYSTEM, output, stamp},
    value, witness,
};

use crate::fixtures::{PoolSim, WalletSim, build_anchor_span_pcd};

fn output_actions(
    rng: &mut StdRng,
    (note, theta, rcv): (Note, ActionEntropy, value::Trapdoor),
    anchor: Anchor,
) -> (
    Pcd<stamp::Actions>,
    BTreeSet<ActionDigest>,
    BTreeSet<Tachygram>,
) {
    let (bind, ()) = PROOF_SYSTEM
        .seed(rng, output::OutputBind, (note, rcv))
        .expect("OutputBind");
    let (cm, pad, _) = *bind.data();
    let (actions, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::OutputAction,
            witness::output_action((*bind.data(), ()), theta, anchor),
            bind,
            Proof::bootstrap().carry::<()>(()),
        )
        .expect("OutputAction");
    let digest = action::Plan::output(note, theta, rcv)
        .digest()
        .expect("action digest");
    (actions, BTreeSet::from([digest]), BTreeSet::from([cm, pad]))
}

fn fee_singletons(max_fee_note: Note, fee: value::Positive) -> (ActionDigest, Tachygram) {
    let digest = fee::Descriptor {
        max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
        value: fee,
    }
    .digest()
    .expect("fee digest");
    let change = Note {
        value: value::Positive::try_from(u64::from(max_fee_note.value) - u64::from(fee)).unwrap(),
        ..max_fee_note
    };
    (digest, Tachygram::from(change.commitment()))
}

fn apply_fee(
    rng: &mut StdRng,
    (actions, digests, tachygrams): (
        &Pcd<stamp::Actions>,
        &BTreeSet<ActionDigest>,
        &BTreeSet<Tachygram>,
    ),
    max_fee_note: Note,
    fee: value::Positive,
) -> (
    Pcd<stamp::Stamp>,
    BTreeSet<ActionDigest>,
    BTreeSet<Tachygram>,
) {
    let (stamp, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::FeeFuse,
            witness::fee_fuse(
                (*actions.data(), ()),
                max_fee_note,
                fee,
                digests,
                tachygrams,
            ),
            actions.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
        .unwrap();
    let (fee_digest, change) = fee_singletons(max_fee_note, fee);
    let mut stamp_digests = digests.clone();
    stamp_digests.insert(fee_digest);
    let mut stamp_tachygrams = tachygrams.clone();
    stamp_tachygrams.insert(change);
    (stamp, stamp_digests, stamp_tachygrams)
}

#[test]
fn lifts_reach_the_span_end() {
    let rng = &mut StdRng::seed_from_u64(0);
    let whole_epoch: Vec<usize> =
        iter::repeat_n(1, usize::try_from(EPOCH_SIZE - 1).unwrap()).collect();
    let rows: [(&[usize], usize, usize); 4] = [
        (&[1], 0, 0),
        (&[1, 3, 2, 3], 0, 3),
        (&[3, 1, 2], 2, 1),
        (whole_epoch.as_slice(), 0, whole_epoch.len() / 2),
    ];
    for (stamps_per_block, first, at) in rows {
        let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::random(rng)]]);
        for &stamps in stamps_per_block {
            pool.mine(
                iter::repeat_with(|| vec![Tachygram::random(rng)])
                    .take(stamps)
                    .collect(),
            );
        }
        let start = BlockHeight(u32::try_from(first).unwrap() + 1);
        let (span, members) = build_anchor_span_pcd(rng, &pool, start..=pool.height());
        let (anchor_start, _, anchor_end) = *span.data();
        let anchors: Vec<Anchor> = iter::once(anchor_start).chain(members.clone()).collect();

        for (position, anchor) in [
            ("the start", anchor_start),
            ("a member", anchors[at]),
            ("the end", anchor_end),
        ] {
            let case = format!(
                "{} blocks from block {first}, anchored at {position}",
                stamps_per_block.len()
            );
            let planned = (
                WalletSim::random(rng).random_note(300),
                ActionEntropy::random(rng),
                value::Trapdoor::random(rng),
            );
            let (actions, digests, published) = output_actions(rng, planned, anchor);
            let max_fee_note = WalletSim::random(rng).random_note(100);
            let (stamp_pcd, ..) = apply_fee(
                rng,
                (&actions, &digests, &published),
                max_fee_note,
                value::Positive::try_from(40u64).unwrap(),
            );
            let (actions_commit, actions_tachygrams, _) = *actions.data();
            let (stamp_commit, stamp_tachygrams, _) = *stamp_pcd.data();

            let (lifted_actions, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    stamp::ActionLift,
                    (AnchorSetPoly::from_iter(members.iter().copied()),),
                    actions,
                    span.clone(),
                )
                .unwrap();
            let (lifted_stamp, ()) = PROOF_SYSTEM
                .fuse(
                    rng,
                    stamp::StampLift,
                    witness::stamp_lift((*stamp_pcd.data(), *span.data()), &members),
                    stamp_pcd,
                    span.clone(),
                )
                .unwrap();
            assert_eq!(
                *lifted_actions.data(),
                (actions_commit, actions_tachygrams, anchor_end),
                "{case}: the lifted actions"
            );
            assert_eq!(
                *lifted_stamp.data(),
                (stamp_commit, stamp_tachygrams, anchor_end),
                "{case}: the lifted stamp"
            );
        }
    }
}

#[test]
fn lift_steps_reject_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let mut pool = PoolSim::genesis_with(vec![vec![Tachygram::random(rng)]]);
    pool.mine(vec![
        vec![Tachygram::random(rng)],
        vec![Tachygram::random(rng)],
    ]);
    let (span, members) = build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(1));
    let (anchor_start, ..) = *span.data();
    let fork_set = TachygramSetPoly::from_iter(vec![Tachygram::random(rng)]).commit();
    let fork = anchor_start
        .next_stamp(EpochIndex::new(0), &fork_set)
        .unwrap();
    let foreign_members: Vec<Anchor> = members.iter().copied().chain([fork]).collect();

    let content = |content_rng: &mut StdRng, anchor| {
        let planned = (
            WalletSim::random(content_rng).random_note(300),
            ActionEntropy::random(content_rng),
            value::Trapdoor::random(content_rng),
        );
        let (actions, digests, published) = output_actions(content_rng, planned, anchor);
        let max_fee_note = WalletSim::random(content_rng).random_note(300);
        let (stamp_pcd, ..) = apply_fee(
            content_rng,
            (&actions, &digests, &published),
            max_fee_note,
            value::Positive::ZERO,
        );
        (actions, stamp_pcd)
    };
    let action_lift =
        |lift_rng: &mut StdRng, actions: &Pcd<stamp::Actions>, witnessed: &[Anchor]| {
            PROOF_SYSTEM.fuse(
                lift_rng,
                stamp::ActionLift,
                (AnchorSetPoly::from_iter(witnessed.iter().copied()),),
                actions.clone(),
                span.clone(),
            )
        };
    let stamp_lift =
        |lift_rng: &mut StdRng, stamp_pcd: &Pcd<stamp::Stamp>, witnessed: &[Anchor]| {
            PROOF_SYSTEM.fuse(
                lift_rng,
                stamp::StampLift,
                witness::stamp_lift((*stamp_pcd.data(), *span.data()), witnessed),
                stamp_pcd.clone(),
                span.clone(),
            )
        };
    let (forked_actions, forked_stamp) = content(rng, fork);
    let (member_actions, member_stamp) = content(rng, members[0]);

    {
        let Err(ragu_core::Error::InvalidWitness(err)) =
            action_lift(rng, &forked_actions, &members)
        else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "ActionLift: actions anchor is neither the span's start nor a member"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) =
            action_lift(rng, &member_actions, &foreign_members)
        else {
            panic!();
        };
        assert_eq!(err.to_string(), "ActionLift: members do not match header");
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = stamp_lift(rng, &forked_stamp, &members)
        else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampLift: stamp anchor is neither the span's start nor a member"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) =
            stamp_lift(rng, &member_stamp, &foreign_members)
        else {
            panic!();
        };
        assert_eq!(err.to_string(), "StampLift: members do not match header");
    }
}

#[test]
fn action_merge_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let elsewhere = Anchor::random(rng);
    let (note, theta, rcv) = (
        WalletSim::random(rng).random_note(300),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    let right_output = (
        WalletSim::random(rng).random_note(300),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    let displaced_output = (
        WalletSim::random(rng).random_note(300),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    let rerandomized = (note, ActionEntropy::random(rng), rcv);
    let [left, right, displaced, reused, repeated] = [
        output_actions(rng, (note, theta, rcv), anchor),
        output_actions(rng, right_output, anchor),
        output_actions(rng, displaced_output, elsewhere),
        output_actions(rng, rerandomized, anchor),
        output_actions(rng, (note, theta, rcv), anchor),
    ];
    let merge = |merge_rng: &mut StdRng, merge, right_half: &Pcd<stamp::Actions>| {
        PROOF_SYSTEM.fuse(
            merge_rng,
            stamp::ActionMerge,
            merge,
            left.0.clone(),
            right_half.clone(),
        )
    };
    let honest = (
        (
            left.1.iter().copied().collect(),
            left.2.iter().copied().collect(),
        ),
        (
            left.1.union(&right.1).copied().collect(),
            left.2.union(&right.2).copied().collect(),
        ),
        (
            right.1.iter().copied().collect(),
            right.2.iter().copied().collect(),
        ),
    );
    let ((left_actions, left_tachygrams), merged, (right_actions, right_tachygrams)) =
        honest.clone();

    let (merged_actions, ()) = merge(rng, honest, &right.0).unwrap();
    assert_eq!(
        *merged_actions.data(),
        (merged.0.commit(), merged.1.commit(), left.0.data().2)
    );

    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (
                    left.1.iter().copied().collect(),
                    left.2.iter().copied().collect(),
                ),
                (
                    left.1.union(&displaced.1).copied().collect(),
                    left.2.union(&displaced.2).copied().collect(),
                ),
                (
                    displaced.1.iter().copied().collect(),
                    displaced.2.iter().copied().collect(),
                ),
            ),
            &displaced.0,
        ) else {
            panic!();
        };
        assert_eq!(err.to_string(), "ActionMerge: anchors must match");
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (right_actions.clone(), left_tachygrams.clone()),
                merged.clone(),
                (right_actions.clone(), right_tachygrams.clone()),
            ),
            &right.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "ActionMerge: left action accumulator must commit to header commit"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (left_actions.clone(), left_tachygrams.clone()),
                merged.clone(),
                (left_actions.clone(), right_tachygrams.clone()),
            ),
            &right.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "ActionMerge: right action accumulator must commit to header commit"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (left_actions.clone(), right_tachygrams.clone()),
                merged.clone(),
                (right_actions.clone(), right_tachygrams),
            ),
            &right.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "ActionMerge: left tachygram accumulator must commit to header commit"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (left_actions, left_tachygrams.clone()),
                merged,
                (right_actions, left_tachygrams),
            ),
            &right.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "ActionMerge: right tachygram accumulator must commit to header commit"
        );
    }
    // A reused note repeats its tachygrams and a repeated action its digest.
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (
                    left.1.iter().copied().collect(),
                    left.2.iter().copied().collect(),
                ),
                (
                    left.1.union(&reused.1).copied().collect(),
                    left.2.union(&reused.2).copied().collect(),
                ),
                (
                    reused.1.iter().copied().collect(),
                    reused.2.iter().copied().collect(),
                ),
            ),
            &reused.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "ActionMerge: merged tachygram set must be the product of left and right tachygram sets"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (
                    left.1.iter().copied().collect(),
                    left.2.iter().copied().collect(),
                ),
                (
                    left.1.union(&repeated.1).copied().collect(),
                    left.2.union(&repeated.2).copied().collect(),
                ),
                (
                    repeated.1.iter().copied().collect(),
                    repeated.2.iter().copied().collect(),
                ),
            ),
            &repeated.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "ActionMerge: merged action set must be the product of left and right action sets"
        );
    }
}

#[test]
fn stamp_merge_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let elsewhere = Anchor::random(rng);
    let (note, theta, rcv) = (
        WalletSim::random(rng).random_note(300),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    let right_output = (
        WalletSim::random(rng).random_note(300),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    let displaced_output = (
        WalletSim::random(rng).random_note(300),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    let rerandomized = (note, ActionEntropy::random(rng), rcv);
    let [left, right, displaced, reused, repeated] = [
        output_actions(rng, (note, theta, rcv), anchor),
        output_actions(rng, right_output, anchor),
        output_actions(rng, displaced_output, elsewhere),
        output_actions(rng, rerandomized, anchor),
        output_actions(rng, (note, theta, rcv), anchor),
    ]
    .map(|(actions, digests, published)| {
        let max_fee_note = WalletSim::random(rng).random_note(300);
        apply_fee(
            rng,
            (&actions, &digests, &published),
            max_fee_note,
            value::Positive::ZERO,
        )
    });
    let merge = |merge_rng: &mut StdRng, merge, right_half: &Pcd<stamp::Stamp>| {
        PROOF_SYSTEM.fuse(
            merge_rng,
            stamp::StampMerge,
            merge,
            left.0.clone(),
            right_half.clone(),
        )
    };
    let honest = (
        (
            left.1.iter().copied().collect(),
            left.2.iter().copied().collect(),
        ),
        (
            left.1.union(&right.1).copied().collect(),
            left.2.union(&right.2).copied().collect(),
        ),
        (
            right.1.iter().copied().collect(),
            right.2.iter().copied().collect(),
        ),
    );
    let ((left_actions, left_tachygrams), merged, (right_actions, right_tachygrams)) =
        honest.clone();

    let (merged_stamp, ()) = merge(rng, honest, &right.0).unwrap();
    assert_eq!(
        *merged_stamp.data(),
        (merged.0.commit(), merged.1.commit(), left.0.data().2)
    );

    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (
                    left.1.iter().copied().collect(),
                    left.2.iter().copied().collect(),
                ),
                (
                    left.1.union(&displaced.1).copied().collect(),
                    left.2.union(&displaced.2).copied().collect(),
                ),
                (
                    displaced.1.iter().copied().collect(),
                    displaced.2.iter().copied().collect(),
                ),
            ),
            &displaced.0,
        ) else {
            panic!();
        };
        assert_eq!(err.to_string(), "StampMerge: anchors must match");
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (right_actions.clone(), left_tachygrams.clone()),
                merged.clone(),
                (right_actions.clone(), right_tachygrams.clone()),
            ),
            &right.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampMerge: left action accumulator must commit to header commit"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (left_actions.clone(), left_tachygrams.clone()),
                merged.clone(),
                (left_actions.clone(), right_tachygrams.clone()),
            ),
            &right.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampMerge: right action accumulator must commit to header commit"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (left_actions.clone(), right_tachygrams.clone()),
                merged.clone(),
                (right_actions.clone(), right_tachygrams),
            ),
            &right.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampMerge: left tachygram accumulator must commit to header commit"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (left_actions, left_tachygrams.clone()),
                merged,
                (right_actions, left_tachygrams),
            ),
            &right.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampMerge: right tachygram accumulator must commit to header commit"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (
                    left.1.iter().copied().collect(),
                    left.2.iter().copied().collect(),
                ),
                (
                    left.1.union(&reused.1).copied().collect(),
                    left.2.union(&reused.2).copied().collect(),
                ),
                (
                    reused.1.iter().copied().collect(),
                    reused.2.iter().copied().collect(),
                ),
            ),
            &reused.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampMerge: merged tachygram set must be the product of left and right tachygram sets"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = merge(
            rng,
            (
                (
                    left.1.iter().copied().collect(),
                    left.2.iter().copied().collect(),
                ),
                (
                    left.1.union(&repeated.1).copied().collect(),
                    left.2.union(&repeated.2).copied().collect(),
                ),
                (
                    repeated.1.iter().copied().collect(),
                    repeated.2.iter().copied().collect(),
                ),
            ),
            &repeated.0,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampMerge: merged action set must be the product of left and right action sets"
        );
    }
}

#[test]
fn unmerge_binds_its_sets() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let [alice, bob, carol] = [(); 3].map(|()| {
        let planned = (
            WalletSim::random(rng).random_note(300),
            ActionEntropy::random(rng),
            value::Trapdoor::random(rng),
        );
        let (actions, digests, published) = output_actions(rng, planned, anchor);
        let max_fee_note = WalletSim::random(rng).random_note(300);
        apply_fee(
            rng,
            (&actions, &digests, &published),
            max_fee_note,
            value::Positive::ZERO,
        )
    });
    let alice_sets: (ActionSetPoly, TachygramSetPoly) = (
        alice.1.iter().copied().collect(),
        alice.2.iter().copied().collect(),
    );
    let bob_sets: (ActionSetPoly, TachygramSetPoly) = (
        bob.1.iter().copied().collect(),
        bob.2.iter().copied().collect(),
    );
    let union_sets: (ActionSetPoly, TachygramSetPoly) = (
        alice.1.union(&bob.1).copied().collect(),
        alice.2.union(&bob.2).copied().collect(),
    );
    let (alice_bob, ()) = PROOF_SYSTEM
        .fuse(
            rng,
            stamp::StampMerge,
            (alice_sets.clone(), union_sets.clone(), bob_sets.clone()),
            alice.0.clone(),
            bob.0.clone(),
        )
        .unwrap();
    let unmerge = |unmerge_rng: &mut StdRng, unmerge_witness| {
        PROOF_SYSTEM.fuse(
            unmerge_rng,
            stamp::StampUnmerge,
            unmerge_witness,
            alice_bob.clone(),
            bob.0.clone(),
        )
    };
    let valid = (union_sets, alice_sets, bob_sets);
    unmerge(rng, valid.clone()).unwrap();

    let carol_actions: ActionSetPoly = carol.1.iter().copied().collect();
    let carol_tachygrams: TachygramSetPoly = carol.2.iter().copied().collect();
    let mut wrong_dividend_actions = valid.clone();
    wrong_dividend_actions.0.0 = carol_actions.clone();
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = unmerge(rng, wrong_dividend_actions)
        else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampUnmerge: dividend action accumulator must commit to header commit"
        );
    }
    let mut wrong_divisor_actions = valid.clone();
    wrong_divisor_actions.2.0 = carol_actions;
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = unmerge(rng, wrong_divisor_actions) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampUnmerge: divisor action accumulator must commit to header commit"
        );
    }
    let mut wrong_dividend_tachygrams = valid.clone();
    wrong_dividend_tachygrams.0.1 = carol_tachygrams.clone();
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = unmerge(rng, wrong_dividend_tachygrams)
        else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampUnmerge: dividend tachygram accumulator must commit to header commit"
        );
    }
    let mut wrong_divisor_tachygrams = valid.clone();
    wrong_divisor_tachygrams.2.1 = carol_tachygrams;
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = unmerge(rng, wrong_divisor_tachygrams)
        else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampUnmerge: divisor tachygram accumulator must commit to header commit"
        );
    }
    let mut wrong_action_quotient = valid.clone();
    wrong_action_quotient.1.0 = valid.2.0.clone();
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = unmerge(rng, wrong_action_quotient) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampUnmerge: dividend action set must be the product of divisor and quotient action sets"
        );
    }
    let alice_tachygram = *alice.2.first().unwrap();
    let bob_tachygram = *bob.2.first().unwrap();
    let mut wrong_tachygram_quotient = valid;
    wrong_tachygram_quotient.1.1 = alice
        .2
        .iter()
        .copied()
        .filter(|&tachygram| tachygram != alice_tachygram)
        .chain([bob_tachygram])
        .collect();
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = unmerge(rng, wrong_tachygram_quotient)
        else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "StampUnmerge: dividend tachygram set must be the product of divisor and quotient \
         tachygram sets"
        );
    }
}

#[test]
fn fee_steps_prove_their_singletons() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    for (max_fee, fee_amount) in [(0, 0), (MAX_MONEY, 0), (MAX_MONEY, MAX_MONEY)] {
        let case = format!("a fee of {fee_amount} out of {max_fee}");
        let max_fee_note = WalletSim::random(rng).random_note(max_fee);
        let fee = value::Positive::try_from(fee_amount).unwrap();
        let planned = (
            WalletSim::random(rng).random_note(500),
            ActionEntropy::random(rng),
            value::Trapdoor::random(rng),
        );
        let (actions, digests, published) = output_actions(rng, planned, anchor);
        let (stamp_pcd, stamp_digests, stamp_tachygrams) =
            apply_fee(rng, (&actions, &digests, &published), max_fee_note, fee);
        let (fee_digest, change) = fee_singletons(max_fee_note, fee);
        let action_set: ActionSetPoly = stamp_digests.iter().copied().collect();
        let tachygram_set: TachygramSetPoly = stamp_tachygrams.iter().copied().collect();
        assert_eq!(stamp_digests.len(), 2, "{case}: the digest count");
        assert!(
            stamp_digests.contains(&fee_digest),
            "{case}: the fee digest"
        );
        assert!(
            stamp_tachygrams.contains(&change),
            "{case}: the change note"
        );
        assert_eq!(
            *stamp_pcd.data(),
            (action_set.commit(), tachygram_set.commit(), anchor),
            "{case}: the stamp"
        );
    }

    let seed_note = WalletSim::random(rng).random_note(0);
    let (seed_digest, seed_change) = fee_singletons(seed_note, value::Positive::ZERO);
    let (seed_pcd, ()) = PROOF_SYSTEM
        .seed(
            rng,
            stamp::FeeSeed,
            witness::fee_seed(((), ()), seed_note, anchor),
        )
        .unwrap();
    assert_eq!(
        *seed_pcd.data(),
        (
            ActionSetPoly::from_iter([seed_digest]).commit(),
            TachygramSetPoly::from_iter([seed_change]).commit(),
            anchor,
        )
    );
}

#[test]
fn fee_fuse_binds_its_header() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    let elsewhere = Anchor::random(rng);
    let max_fee_note = WalletSim::random(rng).random_note(100);
    let planned = (
        WalletSim::random(rng).random_note(500),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    let (actions, digests, published) = output_actions(rng, planned, anchor);
    let (stamp_pcd, ..) = apply_fee(
        rng,
        (&actions, &digests, &published),
        max_fee_note,
        value::Positive::try_from(40u64).unwrap(),
    );
    let (actions_commit, actions_tachygrams, _) = *actions.data();
    let verifies = |verify_rng: &mut StdRng, pcd: &Pcd<stamp::Stamp>| {
        PROOF_SYSTEM.verify(pcd, &mut *verify_rng).unwrap()
    };

    assert!(verifies(rng, &stamp_pcd));
    let mut actions_set_data = *stamp_pcd.data();
    actions_set_data.0 = actions_commit;
    assert!(!verifies(
        rng,
        &stamp_pcd
            .proof()
            .clone()
            .carry::<stamp::Stamp>(actions_set_data)
    ));
    let mut actions_tachygrams_data = *stamp_pcd.data();
    actions_tachygrams_data.1 = actions_tachygrams;
    assert!(!verifies(
        rng,
        &stamp_pcd
            .proof()
            .clone()
            .carry::<stamp::Stamp>(actions_tachygrams_data)
    ));
    let mut elsewhere_data = *stamp_pcd.data();
    elsewhere_data.2 = elsewhere;
    assert!(!verifies(
        rng,
        &stamp_pcd
            .proof()
            .clone()
            .carry::<stamp::Stamp>(elsewhere_data)
    ));
    assert!(!verifies(
        rng,
        &actions
            .proof()
            .clone()
            .carry::<stamp::Stamp>(*actions.data())
    ));
}

#[test]
fn fee_fuse_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let anchor = Anchor::random(rng);
    // One short of MAX_MONEY, so even the excess fee is a valid value.
    let max_fee_note = WalletSim::random(rng).random_note(MAX_MONEY - 1);
    let (fee, other_fee, excess) = (
        value::Positive::try_from(MAX_MONEY - 2).unwrap(),
        value::Positive::try_from(MAX_MONEY - 1).unwrap(),
        value::Positive::try_from(MAX_MONEY).unwrap(),
    );
    let planned = (
        WalletSim::random(rng).random_note(500),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    );
    let (actions, digests, published) = output_actions(rng, planned, anchor);
    let fee_witness = |applied| {
        witness::fee_fuse(
            (*actions.data(), ()),
            max_fee_note,
            applied,
            &digests,
            &published,
        )
    };
    let (_, _, (left_actions, left_tachygrams), output_sets, fee_sets) = fee_witness(fee);
    let (.., other_output_sets, other_fee_sets) = fee_witness(other_fee);
    let fuse = |fuse_rng: &mut StdRng,
                applied: value::Positive,
                left_sets: (ActionSetPoly, TachygramSetPoly),
                output: (ActionSetPoly, TachygramSetPoly),
                fee_singleton: (ActionSetPoly, TachygramSetPoly)| {
        PROOF_SYSTEM.fuse(
            fuse_rng,
            stamp::FeeFuse,
            (max_fee_note, applied, left_sets, output, fee_singleton),
            actions.clone(),
            Proof::bootstrap().carry::<()>(()),
        )
    };
    let honest_left = || (left_actions.clone(), left_tachygrams.clone());

    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(
            rng,
            fee,
            (output_sets.0.clone(), left_tachygrams.clone()),
            output_sets.clone(),
            fee_sets.clone(),
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "FeeFuse: left action accumulator must commit to header commit"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(
            rng,
            fee,
            (left_actions.clone(), output_sets.1.clone()),
            output_sets.clone(),
            fee_sets.clone(),
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "FeeFuse: left tachygram accumulator must commit to header commit"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(
            rng,
            excess,
            honest_left(),
            output_sets.clone(),
            fee_sets.clone(),
        ) else {
            panic!();
        };
        assert_eq!(err.to_string(), "FeeFuse: change is out of range");
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(
            rng,
            fee,
            honest_left(),
            output_sets.clone(),
            (other_fee_sets.0.clone(), fee_sets.1.clone()),
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "FeeFuse: fee action set does not commit to the fee digest"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(
            rng,
            fee,
            honest_left(),
            output_sets.clone(),
            (fee_sets.0.clone(), other_fee_sets.1),
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "FeeFuse: fee tachygram set does not commit to the fee change note"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(
            rng,
            fee,
            honest_left(),
            (other_output_sets.0.clone(), output_sets.1.clone()),
            fee_sets.clone(),
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "FeeFuse: output action set must be the product of left and fee action sets"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fuse(
            rng,
            fee,
            honest_left(),
            (output_sets.0, other_output_sets.1),
            fee_sets,
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "FeeFuse: output tachygram set must be the product of left and fee tachygram sets"
        );
    }
}

#[test]
fn fee_seed_rejects_corruptions() {
    let rng = &mut StdRng::seed_from_u64(0);
    let wallet = WalletSim::random(rng);
    let anchor = Anchor::random(rng);
    let (seed_note, seed_anchor, seed_actions, seed_tachygrams) =
        witness::fee_seed(((), ()), wallet.random_note(0), anchor);
    let (.., other_seed_actions, other_seed_tachygrams) =
        witness::fee_seed(((), ()), wallet.random_note(0), anchor);
    let fee_seed = |seed_rng: &mut StdRng, seed_witness| {
        PROOF_SYSTEM.seed(seed_rng, stamp::FeeSeed, seed_witness)
    };
    let funded = Note {
        value: value::Positive::try_from(1u64).unwrap(),
        ..seed_note
    };

    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fee_seed(
            rng,
            (
                funded,
                seed_anchor,
                seed_actions.clone(),
                seed_tachygrams.clone(),
            ),
        ) else {
            panic!();
        };
        assert_eq!(err.to_string(), "FeeSeed: maximum fee must be zero");
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fee_seed(
            rng,
            (seed_note, seed_anchor, other_seed_actions, seed_tachygrams),
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "FeeSeed: fee action set does not commit to the fee digest"
        );
    }
    {
        let Err(ragu_core::Error::InvalidWitness(err)) = fee_seed(
            rng,
            (seed_note, seed_anchor, seed_actions, other_seed_tachygrams),
        ) else {
            panic!();
        };
        assert_eq!(
            err.to_string(),
            "FeeSeed: fee tachygram set does not commit to the fee change note"
        );
    }
}
