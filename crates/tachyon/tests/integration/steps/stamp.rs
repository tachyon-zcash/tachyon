//! Stamp content: `ActionLift`, `ActionMerge`, `FeeFuse`, `FeeSeed`,
//! `StampLift` and `StampMerge`.

extern crate alloc;

use alloc::{collections::BTreeSet, vec::Vec};
use core::iter;

use ff::Field as _;
use pasta_curves::Fp;
use proptest::{collection::vec, prelude::*, sample::Index};
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

use crate::{
    fixtures::{PoolSim, WalletSim, build_anchor_span_pcd, random_block},
    strategies::{assert_rejections, check, tachygrams},
};

/// An output of `note` under `theta` and `rcv`, proved as `Actions` at
/// `anchor`, with the action digest and the tachygrams it publishes.
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
            Proof::trivial().carry::<()>(()),
        )
        .expect("OutputAction");
    let digest = action::Plan::output(note, theta, rcv)
        .digest()
        .expect("action digest");
    (actions, BTreeSet::from([digest]), BTreeSet::from([cm, pad]))
}

/// The fee digest and fee change note commitment `fee` out of `max_fee_note`
/// contributes.
fn fee_singletons(max_fee_note: Note, fee: value::Positive) -> (ActionDigest, Tachygram) {
    let digest = fee::Descriptor {
        max_commitment: max_fee_note.fee_blind().commit(-max_fee_note.value),
        value: fee,
    }
    .digest()
    .expect("fee digest");
    let change = Note {
        value: value::Positive::try_from(u64::from(max_fee_note.value) - u64::from(fee))
            .expect("the fee is within the maximum"),
        ..max_fee_note
    };
    (digest, Tachygram::from(change.commitment()))
}

/// `actions` with `fee` out of `max_fee_note` applied, and the content of the
/// stamp it proves.
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
            Proof::trivial().carry::<()>(()),
        )
        .expect("FeeFuse");
    let (fee_digest, change) = fee_singletons(max_fee_note, fee);
    let mut stamp_digests = digests.clone();
    stamp_digests.insert(fee_digest);
    let mut stamp_tachygrams = tachygrams.clone();
    stamp_tachygrams.insert(change);
    (stamp, stamp_digests, stamp_tachygrams)
}

/// The set polynomials of a content's action digests and tachygrams.
fn polys(
    digests: &BTreeSet<ActionDigest>,
    tachygrams: &BTreeSet<Tachygram>,
) -> (ActionSetPoly, TachygramSetPoly) {
    (
        digests.iter().copied().collect(),
        tachygrams.iter().copied().collect(),
    )
}

/// The merge witness of `left` and `right`, merged as an honest prover does:
/// the union of their sets.
fn merge_witness(
    (left_digests, left_tachygrams): (&BTreeSet<ActionDigest>, &BTreeSet<Tachygram>),
    (right_digests, right_tachygrams): (&BTreeSet<ActionDigest>, &BTreeSet<Tachygram>),
) -> (
    (ActionSetPoly, TachygramSetPoly),
    (ActionSetPoly, TachygramSetPoly),
    (ActionSetPoly, TachygramSetPoly),
) {
    (
        polys(left_digests, left_tachygrams),
        polys(
            &left_digests.union(right_digests).copied().collect(),
            &left_tachygrams.union(right_tachygrams).copied().collect(),
        ),
        polys(right_digests, right_tachygrams),
    )
}

/// A random output of a fresh wallet.
fn random_output(rng: &mut StdRng, amount: u64) -> (Note, ActionEntropy, value::Trapdoor) {
    (
        WalletSim::random(rng).random_note(amount),
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
    )
}

/// Over any run of blocks of one epoch, the whole epoch included, content
/// anchored at the span's start, at any member or at its end lifts to the
/// span's end and keeps its action and tachygram sets, as `Actions` through
/// `ActionLift` and as a `Stamp` through `StampLift`.
#[test]
fn lifts_reach_the_span_end() {
    let whole_epoch = vec![1usize; usize::try_from(EPOCH_SIZE - 1).unwrap()];
    let blocks = prop_oneof![4 => vec(1usize..=3, 1..=4), 1 => Just(whole_epoch)];
    let strategy = (any::<u64>(), blocks, any::<Index>(), any::<Index>());
    check(8, strategy, |(seed, stamps_per_block, first, at)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
        for &stamps in &stamps_per_block {
            pool.mine(random_block(rng, 1, stamps));
        }
        let start = BlockHeight(u32::try_from(first.index(stamps_per_block.len())).unwrap() + 1);
        let (span, members) = build_anchor_span_pcd(rng, &pool, start..=pool.height());
        let (anchor_start, _, anchor_end) = *span.data();
        let anchors: Vec<Anchor> = iter::once(anchor_start).chain(members.clone()).collect();
        let anchor = anchors[at.index(anchors.len())];

        let planned = random_output(rng, 300);
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
            .expect("ActionLift");
        let (lifted_stamp, ()) = PROOF_SYSTEM
            .fuse(
                rng,
                stamp::StampLift,
                witness::stamp_lift((*stamp_pcd.data(), *span.data()), &members),
                stamp_pcd,
                span,
            )
            .expect("StampLift");
        prop_assert_eq!(
            *lifted_actions.data(),
            (actions_commit, actions_tachygrams, anchor_end)
        );
        prop_assert_eq!(
            *lifted_stamp.data(),
            (stamp_commit, stamp_tachygrams, anchor_end)
        );
        Ok(())
    });
}

/// `ActionLift` and `StampLift` refuse content anchored on a fork of the
/// span, and members other than the span's.
#[test]
fn lift_steps_reject_corruptions() {
    check(8, (any::<u64>(), 1usize..=3), |(seed, stamps)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let mut pool = PoolSim::genesis_with(random_block(rng, 1, 1));
        pool.mine(random_block(rng, 1, stamps));
        let (span, members) = build_anchor_span_pcd(rng, &pool, BlockHeight(1)..=BlockHeight(1));
        let (anchor_start, ..) = *span.data();
        let fork_set = TachygramSetPoly::from_iter(tachygrams(rng, 1)).commit();
        let fork = anchor_start
            .next_stamp(EpochIndex::new(0), &fork_set)
            .unwrap();
        let foreign_members: Vec<Anchor> = members.iter().copied().chain([fork]).collect();

        let content = |content_rng: &mut StdRng, anchor| {
            let planned = random_output(content_rng, 300);
            let (actions, digests, published) = output_actions(content_rng, planned, anchor);
            let max_fee_note = WalletSim::random(content_rng).random_note(0);
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
                PROOF_SYSTEM
                    .fuse(
                        lift_rng,
                        stamp::ActionLift,
                        (AnchorSetPoly::from_iter(witnessed.iter().copied()),),
                        actions.clone(),
                        span.clone(),
                    )
                    .map(drop)
            };
        let stamp_lift =
            |lift_rng: &mut StdRng, stamp_pcd: &Pcd<stamp::Stamp>, witnessed: &[Anchor]| {
                PROOF_SYSTEM
                    .fuse(
                        lift_rng,
                        stamp::StampLift,
                        witness::stamp_lift((*stamp_pcd.data(), *span.data()), witnessed),
                        stamp_pcd.clone(),
                        span.clone(),
                    )
                    .map(drop)
            };
        let (forked_actions, forked_stamp) = content(rng, fork);
        let (member_actions, member_stamp) = content(rng, members[0]);

        assert_rejections([
            (
                "actions anchored on a fork",
                action_lift(rng, &forked_actions, &members),
                "ActionLift: actions anchor is neither the span's start nor a member",
            ),
            (
                "actions lifted along foreign members",
                action_lift(rng, &member_actions, &foreign_members),
                "ActionLift: members do not match header",
            ),
            (
                "a stamp anchored on a fork",
                stamp_lift(rng, &forked_stamp, &members),
                "StampLift: stamp anchor is neither the span's start nor a member",
            ),
            (
                "a stamp lifted along foreign members",
                stamp_lift(rng, &member_stamp, &foreign_members),
                "StampLift: members do not match header",
            ),
        ]);
        Ok(())
    });
}

/// `ActionMerge` and `StampMerge` refuse halves at different anchors, input
/// sets other than the halves' headers, and halves that overlap: a note
/// output twice shares its tachygrams, and an action counted twice shares its
/// digest too, so the honest union is not their product.
#[test]
fn merge_steps_reject_corruptions() {
    check(6, (any::<u64>(), 0..=MAX_MONEY), |(seed, amount)| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let anchor = Anchor::from(Fp::random(&mut *rng));
        let elsewhere = Anchor::from(Fp::random(&mut *rng));
        let planned = random_output(rng, amount);
        let (note, theta, rcv) = planned;
        let (right_output, displaced_output) =
            (random_output(rng, amount), random_output(rng, amount));
        let rerandomized = (note, ActionEntropy::random(rng), rcv);
        let left = output_actions(rng, planned, anchor);
        let right = output_actions(rng, right_output, anchor);
        let displaced = output_actions(rng, displaced_output, elsewhere);
        let reused = output_actions(rng, rerandomized, anchor);
        let repeated = output_actions(rng, (note, theta, rcv), anchor);

        let stamped = |stamp_rng: &mut StdRng,
                       content: &(
            Pcd<stamp::Actions>,
            BTreeSet<ActionDigest>,
            BTreeSet<Tachygram>,
        )| {
            let max_fee_note = WalletSim::random(stamp_rng).random_note(amount);
            apply_fee(
                stamp_rng,
                (&content.0, &content.1, &content.2),
                max_fee_note,
                value::Positive::ZERO,
            )
        };
        let left_stamp = stamped(rng, &left);
        let right_stamp = stamped(rng, &right);
        let displaced_stamp = stamped(rng, &displaced);
        let reused_stamp = stamped(rng, &reused);
        let repeated_stamp = stamped(rng, &repeated);

        let action_merge = |merge_rng: &mut StdRng, merge, right_half: &Pcd<stamp::Actions>| {
            PROOF_SYSTEM
                .fuse(
                    merge_rng,
                    stamp::ActionMerge,
                    merge,
                    left.0.clone(),
                    right_half.clone(),
                )
                .map(drop)
        };
        let stamp_merge = |merge_rng: &mut StdRng, merge, right_half: &Pcd<stamp::Stamp>| {
            PROOF_SYSTEM
                .fuse(
                    merge_rng,
                    stamp::StampMerge,
                    merge,
                    left_stamp.0.clone(),
                    right_half.clone(),
                )
                .map(drop)
        };
        let actions_honest = merge_witness((&left.1, &left.2), (&right.1, &right.2));
        let stamps_honest = merge_witness(
            (&left_stamp.1, &left_stamp.2),
            (&right_stamp.1, &right_stamp.2),
        );
        let ((left_actions, left_tachygrams), merged, (right_actions, right_tachygrams)) =
            actions_honest.clone();
        let (
            (left_stamp_actions, left_stamp_tachygrams),
            stamp_merged,
            (right_stamp_actions, right_stamp_tachygrams),
        ) = stamps_honest.clone();

        PROOF_SYSTEM
            .fuse(
                rng,
                stamp::ActionMerge,
                actions_honest,
                left.0.clone(),
                right.0.clone(),
            )
            .expect("ActionMerge");
        PROOF_SYSTEM
            .fuse(
                rng,
                stamp::StampMerge,
                stamps_honest,
                left_stamp.0.clone(),
                right_stamp.0.clone(),
            )
            .expect("StampMerge");

        assert_rejections([
            (
                "actions at another anchor",
                action_merge(
                    rng,
                    merge_witness((&left.1, &left.2), (&displaced.1, &displaced.2)),
                    &displaced.0,
                ),
                "ActionMerge: anchors must match",
            ),
            (
                "a left action set other than the header's",
                action_merge(
                    rng,
                    (
                        (right_actions.clone(), left_tachygrams.clone()),
                        merged.clone(),
                        (right_actions.clone(), right_tachygrams.clone()),
                    ),
                    &right.0,
                ),
                "ActionMerge: left action accumulator must commit to header commit",
            ),
            (
                "a right action set other than the header's",
                action_merge(
                    rng,
                    (
                        (left_actions.clone(), left_tachygrams.clone()),
                        merged.clone(),
                        (left_actions.clone(), right_tachygrams.clone()),
                    ),
                    &right.0,
                ),
                "ActionMerge: right action accumulator must commit to header commit",
            ),
            (
                "a left tachygram set other than the header's",
                action_merge(
                    rng,
                    (
                        (left_actions.clone(), right_tachygrams.clone()),
                        merged.clone(),
                        (right_actions.clone(), right_tachygrams),
                    ),
                    &right.0,
                ),
                "ActionMerge: left tachygram accumulator must commit to header commit",
            ),
            (
                "a right tachygram set other than the header's",
                action_merge(
                    rng,
                    (
                        (left_actions, left_tachygrams.clone()),
                        merged,
                        (right_actions, left_tachygrams),
                    ),
                    &right.0,
                ),
                "ActionMerge: right tachygram accumulator must commit to header commit",
            ),
            (
                "a note output twice",
                action_merge(
                    rng,
                    merge_witness((&left.1, &left.2), (&reused.1, &reused.2)),
                    &reused.0,
                ),
                "ActionMerge: merged tachygram set must be the product of left and right \
                 tachygram sets",
            ),
            (
                "an action counted twice",
                action_merge(
                    rng,
                    merge_witness((&left.1, &left.2), (&repeated.1, &repeated.2)),
                    &repeated.0,
                ),
                "ActionMerge: merged action set must be the product of left and right action sets",
            ),
            (
                "a stamp at another anchor",
                stamp_merge(
                    rng,
                    merge_witness(
                        (&left_stamp.1, &left_stamp.2),
                        (&displaced_stamp.1, &displaced_stamp.2),
                    ),
                    &displaced_stamp.0,
                ),
                "StampMerge: anchors must match",
            ),
            (
                "a left stamp action set other than the header's",
                stamp_merge(
                    rng,
                    (
                        (right_stamp_actions.clone(), left_stamp_tachygrams.clone()),
                        stamp_merged.clone(),
                        (right_stamp_actions.clone(), right_stamp_tachygrams.clone()),
                    ),
                    &right_stamp.0,
                ),
                "StampMerge: left action accumulator must commit to header commit",
            ),
            (
                "a right stamp action set other than the header's",
                stamp_merge(
                    rng,
                    (
                        (left_stamp_actions.clone(), left_stamp_tachygrams.clone()),
                        stamp_merged.clone(),
                        (left_stamp_actions.clone(), right_stamp_tachygrams.clone()),
                    ),
                    &right_stamp.0,
                ),
                "StampMerge: right action accumulator must commit to header commit",
            ),
            (
                "a left stamp tachygram set other than the header's",
                stamp_merge(
                    rng,
                    (
                        (left_stamp_actions.clone(), right_stamp_tachygrams.clone()),
                        stamp_merged.clone(),
                        (right_stamp_actions.clone(), right_stamp_tachygrams),
                    ),
                    &right_stamp.0,
                ),
                "StampMerge: left tachygram accumulator must commit to header commit",
            ),
            (
                "a right stamp tachygram set other than the header's",
                stamp_merge(
                    rng,
                    (
                        (left_stamp_actions, left_stamp_tachygrams.clone()),
                        stamp_merged,
                        (right_stamp_actions, left_stamp_tachygrams),
                    ),
                    &right_stamp.0,
                ),
                "StampMerge: right tachygram accumulator must commit to header commit",
            ),
            (
                "a stamp outputting the note again",
                stamp_merge(
                    rng,
                    merge_witness(
                        (&left_stamp.1, &left_stamp.2),
                        (&reused_stamp.1, &reused_stamp.2),
                    ),
                    &reused_stamp.0,
                ),
                "StampMerge: merged tachygram set must be the product of left and right \
                 tachygram sets",
            ),
            (
                "a stamp counting the action again",
                stamp_merge(
                    rng,
                    merge_witness(
                        (&left_stamp.1, &left_stamp.2),
                        (&repeated_stamp.1, &repeated_stamp.2),
                    ),
                    &repeated_stamp.0,
                ),
                "StampMerge: merged action set must be the product of left and right action sets",
            ),
        ]);
        Ok(())
    });
}

/// `FeeFuse` turns `Actions` into a `Stamp` at the same anchor whose sets
/// add the fee digest and the fee change note, for any fee up to the
/// maximum; the proof verifies under that header and no other, and the
/// `Actions` proof does not verify as a `Stamp`. `FeeSeed` proves a zero
/// fee's singletons at its witnessed anchor, and verifies under that header
/// and no other.
#[test]
fn fee_steps_bind_their_sets() {
    let fees = (0..=MAX_MONEY).prop_flat_map(|max_fee| (Just(max_fee), 0..=max_fee));
    check(12, (any::<u64>(), fees), |(seed, (max_fee, fee_amount))| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::random(rng);
        let anchor = Anchor::from(Fp::random(&mut *rng));
        let elsewhere = Anchor::from(Fp::random(&mut *rng));
        let max_fee_note = wallet.random_note(max_fee);
        let fee = value::Positive::try_from(fee_amount).unwrap();
        let planned = random_output(rng, 500);
        let (actions, digests, published) = output_actions(rng, planned, anchor);
        let (stamp_pcd, stamp_digests, stamp_tachygrams) =
            apply_fee(rng, (&actions, &digests, &published), max_fee_note, fee);
        let (fee_digest, change) = fee_singletons(max_fee_note, fee);
        let (action_set, tachygram_set) = polys(&stamp_digests, &stamp_tachygrams);
        prop_assert_eq!(stamp_digests.len(), 2);
        prop_assert!(stamp_digests.contains(&fee_digest));
        prop_assert!(stamp_tachygrams.contains(&change));
        prop_assert_eq!(
            *stamp_pcd.data(),
            (action_set.commit(), tachygram_set.commit(), anchor)
        );

        let verifies = |verify_rng: &mut StdRng, pcd: &Pcd<stamp::Stamp>| {
            PROOF_SYSTEM
                .verify(pcd, &mut *verify_rng)
                .expect("proof system verification")
        };
        let recarried = |header| stamp_pcd.proof().clone().carry::<stamp::Stamp>(header);
        let (actions_commit, actions_tachygrams, _) = *actions.data();
        prop_assert!(verifies(rng, &stamp_pcd));
        prop_assert!(!verifies(
            rng,
            &recarried((actions_commit, tachygram_set.commit(), anchor))
        ));
        prop_assert!(!verifies(
            rng,
            &recarried((action_set.commit(), actions_tachygrams, anchor))
        ));
        prop_assert!(!verifies(
            rng,
            &recarried((action_set.commit(), tachygram_set.commit(), elsewhere))
        ));
        prop_assert!(!verifies(
            rng,
            &actions
                .proof()
                .clone()
                .carry::<stamp::Stamp>(*actions.data())
        ));

        let seed_note = wallet.random_note(0);
        let (seed_digest, seed_change) = fee_singletons(seed_note, value::Positive::ZERO);
        let (seed_pcd, ()) = PROOF_SYSTEM
            .seed(
                rng,
                stamp::FeeSeed,
                witness::fee_seed(((), ()), seed_note, anchor),
            )
            .expect("FeeSeed");
        let seed_header = (
            ActionSetPoly::from_iter([seed_digest]).commit(),
            TachygramSetPoly::from_iter([seed_change]).commit(),
            anchor,
        );
        let reseeded = |header| seed_pcd.proof().clone().carry::<stamp::Stamp>(header);
        prop_assert_eq!(*seed_pcd.data(), seed_header);
        prop_assert!(verifies(rng, &seed_pcd));
        prop_assert!(!verifies(
            rng,
            &reseeded((action_set.commit(), seed_header.1, anchor))
        ));
        prop_assert!(!verifies(
            rng,
            &reseeded((seed_header.0, tachygram_set.commit(), anchor))
        ));
        prop_assert!(!verifies(
            rng,
            &reseeded((seed_header.0, seed_header.1, elsewhere))
        ));
        Ok(())
    });
}

/// `FeeFuse` refuses input sets other than the `Actions` header's, a fee
/// above the maximum, and output or fee sets of another fee. `FeeSeed`
/// refuses a nonzero maximum fee and singletons of another seed.
#[test]
fn fee_steps_reject_corruptions() {
    let fees = (1..MAX_MONEY).prop_flat_map(|max_fee| (Just(max_fee), 0..max_fee));
    check(12, (any::<u64>(), fees), |(seed, (max_fee, fee_amount))| {
        let rng = &mut StdRng::seed_from_u64(seed);
        let wallet = WalletSim::random(rng);
        let anchor = Anchor::from(Fp::random(&mut *rng));
        let max_fee_note = wallet.random_note(max_fee);
        let (fee, other_fee) = (
            value::Positive::try_from(fee_amount).unwrap(),
            value::Positive::try_from(fee_amount + 1).unwrap(),
        );
        let planned = random_output(rng, 500);
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
            PROOF_SYSTEM
                .fuse(
                    fuse_rng,
                    stamp::FeeFuse,
                    (max_fee_note, applied, left_sets, output, fee_singleton),
                    actions.clone(),
                    Proof::trivial().carry::<()>(()),
                )
                .map(drop)
        };
        let honest_left = || (left_actions.clone(), left_tachygrams.clone());
        let excess = value::Positive::try_from(max_fee + 1).unwrap();

        let seed_note = wallet.random_note(0);
        let (seed_note_witness, seed_anchor, seed_actions, seed_tachygrams) =
            witness::fee_seed(((), ()), seed_note, anchor);
        let (.., other_seed_actions, other_seed_tachygrams) =
            witness::fee_seed(((), ()), wallet.random_note(0), anchor);
        let fee_seed = |seed_rng: &mut StdRng, seed_witness| {
            PROOF_SYSTEM
                .seed(seed_rng, stamp::FeeSeed, seed_witness)
                .map(drop)
        };
        let funded = Note {
            value: value::Positive::try_from(max_fee).unwrap(),
            ..seed_note_witness
        };

        assert_rejections([
            (
                "a left action set other than the header's",
                fuse(
                    rng,
                    fee,
                    (output_sets.0.clone(), left_tachygrams.clone()),
                    output_sets.clone(),
                    fee_sets.clone(),
                ),
                "FeeFuse: left action accumulator must commit to header commit",
            ),
            (
                "a left tachygram set other than the header's",
                fuse(
                    rng,
                    fee,
                    (left_actions.clone(), output_sets.1.clone()),
                    output_sets.clone(),
                    fee_sets.clone(),
                ),
                "FeeFuse: left tachygram accumulator must commit to header commit",
            ),
            (
                "a fee above the maximum",
                fuse(
                    rng,
                    excess,
                    honest_left(),
                    output_sets.clone(),
                    fee_sets.clone(),
                ),
                "FeeFuse: change is out of range",
            ),
            (
                "the fee action set of another fee",
                fuse(
                    rng,
                    fee,
                    honest_left(),
                    output_sets.clone(),
                    (other_fee_sets.0.clone(), fee_sets.1.clone()),
                ),
                "FeeFuse: fee action set does not commit to the fee digest",
            ),
            (
                "the fee tachygram set of another fee",
                fuse(
                    rng,
                    fee,
                    honest_left(),
                    output_sets.clone(),
                    (fee_sets.0.clone(), other_fee_sets.1),
                ),
                "FeeFuse: fee tachygram set does not commit to the fee change note",
            ),
            (
                "the output action set of another fee",
                fuse(
                    rng,
                    fee,
                    honest_left(),
                    (other_output_sets.0.clone(), output_sets.1.clone()),
                    fee_sets.clone(),
                ),
                "FeeFuse: output action set must be the product of left and fee action sets",
            ),
            (
                "the output tachygram set of another fee",
                fuse(
                    rng,
                    fee,
                    honest_left(),
                    (output_sets.0, other_output_sets.1),
                    fee_sets,
                ),
                "FeeFuse: output tachygram set must be the product of left and fee tachygram sets",
            ),
            (
                "a seed with a nonzero maximum fee",
                fee_seed(
                    rng,
                    (
                        funded,
                        seed_anchor,
                        seed_actions.clone(),
                        seed_tachygrams.clone(),
                    ),
                ),
                "FeeSeed: maximum fee must be zero",
            ),
            (
                "the fee action set of another seed",
                fee_seed(
                    rng,
                    (
                        seed_note_witness,
                        seed_anchor,
                        other_seed_actions,
                        seed_tachygrams,
                    ),
                ),
                "FeeSeed: fee action set does not commit to the fee digest",
            ),
            (
                "the fee tachygram set of another seed",
                fee_seed(
                    rng,
                    (
                        seed_note_witness,
                        seed_anchor,
                        seed_actions,
                        other_seed_tachygrams,
                    ),
                ),
                "FeeSeed: fee tachygram set does not commit to the fee change note",
            ),
        ]);
        Ok(())
    });
}
