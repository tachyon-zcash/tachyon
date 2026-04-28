use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    action,
    entropy::ActionEntropy,
    primitives::{DelegationTrapdoor, EpochIndex, effect},
    test_support::{
        PoolSim, WalletSim, build_output_action, ggm_tools::nullifier_pair_from_master,
        random_block, random_block_with,
    },
    value,
};

fn digest(action: &Action) -> ActionDigest {
    ActionDigest::try_from(action).expect("valid action")
}

/// MergeStamp rejects mismatched anchors.
#[test]
fn merge_stamp_rejects_mismatched_anchors() {
    let mut rng = StdRng::seed_from_u64(500);
    let user_a = WalletSim::random(&mut rng);
    let user_b = WalletSim::random(&mut rng);
    let mut pool = PoolSim::new();

    pool.advance(3, |_| random_block(&mut rng, 50));
    let anchor_early = pool.anchor();
    let note_a = user_a.random_note(&mut rng, 200);
    let (rcv_a, alpha_a, action_a) = build_output_action(&mut rng, note_a);
    let stamp_a = Stamp::prove_output(&mut rng, rcv_a, alpha_a, note_a, anchor_early)
        .expect("prove_output a");

    pool.advance(3, |_| random_block(&mut rng, 50));
    let anchor_late = pool.anchor();
    let note_b = user_b.random_note(&mut rng, 300);
    let (rcv_b, alpha_b, action_b) = build_output_action(&mut rng, note_b);
    let stamp_b =
        Stamp::prove_output(&mut rng, rcv_b, alpha_b, note_b, anchor_late).expect("prove_output b");

    assert!(
        Stamp::prove_merge(
            &mut rng,
            (stamp_a, &[digest(&action_a)]),
            (stamp_b, &[digest(&action_b)]),
        )
        .is_err(),
        "merge with mismatched anchors must fail"
    );
}

/// `Plan::prove` rejects every malformed input: empty plans, PCD counts that
/// don't match the spend count (fewer or more), and equal-length PCD sets
/// whose pairing is wrong (a swap is caught at `SpendBind` via the
/// `delegation_id` equality check).
#[test]
#[expect(clippy::too_many_lines, reason = "bundled invalid-input cases")]
fn plan_prove_rejects_invalid_inputs() {
    let mut rng = StdRng::seed_from_u64(602);
    let user = WalletSim::random(&mut rng);
    let mut pool = PoolSim::new();
    let target_epoch = EpochIndex(0);

    // Two notes with distinct trapdoors → distinct delegation_ids. Both cms
    // mined into the same block so each `spendable_init` sees its cm and
    // produces a spendable at the same anchor.
    let note_a = user.random_note(&mut rng, 500);
    let note_b = user.random_note(&mut rng, 700);
    let trap_a = DelegationTrapdoor::random(&mut rng);
    let trap_b = DelegationTrapdoor::random(&mut rng);
    pool.mine(&random_block_with(
        &mut rng,
        &[note_a.commitment(), note_b.commitment()],
        50,
    ));
    let height = pool.tip();
    let anchor = pool.anchor_at(height);
    let prev_chain = pool.prev_chain_at(height);
    let block = pool.block_at(height);

    let master_a = user.note_master(&mut rng, note_a);
    let master_b = user.note_master(&mut rng, note_b);
    let (nf_now_a, nf_next_a) =
        nullifier_pair_from_master(&mut rng, master_a, trap_a, target_epoch);
    let (nf_now_b, nf_next_b) =
        nullifier_pair_from_master(&mut rng, master_b, trap_b, target_epoch);
    let spendable_a =
        user.spendable_init(&mut rng, note_a, trap_a, &pool, height, nf_now_a.clone());
    let spendable_b =
        user.spendable_init(&mut rng, note_b, trap_b, &pool, height, nf_now_b.clone());

    let rcv_a = value::CommitmentTrapdoor::random(&mut rng);
    let theta_a = ActionEntropy::random(&mut rng);
    let alpha_a = theta_a.randomizer::<effect::Spend>(&note_a.commitment());
    let plan_a = action::Plan::spend(note_a, theta_a, rcv_a, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });

    let rcv_b = value::CommitmentTrapdoor::random(&mut rng);
    let theta_b = ActionEntropy::random(&mut rng);
    let alpha_b = theta_b.randomizer::<effect::Spend>(&note_b.commitment());
    let plan_b = action::Plan::spend(note_b, theta_b, rcv_b, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });

    let two_spends = || {
        alloc::vec![
            ((plan_a.cv(), plan_a.rk), (alpha_a, note_a, rcv_a, trap_a)),
            ((plan_b.cv(), plan_b.rk), (alpha_b, note_b, rcv_b, trap_b)),
        ]
    };

    // Empty plan: no actions at all.
    {
        let plan = Plan::new(alloc::vec![], alloc::vec![], anchor);
        assert!(
            matches!(
                plan.prove(&mut rng, &user.pak, alloc::vec![]),
                Err(ProveError::NoActions),
            ),
            "empty plan must return NoActions",
        );
    }

    // Too few PCDs: 2 spends, 1 PCD.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![(
            nf_now_a.clone(),
            nf_next_a.clone(),
            spendable_a.clone(),
            prev_chain,
            block.clone(),
            height,
        )];
        assert!(
            matches!(
                plan.prove(&mut rng, &user.pak, pcds),
                Err(ProveError::SpendableMismatch),
            ),
            "fewer PCDs than spends must return SpendableMismatch",
        );
    }

    // Too many PCDs: 2 spends, 3 PCDs.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![
            (
                nf_now_a.clone(),
                nf_next_a.clone(),
                spendable_a.clone(),
                prev_chain,
                block.clone(),
                height,
            ),
            (
                nf_now_b.clone(),
                nf_next_b.clone(),
                spendable_b.clone(),
                prev_chain,
                block.clone(),
                height,
            ),
            (
                nf_now_a.clone(),
                nf_next_a.clone(),
                spendable_a.clone(),
                prev_chain,
                block.clone(),
                height,
            ),
        ];
        assert!(
            matches!(
                plan.prove(&mut rng, &user.pak, pcds),
                Err(ProveError::SpendableMismatch),
            ),
            "more PCDs than spends must return SpendableMismatch",
        );
    }

    // Correspondence swap: lengths match, pairing is wrong.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![
            (
                nf_now_b,
                nf_next_b,
                spendable_b,
                prev_chain,
                block.clone(),
                height,
            ),
            (nf_now_a, nf_next_a, spendable_a, prev_chain, block, height),
        ];
        assert!(
            matches!(
                plan.prove(&mut rng, &user.pak, pcds),
                Err(ProveError::ProofFailed),
            ),
            "swapped PCD correspondence must return ProofFailed",
        );
    }
}
