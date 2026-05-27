use alloc::vec;

use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    action,
    constants::EPOCH_SIZE,
    fixtures::{
        PoolSim, WalletSim, build_output_stamp, random_block, random_block_with, spend_witness,
    },
    primitives::BlockHeight,
};

const WITHIN_EPOCH_ANCHOR_PAIRS: &[(BlockHeight, BlockHeight)] = &[
    (BlockHeight(8), BlockHeight(8)),
    (BlockHeight(0), BlockHeight(1)),
    (BlockHeight(2), BlockHeight(5)),
    (BlockHeight(0), BlockHeight(EPOCH_SIZE - 1)),
];

#[test]
fn merge_stamp_iff_matching_anchors() {
    for &(anchor_height_a, anchor_height_b) in WITHIN_EPOCH_ANCHOR_PAIRS {
        let rng = &mut StdRng::seed_from_u64(0);
        let user_a = WalletSim::random(rng);
        let user_b = WalletSim::random(rng);
        let mut pool = PoolSim::genesis(rng);

        pool.advance(
            usize::try_from(anchor_height_a.0 + 1).expect("fits"),
            |_| random_block(rng, 1, 50),
        );
        let anchor_a = pool.anchor();
        let note_a = user_a.random_note(rng, 200);
        let (stamp_a, plan_a) = build_output_stamp(rng, anchor_a, note_a);

        let n_between = anchor_height_b.0 - anchor_height_a.0;
        pool.advance(usize::try_from(n_between).expect("fits"), |_| {
            random_block(rng, 1, 50)
        });
        let anchor_b = pool.anchor();
        let note_b = user_b.random_note(rng, 300);
        let (stamp_b, plan_b) = build_output_stamp(rng, anchor_b, note_b);

        let result = Stamp::prove_merge(
            rng,
            (stamp_a, &[plan_a.digest().expect("valid plan")]),
            (stamp_b, &[plan_b.digest().expect("valid plan")]),
        );
        assert_eq!(
            result.is_ok(),
            anchor_height_a == anchor_height_b,
            "merge with anchors {anchor_height_a:?} {anchor_height_b:?}"
        );
    }
}

#[test]
fn plan_prove_rejects_invalid_inputs() {
    let rng = &mut StdRng::seed_from_u64(0);
    let user = WalletSim::random(rng);
    let mut pool = PoolSim::genesis(rng);

    let note_a = user.random_note(rng, 500);
    let note_b = user.random_note(rng, 700);
    pool.mine(random_block_with(
        rng,
        &[vec![note_a.commitment()], vec![note_b.commitment()]],
        50,
    ));
    let height = pool.height();
    let anchor = pool.anchor_at(height);

    let sp_a = user.fresh_spend(rng, &pool, height, &note_a);
    let head_a = user.consumed_head(&note_a, 0);
    let tail_a = user.remaining_tail(&note_a, 0);
    let sp_b = user.fresh_spend(rng, &pool, height, &note_b);
    let head_b = user.consumed_head(&note_b, 0);
    let tail_b = user.remaining_tail(&note_b, 0);

    let (rcv_a, theta_a, alpha_a) = spend_witness(rng, &note_a);
    let plan_a = action::Plan::spend(note_a, theta_a, rcv_a, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });

    let (rcv_b, theta_b, alpha_b) = spend_witness(rng, &note_b);
    let plan_b = action::Plan::spend(note_b, theta_b, rcv_b, |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });

    let two_spends = || {
        alloc::vec![
            ((plan_a.cv(), plan_a.rk), (alpha_a, note_a, rcv_a)),
            ((plan_b.cv(), plan_b.rk), (alpha_b, note_b, rcv_b)),
        ]
    };

    // Empty plan: no actions at all.
    {
        let plan = Plan::new(alloc::vec![], alloc::vec![], anchor);
        let err = plan.prove(rng, &user.pak, alloc::vec![]).unwrap_err();
        assert_eq!(alloc::format!("{err}"), "no actions to prove");
    }

    let bundle_a = || (sp_a.clone(), head_a.clone(), tail_a.clone());
    let bundle_b = || (sp_b.clone(), head_b.clone(), tail_b.clone());

    // Too few PCDs: 2 spends, 1 PCD.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![bundle_a()];
        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        assert_eq!(alloc::format!("{err}"), "spendable PCD count mismatch");
    }

    // Too many PCDs: 2 spends, 3 PCDs.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![bundle_a(), bundle_b(), bundle_a()];
        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        assert_eq!(alloc::format!("{err}"), "spendable PCD count mismatch");
    }

    // Correspondence swap: lengths match, pairing is wrong. `prove` builds the
    // nullifier pieces from note_a's `cm` (the planned spend) but note_b's `M`
    // (the swapped bundle); SpendBind re-derives `cm` from the mismatched
    // preimage (note_a fields, note_b psi), so the pieces no longer satisfy the
    // rank-2 pair binding.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![bundle_b(), bundle_a()];
        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        assert_eq!(
            alloc::format!("{err}"),
            "action proof failed: Error(\"SpendBind: pair is not the rank-2 nullifier pair of the witnessed scalars\")",
        );
    }
}
