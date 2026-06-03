use alloc::vec;

use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::{
    action,
    constants::EPOCH_SIZE,
    fixtures::{
        PoolSim, WalletSim, build_output_stamp, random_block, random_block_with, spend_witness,
    },
    primitives::{BlockHeight, EpochIndex},
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
    let target_epoch = EpochIndex(0);

    let note_a = user.random_note(rng, 500);
    let note_b = user.random_note(rng, 700);
    pool.mine(random_block_with(
        rng,
        &[vec![note_a.commitment()], vec![note_b.commitment()]],
        50,
    ));
    let height = pool.height();
    let anchor = pool.anchor_at(height);

    let init_nf_a = user.nullifier_pcd(rng, note_a.clone(), target_epoch);
    let spendable_a = user.spendable_init(rng, note_a.clone(), &pool, height, init_nf_a);
    let init_nf_b = user.nullifier_pcd(rng, note_b.clone(), target_epoch);
    let spendable_b = user.spendable_init(rng, note_b.clone(), &pool, height, init_nf_b);

    let (nf_now_a, nf_next_a) = user.nullifier_pair_pcd(rng, note_a.clone(), target_epoch);
    let (nf_now_b, nf_next_b) = user.nullifier_pair_pcd(rng, note_b.clone(), target_epoch);

    let (rcv_a, theta_a, alpha_a) = spend_witness(rng, &note_a);
    let plan_a = action::Plan::spend(note_a.clone(), theta_a, rcv_a.clone(), |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });

    let (rcv_b, theta_b, alpha_b) = spend_witness(rng, &note_b);
    let plan_b = action::Plan::spend(note_b.clone(), theta_b, rcv_b.clone(), |alpha| {
        user.pak.ak.derive_action_public(&alpha)
    });

    let two_spends = || {
        alloc::vec![
            (
                (plan_a.cv(), plan_a.rk),
                (alpha_a, note_a.clone(), rcv_a.clone())
            ),
            (
                (plan_b.cv(), plan_b.rk),
                (alpha_b, note_b.clone(), rcv_b.clone())
            ),
        ]
    };

    // Empty plan: no actions at all.
    {
        let plan = Plan::new(alloc::vec![], alloc::vec![], anchor);
        let err = plan.prove(rng, &user.pak, alloc::vec![]).unwrap_err();
        assert_eq!(alloc::format!("{err}"), "no actions to prove");
    }

    // Too few PCDs: 2 spends, 1 PCD.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![(nf_now_a.clone(), nf_next_a.clone(), spendable_a.clone(),)];
        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        assert_eq!(alloc::format!("{err}"), "spendable PCD count mismatch");
    }

    // Too many PCDs: 2 spends, 3 PCDs.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![
            (nf_now_a.clone(), nf_next_a.clone(), spendable_a.clone()),
            (nf_now_b.clone(), nf_next_b.clone(), spendable_b.clone()),
            (nf_now_a.clone(), nf_next_a.clone(), spendable_a.clone()),
        ];
        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        assert_eq!(alloc::format!("{err}"), "spendable PCD count mismatch");
    }

    // Correspondence swap: lengths match, pairing is wrong.
    {
        let plan = Plan::new(two_spends(), alloc::vec![], anchor);
        let pcds = alloc::vec![
            (nf_now_b, nf_next_b, spendable_b),
            (nf_now_a, nf_next_a, spendable_a),
        ];
        let err = plan.prove(rng, &user.pak, pcds).unwrap_err();
        assert_eq!(
            alloc::format!("{err}"),
            "action proof failed: Error(\"SpendBind: nullifiers not related to note\")",
        );
    }
}
