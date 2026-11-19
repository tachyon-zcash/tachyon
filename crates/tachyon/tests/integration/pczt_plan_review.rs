use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::pczt::{Bundle, Plan, PlanError};

use super::fixtures::wallet::{WalletSim, output_plan, shared_sk};

#[test]
fn checked_plan_rejects_memo_over_wire_limit() {
    let wallet = WalletSim::new(shared_sk());
    let memo = vec![0; (1 << 25) + 1];
    assert_eq!(
        Plan::new(vec![], vec![], wallet.random_note(0), memo).unwrap_err(),
        PlanError::MemoTooLong,
    );
}

#[test]
fn checked_plan_rejects_duplicate_actions() {
    let rng = &mut StdRng::seed_from_u64(21);
    let wallet = WalletSim::new(shared_sk());
    let output = output_plan(rng, wallet.random_note(100));
    let opening = (output.note, output.theta, output.rcv);
    let max_fee = wallet.random_note(10);
    let plan = Plan::new(vec![], vec![opening], max_fee, vec![1]).unwrap();
    let effects = plan.effects();
    assert_eq!(effects.actions, [output.descriptor()]);
    assert_eq!(effects.memo, vec![1]);
    assert_eq!(
        Bundle::from_plan(&plan).effects().commitment(),
        effects.commitment()
    );
    assert_eq!(
        Plan::new(vec![], vec![opening, opening], max_fee, vec![]).unwrap_err(),
        PlanError::DuplicateAction
    );
}

#[test]
fn section_review_reconstructs_the_checked_plan() {
    let rng = &mut StdRng::seed_from_u64(22);
    let wallet = WalletSim::new(shared_sk());
    let output = output_plan(rng, wallet.random_note(100));
    let plan = Plan::new(
        vec![],
        vec![(output.note, output.theta, output.rcv)],
        wallet.random_note(10),
        vec![],
    )
    .unwrap();
    let section = Bundle::from_plan(&plan);
    section.actions()[0].verify_opening().unwrap();
    assert_eq!(
        section.plan().unwrap().effects().commitment(),
        plan.effects().commitment()
    );
}
