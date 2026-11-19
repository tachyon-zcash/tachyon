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

#[test]
fn mirror_round_trips_fields_and_rejects_duplicate_descriptors() {
    use zcash_tachyon::{effect, keys::private::ActionSigningKey};

    let rng = &mut StdRng::seed_from_u64(23);
    let wallet = WalletSim::new(shared_sk());
    let output = output_plan(rng, wallet.random_note(100));
    let plan = Plan::new(
        vec![],
        vec![(output.note, output.theta, output.rcv)],
        wallet.random_note(10),
        vec![1, 2],
    )
    .unwrap();
    let mut mirror = Bundle::from_plan(&plan).to_mirror();
    assert!(mirror.actions[0].note.psi.take().is_some());
    let alpha = output
        .theta
        .randomizer::<effect::Output>(output.note.commitment());
    let signature = ActionSigningKey::new(&alpha).sign(rng, &[0; 32]);
    let mut signature_bytes = [0; 64];
    signature.write(signature_bytes.as_mut_slice()).unwrap();
    mirror.actions[0].sig = Some(signature_bytes);
    mirror.bsk = Some([0; 32]);
    assert_eq!(Bundle::parse(mirror.clone()).unwrap().to_mirror(), mirror);

    let mut compact_fee = mirror.clone();
    compact_fee.max_fee.cv_feemax = None;
    assert_eq!(
        Bundle::parse(compact_fee.clone()).unwrap().to_mirror(),
        mirror
    );
    compact_fee.max_fee.note.psi = None;
    assert_eq!(
        Bundle::parse(compact_fee).unwrap_err().to_string(),
        "missing maximum fee note Psi for compact effect"
    );

    mirror.actions.push(mirror.actions[0].clone());
    assert_eq!(
        Bundle::parse(mirror).unwrap_err().to_string(),
        "descriptors are not strictly ascending in actions",
    );
}

#[test]
fn mirror_derives_compact_spend_and_output_effects() {
    use zcash_tachyon::{entropy::ActionEntropy, value};

    let rng = &mut StdRng::seed_from_u64(26);
    let wallet = WalletSim::new(shared_sk());
    let output = output_plan(rng, wallet.random_note(100));
    let plan = Plan::new(
        vec![(
            wallet.random_note(200),
            ActionEntropy::random(rng),
            value::Trapdoor::random(rng),
            wallet.pak.ak,
        )],
        vec![(output.note, output.theta, output.rcv)],
        wallet.random_note(10),
        vec![],
    )
    .unwrap();
    let full = Bundle::from_plan(&plan).to_mirror();
    let mut compact = full.clone();
    compact.value_balance = None;
    for action in &mut compact.actions {
        action.descriptor = None;
    }
    assert_eq!(Bundle::parse(compact.clone()).unwrap().to_mirror(), full);

    compact.actions[0].theta = None;
    assert_eq!(
        Bundle::parse(compact).unwrap_err().to_string(),
        "missing action 0 Theta for compact effect"
    );
}
