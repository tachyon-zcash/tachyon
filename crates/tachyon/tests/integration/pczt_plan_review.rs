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

#[test]
#[expect(
    clippy::ref_patterns,
    reason = "borrow the witness fields from the section"
)]
fn updater_attaches_proving_and_signing_metadata() {
    use core::error::Error;

    use zcash_tachyon::{
        BlockHeight,
        entropy::ActionEntropy,
        pasta::Fp,
        pczt::{ActionWitness, SpendLineage, Zip32Derivation},
        value,
    };

    use super::fixtures::{application, pool::PoolSim};

    let rng = &mut StdRng::seed_from_u64(27);
    let app = &application();
    let pool = PoolSim::shared();
    let wallet = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(1000);
    let spendable = wallet.spendable_init(app, pool, &note, BlockHeight(1));
    let anchor = spendable.data().2;
    let lineage = SpendLineage::new(wallet.note_secret(app, note), spendable, vec![]);
    let output = output_plan(rng, wallet.random_note(100));
    let plan = Plan::new(
        vec![(
            note,
            ActionEntropy::random(rng),
            value::Trapdoor::random(rng),
            wallet.pak.ak,
        )],
        vec![(output.note, output.theta, output.rcv)],
        wallet.random_note(10),
        vec![],
    )
    .unwrap();
    let mut section = Bundle::from_plan(&plan);
    let output_index = plan
        .effects()
        .actions
        .binary_search(&output.descriptor())
        .unwrap();
    let spend_index = 1 - output_index;
    let path = Zip32Derivation::new([1; 32], vec![0x8000_0001]);
    section
        .update_with(|mut updater| -> Result<(), Box<dyn Error>> {
            updater.set_anchor(anchor);
            updater.set_pak(spend_index, wallet.pak)?;
            updater.set_lineage(spend_index, lineage)?;
            updater.set_zip32_derivation(spend_index, path.clone())?;
            updater.set_zip32_derivation(output_index, path.clone())?;
            updater.set_max_fee_zip32_derivation(path.clone());
            updater.set_user_address(output_index, "recipient".into())?;
            updater.set_proprietary("global".into(), vec![1]);
            updater.set_action_proprietary(output_index, "action".into(), vec![2])?;
            updater.set_max_fee_proprietary("fee".into(), vec![3]);
            Ok(())
        })
        .unwrap();
    assert_eq!(section.anchor(), Some(anchor));
    let spend = section.actions()[spend_index]
        .witness()
        .and_then(|witness| match *witness {
            ActionWitness::Spend(ref spend) => Some(spend),
            ActionWitness::Output(_) => None,
        })
        .unwrap();
    assert_eq!(
        Fp::from(spend.pak().unwrap().derive_payment_key()),
        Fp::from(wallet.pak.derive_payment_key())
    );
    assert_eq!(spend.lineage().unwrap().spendable().data().2, anchor);
    assert_eq!(spend.zip32_derivation(), Some(&path));
    let recipient = section.actions()[output_index]
        .witness()
        .and_then(|witness| match *witness {
            ActionWitness::Spend(_) => None,
            ActionWitness::Output(ref recipient) => Some(recipient),
        })
        .unwrap();
    assert_eq!(recipient.zip32_derivation(), Some(&path));
    assert_eq!(recipient.user_address(), Some("recipient"));
    assert_eq!(section.max_fee().zip32_derivation(), Some(&path));
    assert_eq!(section.proprietary()["global"], [1]);
    assert_eq!(section.actions()[output_index].proprietary()["action"], [2]);
    assert_eq!(section.max_fee().proprietary()["fee"], [3]);
}
