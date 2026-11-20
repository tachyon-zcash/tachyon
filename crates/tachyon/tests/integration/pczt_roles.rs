use core::error::Error;

use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{BlockHeight, entropy::ActionEntropy, pczt, value};

use super::fixtures::{
    application, mock_sighash,
    pool::PoolSim,
    wallet::{WalletSim, output_plan, shared_sk},
};

#[test]
#[expect(
    clippy::ref_patterns,
    reason = "borrow the witnesses being inspected and redacted"
)]
fn pczt_roles_and_redaction_round_trip() {
    let rng = &mut StdRng::seed_from_u64(42);
    let app = &application();
    let wallet = WalletSim::new(shared_sk());
    let note = PoolSim::shared_note(1000);
    let spendable = wallet.spendable_init(app, PoolSim::shared(), &note, BlockHeight(1));
    let anchor = spendable.data().2;
    let spend = (
        note,
        ActionEntropy::random(rng),
        value::Trapdoor::random(rng),
        wallet.pak.ak,
    );
    let first = output_plan(rng, wallet.random_note(100));
    let second = output_plan(rng, wallet.random_note(200));
    let plan = pczt::Plan::new(
        vec![spend],
        vec![
            (first.note, first.theta, first.rcv),
            (second.note, second.theta, second.rcv),
        ],
        wallet.random_note(10),
        vec![7],
    )
    .unwrap();
    let mut section = pczt::Bundle::from_plan(&plan);
    let find_index = |desc| plan.effects().actions.binary_search(&desc).unwrap();
    let spend_idx = section
        .actions()
        .iter()
        .position(|action| matches!(action.witness(), Some(&pczt::ActionWitness::Spend(_))))
        .unwrap();
    let first_idx = find_index(first.descriptor());
    let second_idx = find_index(second.descriptor());
    let path = pczt::Zip32Derivation::new([8; 32], vec![0x8000_0001]);
    section
        .update_with(|mut updater| -> Result<(), Box<dyn Error>> {
            updater.set_anchor(anchor);
            updater.set_zip32_derivation(first_idx, path.clone())?;
            updater.set_pak(spend_idx, wallet.pak)?;
            updater.set_lineage(
                spend_idx,
                pczt::SpendLineage::new(wallet.note_secret(app, note), spendable, vec![]),
            )?;
            Ok(())
        })
        .unwrap();
    let sighash = mock_sighash(plan.effects().commitment());
    section.finalize_io(sighash, rng).unwrap();
    let base = section.to_mirror();

    let mut compact = base.clone();
    compact.value_balance = None;
    compact.max_fee.cv_feemax = None;
    compact.bsk = None;
    for action in &mut compact.actions {
        action.descriptor = None;
        action.sig = None;
        if let Some(ref mut witness) = action.witness
            && let pczt::mirror::ActionWitness::Spend(ref mut spend_witness) = *witness
        {
            spend_witness.pak = None;
            spend_witness.lineage = None;
        }
    }
    let mut signer = pczt::Bundle::parse(compact).unwrap();
    assert_eq!(
        signer.plan().unwrap().effects().commitment(),
        plan.effects().commitment()
    );
    signer
        .sign_at(spend_idx, sighash, &wallet.sk.derive_auth_private(), rng)
        .unwrap();
    let sig = signer.actions()[spend_idx].sig().unwrap();
    section.apply_signature_at(spend_idx, sighash, sig).unwrap();

    let mut redacted = base.clone();
    redacted.actions[second_idx].note.psi = None;
    let mut layered = pczt::Bundle::parse(redacted).unwrap();
    assert_eq!(
        layered.plan().unwrap_err(),
        pczt::ReviewError::Missing(pczt::ReviewField::Action(
            second_idx,
            pczt::OpeningField::Note(pczt::NoteField::Psi),
        )),
    );
    layered
        .sign_at(spend_idx, sighash, &wallet.sk.derive_auth_private(), rng)
        .unwrap();
    let authorized_spend = &layered.actions()[spend_idx];
    authorized_spend
        .descriptor()
        .rk
        .verify(&sighash, &authorized_spend.sig().unwrap())
        .unwrap();
    let serialized = layered.to_mirror();
    assert_eq!(serialized.actions[second_idx].note.psi, None);
    let preserved_path = serialized.actions[first_idx]
        .witness
        .as_ref()
        .and_then(|witness| match *witness {
            pczt::mirror::ActionWitness::Output(ref output) => output.zip32_derivation.as_ref(),
            pczt::mirror::ActionWitness::Spend(_) => None,
        });
    assert_eq!(preserved_path, Some(&path));

    let for_prover = |selected: &[usize]| {
        let mut mirror = base.clone();
        mirror.bsk = None;
        mirror.proprietary.clear();
        mirror.max_fee.note.pk = None;
        mirror.max_fee.note.value = None;
        mirror.max_fee.note.psi = None;
        mirror.max_fee.note.rcm = None;
        mirror.max_fee.zip32_derivation = None;
        mirror.max_fee.proprietary.clear();
        for (index, action) in mirror.actions.iter_mut().enumerate() {
            action.sig = None;
            action.proprietary.clear();
            let own = selected.contains(&index);
            if !own || index == spend_idx {
                action.note.pk = None;
                action.note.value = None;
                action.note.psi = None;
                action.note.rcm = None;
            }
            if !own {
                action.theta = None;
                action.rcv = None;
                action.witness = None;
            }
            if let Some(ref mut witness) = action.witness {
                match *witness {
                    pczt::mirror::ActionWitness::Spend(ref mut spend_fields) => {
                        spend_fields.ak = None;
                        spend_fields.zip32_derivation = None;
                    },
                    pczt::mirror::ActionWitness::Output(ref mut output) => {
                        output.zip32_derivation = None;
                        output.user_address = None;
                    },
                }
            }
        }
        pczt::Bundle::parse(mirror).unwrap()
    };
    let mut prover = for_prover(&[spend_idx]);
    prover.prove_actions(rng, app, &[spend_idx]).unwrap();
    let mut other = for_prover(&[first_idx, second_idx]);
    other
        .prove_actions(rng, app, &[first_idx, second_idx])
        .unwrap();
    let combined = prover.combine(other).unwrap();
    let mut complete = section.combine(combined).unwrap();
    complete.apply_fee(rng, app, value::Positive::ZERO).unwrap();
    let encoded = complete.to_mirror();
    assert_eq!(
        pczt::Bundle::parse(encoded.clone()).unwrap().to_mirror(),
        encoded
    );

    let mut extractor = encoded;
    extractor.actions_proofs.clear();
    extractor.anchor = None;
    extractor.max_fee.note.pk = None;
    extractor.max_fee.note.value = None;
    extractor.max_fee.note.psi = None;
    extractor.max_fee.note.rcm = None;
    for action in &mut extractor.actions {
        action.note.pk = None;
        action.note.value = None;
        action.note.psi = None;
        action.note.rcm = None;
        action.theta = None;
        action.rcv = None;
        action.witness = None;
    }
    let unbound = pczt::Bundle::parse(extractor).unwrap().extract().unwrap();
    let built = unbound.apply_binding_signature(sighash, rng);
    built.verify(rng, app, &sighash, &[]).unwrap();
}
