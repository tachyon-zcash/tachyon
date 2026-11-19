use rand::{SeedableRng as _, rngs::StdRng};
use zcash_tachyon::{entropy::ActionEntropy, pczt, value};

use super::fixtures::{
    mock_sighash,
    wallet::{WalletSim, output_plan, shared_sk},
};

#[test]
fn pczt_finalize_io_retains_output_signature() {
    let rng = &mut StdRng::seed_from_u64(12);
    let wallet = WalletSim::new(shared_sk());
    let action = output_plan(rng, wallet.random_note(100));
    let opening = (action.note, action.theta, action.rcv);
    let fee = wallet.random_note(10);
    let plan = pczt::Plan::new(vec![], vec![opening], fee, vec![1]).unwrap();
    let mut section = pczt::Bundle::from_plan(&plan);
    let sighash = mock_sighash(plan.effects().commitment());
    section.finalize_io(sighash, rng).unwrap();
    let original = section.to_mirror();
    section.finalize_io(sighash, rng).unwrap();
    assert_eq!(section.to_mirror(), original);
}

#[test]
fn pczt_spend_signature_respects_occupied_slot() {
    let rng = &mut StdRng::seed_from_u64(28);
    let wallet = WalletSim::new(shared_sk());
    let ask = wallet.sk.derive_auth_private();
    let plan = pczt::Plan::new(
        vec![(
            wallet.random_note(100),
            ActionEntropy::random(rng),
            value::Trapdoor::random(rng),
            wallet.pak.ak,
        )],
        vec![],
        wallet.random_note(10),
        vec![],
    )
    .unwrap();
    let mut section = pczt::Bundle::from_plan(&plan);
    let mut alternate = section.clone();
    let sighash = mock_sighash(plan.effects().commitment());
    section.sign_at(0, sighash, &ask, rng).unwrap();
    let stored = section.actions()[0].sig().unwrap();
    section.sign_at(0, sighash, &ask, rng).unwrap();
    assert_eq!(section.actions()[0].sig(), Some(stored));
    let distinct_sighash = [0; 32];
    assert_eq!(
        section.sign_at(0, distinct_sighash, &ask, rng),
        Err(pczt::SignError::InvalidStoredSignature)
    );
    alternate.sign_at(0, sighash, &ask, rng).unwrap();
    let alternate_sig = alternate.actions()[0].sig().unwrap();
    assert_ne!(stored, alternate_sig);
    section.apply_signature_at(0, sighash, stored).unwrap();
    assert_eq!(
        section.apply_signature_at(0, sighash, alternate_sig),
        Err(pczt::ApplySignatureError::Conflict)
    );
    assert_eq!(
        section.apply_signature_at(0, distinct_sighash, alternate_sig),
        Err(pczt::ApplySignatureError::InvalidSignature)
    );
    assert_eq!(section.actions()[0].sig(), Some(stored));
}
