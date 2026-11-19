use alloc::string::ToString as _;

use rand::{SeedableRng as _, rngs::StdRng};

use super::*;
use crate::pasta::Fq;

#[test]
fn verify_opening_rejects_mismatched_descriptor() {
    let note = Note {
        pk: Fp::ONE.into(),
        value: value::Positive::ZERO,
        psi: Fp::ONE.into(),
        rcm: Fp::ONE.into(),
    };
    let theta = ActionEntropy(Fp::ONE);
    let plan = Plan::new(
        Vec::new(),
        Vec::from([(note, theta, value::ValueTrapdoor(Fq::ONE))]),
        note,
        Vec::new(),
    )
    .unwrap();
    let mut section = Bundle::from_plan(&plan);
    section.actions[0].rcv = Some(value::ValueTrapdoor(Fq::from(2)));
    assert_eq!(
        section.actions[0].verify_opening(),
        Err(VerifyError::DescriptorMismatch),
    );
}

#[test]
fn mirror_round_trips_spend_keys_and_rejects_key_mismatch() {
    let rng = &mut StdRng::seed_from_u64(24);
    let sk = private::SpendingKey::random(rng);
    let pak = sk.derive_proof_private();
    let note = Note {
        pk: sk.derive_payment_key(),
        value: value::Positive::ZERO,
        psi: Fp::ONE.into(),
        rcm: Fp::ONE.into(),
    };
    let plan = Plan::new(
        Vec::from([(
            note,
            ActionEntropy(Fp::ONE),
            value::ValueTrapdoor(Fq::ONE),
            pak.ak,
        )]),
        Vec::from([(
            note,
            ActionEntropy(Fp::ONE),
            value::ValueTrapdoor(Fq::from(2)),
        )]),
        note,
        Vec::new(),
    )
    .unwrap();
    let section = Bundle::from_plan(&plan);
    let spend_index = section
        .actions
        .iter()
        .position(|action| matches!(action.witness, Some(ActionWitness::Spend(_))))
        .unwrap();
    let output_index = 1 - spend_index;
    let mut fields = section.to_mirror();
    let path = Zip32Derivation::new([7; 32], Vec::from([0x8000_0001]));
    let mut spend = mirror::SpendWitness {
        ak: Some(pak.ak.0.into()),
        pak: Some([pak.ak.0.into(), Fp::from(pak.nk).to_bytes()]),
        zip32_derivation: Some(path.clone()),
    };
    fields.actions[spend_index].witness = Some(mirror::ActionWitness::Spend(spend.clone()));
    fields.actions[output_index].witness =
        Some(mirror::ActionWitness::Output(mirror::OutputWitness {
            zip32_derivation: Some(path),
            user_address: Some("recipient".into()),
        }));
    assert_eq!(Bundle::parse(fields.clone()).unwrap().to_mirror(), fields);

    let other = private::SpendingKey::random(rng).derive_proof_private();
    spend.ak = Some(other.ak.0.into());
    fields.actions[spend_index].witness = Some(mirror::ActionWitness::Spend(spend));
    assert_eq!(
        Bundle::parse(fields).unwrap_err().to_string(),
        alloc::format!("spend keys disagree at action {spend_index}")
    );
}
