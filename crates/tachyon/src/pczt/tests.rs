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
