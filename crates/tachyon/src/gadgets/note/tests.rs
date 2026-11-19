use ragu::primitives::Simulator;
use udon::field::Field as _;

use super::*;

#[test]
fn fee_commitment_matches_native_at_slack_boundaries() {
    for slack in [0, MAX_MONEY] {
        let native = note::Note {
            pk: Fp::ONE.into(),
            value: (MAX_MONEY - slack).try_into().unwrap(),
            psi: Fp::from(2).into(),
            rcm: Fp::from(3).into(),
        };
        Simulator::<Fp>::simulate(Fp::from(slack), |dr, assignment| {
            let slack_bits = Uint::alloc(dr, assignment)?;
            let value = Positive::from_slack(dr, &slack_bits)?;
            assert_eq!(*value.value().take(), Fp::from(u64::from(native.value)));
            let note = Note {
                rcm: Element::constant(dr, Fp::from(native.rcm)),
                pk: Element::constant(dr, Fp::from(native.pk)),
                value,
                psi: Element::constant(dr, Fp::from(native.psi)),
            };
            let commitment = note.cv_feemax(dr, &slack_bits)?;
            assert_eq!(
                commitment.value().take(),
                EpAffine::from(native.cv_feemax())
            );
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn fee_slack_above_max_money_is_rejected() {
    Simulator::<Fp>::simulate(Fp::from(MAX_MONEY + 1), |dr, assignment| {
        let slack = Uint::alloc(dr, assignment)?;
        Positive::from_slack(dr, &slack)?;
        Ok(())
    })
    .map(|_| ())
    .unwrap_err();
}
