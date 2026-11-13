use ragu_primitives::Simulator;
use udon::field::Field as _;

use super::*;

#[test]
fn from_bits_accepts_up_to_max_money() {
    let amount = |value: Fp| {
        Simulator::<Fp>::simulate(value, |driver, assignment| {
            let bits = Uint::alloc(driver, assignment)?;
            Positive::from_bits(driver, &bits)?;
            Ok(())
        })
        .map(|_| ())
    };
    for value in [Fp::ZERO, Fp::from(MAX_MONEY)] {
        amount(value).unwrap();
    }
    amount(Fp::from(MAX_MONEY + 1)).unwrap_err();
}

#[test]
fn split_rejects_a_part_above_the_total() {
    let split = |part: Fp| {
        Simulator::<Fp>::simulate(part, |driver, assignment| {
            let bits = Uint::alloc(driver, Simulator::<Fp>::just(|| Fp::from(1000)))?;
            Positive::from_bits(driver, &bits)?.split(driver, assignment)?;
            Ok(())
        })
        .map(|_| ())
    };
    for part in [Fp::ZERO, Fp::from(1000)] {
        split(part).unwrap();
    }
    split(Fp::from(1001)).unwrap_err();
}
