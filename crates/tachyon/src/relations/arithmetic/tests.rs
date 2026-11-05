use ragu_primitives::Simulator;

use super::*;
use crate::constants::MAX_MONEY;

#[test]
fn bounded_amount_rejects_raw_out_of_range_assignments() {
    for (amount, valid) in [
        (Fp::ZERO, true),
        (Fp::from(MAX_MONEY), true),
        (-Fp::ONE, false),
        (Fp::from(MAX_MONEY + 1), false),
        (Fp::from(2).pow_u64(51), false),
    ] {
        let result = Simulator::<Fp>::simulate(amount, |dr, assignment| {
            let element = Element::alloc(dr, &mut (), assignment)?;
            bounded::<_, 51>(dr, &element, MAX_MONEY)
        });
        assert_eq!(result.is_ok(), valid);
    }
}

#[test]
fn epoch_successor_rejects_raw_final_and_out_of_domain_assignments() {
    for (index, valid) in [
        (Fp::ZERO, true),
        (Fp::from(u64::from(EPOCH_MAX - 1)), true),
        (-Fp::ONE, false),
        (Fp::from(u64::from(EPOCH_MAX)), false),
        (Fp::from(u64::from(EPOCH_MAX) + 1), false),
    ] {
        let result = Simulator::<Fp>::simulate(index, |driver, assignment| {
            let epoch = Element::alloc(driver, &mut (), assignment)?;
            epoch_next(driver, &epoch)?;
            Ok(())
        });
        assert_eq!(result.is_ok(), valid);
    }
}
