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
