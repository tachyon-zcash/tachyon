use ragu_primitives::Simulator;

use super::*;
use crate::{
    constants::{EPOCH_MAX, MAX_MONEY},
    nullifier::NF_DERIVATION_WIDTH,
};

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
fn one_bit_decomposition_rejects_raw_nonboolean_field_assignments() {
    for (assignment, valid) in [
        (Fp::ZERO, true),
        (Fp::ONE, true),
        (Fp::from(2), false),
        (-Fp::ONE, false),
    ] {
        let result = Simulator::<Fp>::simulate(assignment, |driver, supplied| {
            let element = Element::alloc(driver, &mut (), supplied)?;
            bits::<_, 1>(driver, &element)?;
            Ok(())
        });
        assert_eq!(result.is_ok(), valid);
    }
}

#[test]
fn nullifier_window_end_rejects_raw_overflow_before_header_conversion() {
    let width = u32::try_from(NF_DERIVATION_WIDTH - 1).unwrap();
    let last_start = EPOCH_MAX - width;
    for raw_start in [last_start, EPOCH_MAX - 3] {
        let result =
            Simulator::<Fp>::simulate(Fp::from(u64::from(raw_start)), |driver, supplied| {
                let start = Element::alloc(driver, &mut (), supplied)?;
                bits::<_, 32>(driver, &start)?;
                let offset = Element::constant(driver, Fp::from(u64::from(width)));
                let end = start.add(driver, &offset);
                bounded::<_, 32>(driver, &end, u64::from(EPOCH_MAX))
            });
        assert_eq!(result.is_ok(), raw_start == last_start);
    }
}
