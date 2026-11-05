use ragu_primitives::Simulator;

use super::*;

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
            EpochIndexGadget::from(epoch).next(driver)?;
            Ok(())
        });
        assert_eq!(result.is_ok(), valid);
    }
}
