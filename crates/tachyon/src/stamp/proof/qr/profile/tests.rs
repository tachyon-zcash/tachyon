use ragu_primitives::Simulator;

use super::*;

#[test]
fn profile_rejects_invalid_depth_and_register() {
    for (native_depth, native_bits, valid) in [
        (0u32, 0, true),
        (32, u32::MAX, true),
        (33, 0, false),
        (0, 1, false),
        (3, 8, false),
    ] {
        let result =
            Simulator::<Fp>::simulate((native_depth, native_bits), |driver, assignment| {
                let depth = Element::alloc(
                    driver,
                    &mut (),
                    assignment
                        .as_ref()
                        .map(|value| Fp::from(u64::from(value.0))),
                )?;
                let register = Element::alloc(
                    driver,
                    &mut (),
                    assignment.map(|value| Fp::from(u64::from(value.1))),
                )?;
                validate(driver, &depth, &register)?;
                Ok(())
            });
        assert_eq!(result.is_ok(), valid);
    }
}
