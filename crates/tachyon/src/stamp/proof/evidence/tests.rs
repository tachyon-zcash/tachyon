use ragu_primitives::Simulator;

use super::*;

#[test]
fn network_comparison_rejects_each_independent_field_mismatch() {
    for changed in 0..=4 {
        let expected = [5u64, 7, 11, 13].map(Fp::from);
        let mut candidate = expected;
        if changed < 4 {
            candidate[changed] += Fp::ONE;
        }
        let result = Simulator::<Fp>::simulate(candidate, |driver, assignment| {
            let left = expected.map(|value| Element::constant(driver, value));
            let right = [0, 1, 2, 3]
                .map(|index| {
                    Element::alloc(
                        driver,
                        &mut (),
                        assignment.as_ref().map(|values| values[index]),
                    )
                })
                .map(|result| result.unwrap());
            enforce_equal_fields(
                driver,
                &left,
                &right,
                ["epoch", "start", "end", "discriminant"],
            )
        });
        assert_eq!(result.is_ok(), changed == 4);
    }
}
