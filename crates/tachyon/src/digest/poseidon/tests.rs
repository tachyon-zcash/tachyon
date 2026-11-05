use ragu_primitives::{GadgetExt as _, Simulator};

use super::*;

#[test]
fn protocol_digest_circuits_emit_gates_and_reject_independent_roots() {
    let input = [Fp::from(2), Fp::from(3), Fp::from(5), Fp::from(7)];
    for operation in 0..6 {
        let expected = match operation {
            0 => note_commitment(input[0], input[1], 5, input[3]),
            1 => payment_key((input[0], input[1]), input[2]),
            2 => action_digest((input[0], input[1]), (input[2], input[3])),
            3 => fee_blind(input[0], input[1], input[2]),
            4 => fee_digest((input[0], input[1]), 5),
            5 => evidence_tree_node(input),
            _ => unreachable!(),
        };
        for wrong in [false, true] {
            let claimed = expected + if wrong { Fp::ONE } else { Fp::ZERO };
            let result = Simulator::<Fp>::simulate((input, claimed), |driver, assignment| {
                let fields = [
                    Element::alloc(
                        driver,
                        &mut (),
                        assignment.as_ref().map(|values| values.0[0]),
                    )?,
                    Element::alloc(
                        driver,
                        &mut (),
                        assignment.as_ref().map(|values| values.0[1]),
                    )?,
                    Element::alloc(
                        driver,
                        &mut (),
                        assignment.as_ref().map(|values| values.0[2]),
                    )?,
                    Element::alloc(
                        driver,
                        &mut (),
                        assignment.as_ref().map(|values| values.0[3]),
                    )?,
                ];
                let before = driver.num_gates();
                let digest = match operation {
                    0 => note_commitment_circuit(driver, &fields)?,
                    1 => payment_key_circuit(
                        driver,
                        &[fields[0].clone(), fields[1].clone(), fields[2].clone()],
                    )?,
                    2 => action_digest_circuit(driver, &fields)?,
                    3 => fee_blind_circuit(
                        driver,
                        &[fields[0].clone(), fields[1].clone(), fields[2].clone()],
                    )?,
                    4 => fee_digest_circuit(
                        driver,
                        &[fields[0].clone(), fields[1].clone(), fields[2].clone()],
                    )?,
                    5 => evidence_tree_node_circuit(driver, &fields)?,
                    _ => unreachable!(),
                };
                assert!(driver.num_gates() > before + 1);
                let target = Element::alloc(driver, &mut (), assignment.map(|values| values.1))?;
                digest.enforce_equal(driver, &target)
            });
            assert_eq!(result.is_ok(), !wrong);
        }
    }
}

#[test]
fn nullifier_group_circuit_is_driver_bound_at_all_four_lanes() {
    let master = Fp::from(19);
    let epoch_start = Fp::from(32);
    let expected = nullifier_group(master, epoch_start);
    for wrong in [false, true] {
        let result = Simulator::<Fp>::simulate((master, epoch_start), |driver, assignment| {
            let master_element =
                Element::alloc(driver, &mut (), assignment.as_ref().map(|values| values.0))?;
            let epoch_element = Element::alloc(driver, &mut (), assignment.map(|values| values.1))?;
            let before = driver.num_gates();
            let actual = nullifier_group_circuit(driver, &master_element, &epoch_element)?;
            assert!(driver.num_gates() > before + PoseidonFp::RATE);
            for (index, (element, expected_value)) in actual.iter().zip(expected).enumerate() {
                let claimed = expected_value
                    + if wrong && index == 0 {
                        Fp::ONE
                    } else {
                        Fp::ZERO
                    };
                let target = Element::constant(driver, claimed);
                element.enforce_equal(driver, &target)?;
            }
            Ok(())
        });
        assert_eq!(result.is_ok(), !wrong);
    }
}
