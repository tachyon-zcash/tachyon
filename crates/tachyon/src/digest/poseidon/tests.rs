use ragu_primitives::Simulator;

use super::*;

#[test]
fn protocol_digest_circuits_emit_gates() {
    let input = [Fp::from(2), Fp::from(3), Fp::from(5), Fp::from(7)];
    for operation in 0..6 {
        Simulator::<Fp>::simulate(input, |driver, assignment| {
            let fields = [
                Element::alloc(driver, &mut (), assignment.as_ref().map(|values| values[0]))?,
                Element::alloc(driver, &mut (), assignment.as_ref().map(|values| values[1]))?,
                Element::alloc(driver, &mut (), assignment.as_ref().map(|values| values[2]))?,
                Element::alloc(driver, &mut (), assignment.as_ref().map(|values| values[3]))?,
            ];
            let before = driver.num_gates();
            let _digest = match operation {
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
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn nullifier_group_circuit_emits_gates() {
    Simulator::<Fp>::simulate((Fp::from(19), Fp::from(32)), |driver, assignment| {
        let master = Element::alloc(driver, &mut (), assignment.as_ref().map(|values| values.0))?;
        let epoch_start = Element::alloc(driver, &mut (), assignment.map(|values| values.1))?;
        let before = driver.num_gates();
        nullifier_group_circuit(driver, &master, &epoch_start)?;
        assert!(driver.num_gates() > before + PoseidonFp::RATE);
        Ok(())
    })
    .unwrap();
}
