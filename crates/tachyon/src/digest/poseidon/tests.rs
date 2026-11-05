use ragu_primitives::Simulator;

use super::*;

#[test]
fn protocol_driver_hashes_emit_gates() {
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
                0 => with_driver::note_commitment(
                    driver, &fields[0], &fields[1], &fields[2], &fields[3],
                )?,
                1 => with_driver::payment_key(driver, (&fields[0], &fields[1]), &fields[2])?,
                2 => with_driver::action_digest(
                    driver,
                    (&fields[0], &fields[1]),
                    (&fields[2], &fields[3]),
                )?,
                3 => with_driver::fee_blind(driver, &fields[0], &fields[1], &fields[2])?,
                4 => with_driver::fee_digest(driver, (&fields[0], &fields[1]), &fields[2])?,
                5 => with_driver::evidence_tree_node(driver, &fields)?,
                _ => unreachable!(),
            };
            assert!(driver.num_gates() > before + 1);
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn nullifier_group_driver_hash_emits_gates() {
    Simulator::<Fp>::simulate((Fp::from(19), Fp::from(32)), |driver, assignment| {
        let master = Element::alloc(driver, &mut (), assignment.as_ref().map(|values| values.0))?;
        let epoch_start = Element::alloc(driver, &mut (), assignment.map(|values| values.1))?;
        let before = driver.num_gates();
        with_driver::nullifier_group(driver, &master, &epoch_start)?;
        assert!(driver.num_gates() > before + PoseidonFp::RATE);
        Ok(())
    })
    .unwrap();
}
