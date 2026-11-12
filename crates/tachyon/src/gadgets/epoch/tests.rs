use ragu_primitives::Simulator;

use super::*;

#[test]
fn epoch_successor_rejects_raw_final_and_out_of_domain_assignments() {
    let successor = |index: Fp| {
        Simulator::<Fp>::simulate(index, |driver, assignment| {
            let epoch = Element::alloc(driver, &mut (), assignment)?;
            EpochIndex::new(driver, &epoch)?;
            EpochIndex::successor(driver, &epoch)?;
            Ok(())
        })
        .map(|_| ())
    };
    for index in [Fp::ZERO, Fp::from(u64::from(EPOCH_MAX - 1))] {
        successor(index).unwrap();
    }
    for index in [
        -Fp::ONE,
        Fp::from(u64::from(EPOCH_MAX)),
        Fp::from(u64::from(EPOCH_MAX) + 1),
    ] {
        successor(index).unwrap_err();
    }
}
