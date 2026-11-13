use ragu_primitives::Simulator;

use super::*;

#[test]
fn next_rejects_the_final_epoch() {
    let next = |index: u32| {
        Simulator::<Fp>::simulate(primitives::EpochIndex::new(index), |driver, assignment| {
            EpochIndex::alloc(driver, &mut (), assignment)?.next(driver)?;
            Ok(())
        })
        .map(|_| ())
    };
    for index in [0, EPOCH_MAX - 1] {
        next(index).unwrap();
    }
    next(EPOCH_MAX).unwrap_err();
}
