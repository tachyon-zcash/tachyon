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

#[test]
fn group_clears_the_two_low_bits() {
    for (index, group_start) in [(0, 0), (EPOCH_MAX, EPOCH_MAX - 3)] {
        Simulator::<Fp>::simulate(primitives::EpochIndex::new(index), |driver, assignment| {
            let (start, _) = EpochIndex::alloc(driver, &mut (), assignment)?.group(driver)?;
            assert_eq!(*start.value().take(), Fp::from(u64::from(group_start)));
            Ok(())
        })
        .unwrap();
    }
}
