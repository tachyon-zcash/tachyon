use ragu::primitives::Simulator;

use super::*;
use crate::pasta::Fq;

#[test]
fn alloc_reads_the_low_254_bits_of_a_scalar() {
    let top = Fq::from(2).pow_u64(254);
    for scalar in [Fq::ONE, top + Fq::ONE] {
        Simulator::<Fp>::simulate(scalar, |dr, assignment| {
            let packed = Uint::<_, 254>::alloc(dr, assignment)?.pack(dr)?;
            assert_eq!(*packed.value().take(), Fp::ONE);
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn from_element_accepts_exactly_its_width() {
    let decompose = |value: Fp| {
        Simulator::<Fp>::simulate(value, |driver, assignment| {
            let element = Element::alloc(driver, &mut (), assignment)?;
            Uint::<_, 8>::from_element(driver, &element)?;
            Ok(())
        })
        .map(|_| ())
    };
    for value in [Fp::ZERO, Fp::from(255)] {
        decompose(value).unwrap();
    }
    for value in [Fp::from(256), -Fp::ONE] {
        decompose(value).unwrap_err();
    }
}
