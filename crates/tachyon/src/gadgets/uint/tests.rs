use ragu_primitives::Simulator;

use super::*;

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

#[test]
fn enforce_max_accepts_up_to_the_maximum() {
    let bound = |value: Fp| {
        Simulator::<Fp>::simulate(value, |driver, assignment| {
            Uint::<_, 8>::alloc(driver, assignment)?.enforce_max(driver, 200)?;
            Ok(())
        })
        .map(|_| ())
    };
    for value in [Fp::ZERO, Fp::from(200)] {
        bound(value).unwrap();
    }
    for value in [Fp::from(201), Fp::from(255)] {
        bound(value).unwrap_err();
    }
}
