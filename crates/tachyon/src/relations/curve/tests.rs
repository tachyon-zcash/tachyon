use ragu_primitives::Simulator;

use super::*;
use crate::{pasta::Fq, relations::arithmetic::scalar_bits};

#[test]
fn complete_curve_addition_handles_inverse_points() {
    let generator = EpAffine::generator();
    Simulator::<Fp>::simulate((generator, -generator), |dr, assignment| {
        let left = Point::alloc(dr, assignment.as_ref().map(|candidate| candidate.0))?;
        let right = Point::alloc(dr, assignment.as_ref().map(|candidate| candidate.1))?;
        let left_complete = from_point(dr, &left)?;
        let right_complete = from_point(dr, &right)?;
        assert!(
            add_complete(dr, &left_complete, &right_complete)?
                .2
                .value()
                .take()
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn scalar_multiplication_accepts_scalars_above_the_circuit_field_modulus() {
    Simulator::<Fp>::simulate(-Fq::ONE, |dr, assignment| {
        let bits = scalar_bits(dr, &assignment)?;
        let base = Point::constant(dr, EpAffine::generator())?;
        let scaled = scale(dr, &base, &bits)?;
        assert_eq!(
            scaled.value().take().to_projective(),
            EpAffine::generator().to_projective() * assignment.take()
        );
        Ok(())
    })
    .unwrap();
}
