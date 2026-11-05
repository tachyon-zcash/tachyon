use ragu::pasta::Fq;
use ragu_primitives::Simulator;

use super::*;
use crate::gadgets::arithmetic::scalar_bits;

#[test]
fn complete_curve_addition_handles_inverse_points() {
    let generator = EpAffine::generator();
    Simulator::<Fp>::simulate((generator, -generator), |dr, assignment| {
        let left = CurvePoint::alloc(
            dr,
            &mut (),
            assignment.as_ref().map(|candidate| candidate.0),
        )?;
        let right = CurvePoint::alloc(
            dr,
            &mut (),
            assignment.as_ref().map(|candidate| candidate.1),
        )?;
        assert!(
            CurvePoint::add(dr, &left, &right)?
                .value()
                .take()
                .is_identity()
        );
        Ok(())
    })
    .unwrap();
}

#[test]
fn scalar_multiplication_accepts_scalars_above_the_circuit_field_modulus() {
    Simulator::<Fp>::simulate(-Fq::ONE, |dr, assignment| {
        let bits = scalar_bits(dr, &assignment)?;
        let base = CurvePoint::constant(dr, EpAffine::generator())?;
        let scaled = CurvePoint::scale(dr, &base, &bits)?;
        assert_eq!(
            scaled.value().take().to_projective(),
            EpAffine::generator().to_projective() * assignment.take()
        );
        Ok(())
    })
    .unwrap();
}
