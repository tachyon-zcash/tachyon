use ragu::pasta::Fq;
use ragu_primitives::Simulator;

use super::*;
use crate::gadgets::arithmetic::scalar_bits;

#[test]
fn complete_curve_addition_handles_equal_inverse_and_identity() {
    let generator = EpAffine::generator();
    for (native_left, native_right) in [(generator, generator), (generator, -generator)] {
        Simulator::<Fp>::simulate((native_left, native_right), |dr, assignment| {
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
            let sum = CurvePoint::add(dr, &left, &right)?;
            assert_eq!(
                sum.value().take().to_projective(),
                native_left.to_projective() + native_right.to_projective()
            );
            let identity = CurvePoint::identity(dr)?;
            assert_eq!(
                CurvePoint::add(dr, &identity, &left)?.value().take(),
                left.value().take()
            );
            assert_eq!(
                CurvePoint::add(dr, &left, &identity)?.value().take(),
                left.value().take()
            );
            assert!(
                CurvePoint::add(dr, &identity, &identity)?
                    .value()
                    .take()
                    .is_identity()
            );
            Ok(())
        })
        .unwrap();
    }
}

#[test]
fn scalar_multiplication_matches_native_at_edge_cases() {
    for scalar in [Fq::ZERO, Fq::ONE, Fq::from(2), -Fq::ONE, Fq::from(12345)] {
        Simulator::<Fp>::simulate(scalar, |dr, assignment| {
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
}
