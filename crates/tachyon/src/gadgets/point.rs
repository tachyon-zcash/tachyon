//! Complete circuit point arithmetic.
use alloc::vec::Vec;
use core::marker::PhantomData;

use derive_more::Debug;
use ragu::pasta::{EpAffine, Fp};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget},
    maybe::Maybe as _,
};
use ragu_primitives::{
    Boolean, Element, GadgetExt as _, Point,
    allocator::Allocator,
    io::{Buffer, Write},
    vec::{ConstLen, FixedVec},
};
use udon::{curve::Affine as _, field::Field};
/// Complete affine arithmetic with an explicit infinity flag.
///
/// Externally witnessed/exported points still use `Point`, which
/// rejects infinity. Inactive divisions use denominator one; branch conditions
/// are constrained comparisons, never native decisions.
///
/// `Point::add_incomplete` and `double_and_add_incomplete` exclude equal and
/// inverse inputs, while ordinary scalar multiplication must include zero,
/// one and minus one. `Endoscalar::group_scale` implements the 128-bit signed
/// endomorphism lift, not multiplication by an arbitrary Fq scalar. These
/// complete formulas supply the missing ordinary-scalar operation using
/// `Element` arithmetic and `Boolean` selection; they do not implement foreign
/// field arithmetic.
#[derive(Gadget, Debug)]
#[debug("CurvePoint(..)")]
#[expect(
    clippy::module_name_repetitions,
    reason = "the semantic gadget name is explicit at call sites"
)]
pub struct CurvePoint<'dr, D: Driver<'dr>> {
    pub(crate) x: Element<'dr, D>,
    pub(crate) y: Element<'dr, D>,
    infinity: Boolean<'dr, D>,
}

impl<F: Field> Write<F> for CurvePoint<'static, PhantomData<F>> {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Bound<'dr, D, Self>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        this.infinity.element().enforce_zero(dr)?;
        this.x.write(dr, buf)?;
        this.y.write(dr, buf)
    }
}

impl<'dr, D: Driver<'dr, F = Fp>> CurvePoint<'dr, D> {
    pub(crate) fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        value: DriverValue<D, EpAffine>,
    ) -> Result<Self> {
        let point = Point::alloc(dr, value)?;
        let mut coordinates = Vec::new();
        point.write(dr, &mut coordinates)?;
        let [x, y]: [Element<'dr, D>; 2] = coordinates
            .try_into()
            .map_err(|_err| Error::InvalidWitness("point must write two coordinates".into()))?;
        let one = Element::constant(dr, Fp::ONE);
        let infinity = one.is_zero(dr, allocator)?;
        Ok(Self { x, y, infinity })
    }

    pub(crate) fn constant(dr: &mut D, value: EpAffine) -> Result<Self> {
        let point = Point::constant(dr, value)?;
        let mut coordinates = Vec::new();
        point.write(dr, &mut coordinates)?;
        let [x, y]: [Element<'dr, D>; 2] = coordinates
            .try_into()
            .map_err(|_err| Error::InvalidWitness("point must write two coordinates".into()))?;
        let one = Element::constant(dr, Fp::ONE);
        let infinity = one.is_zero(dr, &mut ())?;
        Ok(Self { x, y, infinity })
    }

    fn identity(dr: &mut D) -> Result<Self> {
        let x = Element::constant(dr, Fp::ZERO);
        let y = Element::constant(dr, Fp::ZERO);
        let infinity = x.is_zero(dr, &mut ())?;
        Ok(Self { x, y, infinity })
    }

    fn select(dr: &mut D, condition: &Boolean<'dr, D>, left: &Self, right: &Self) -> Result<Self> {
        let x = condition.conditional_select(dr, &left.x, &right.x)?;
        let y = condition.conditional_select(dr, &left.y, &right.y)?;
        let infinity_element = condition.conditional_select(
            dr,
            &left.infinity.element(),
            &right.infinity.element(),
        )?;
        let one = Element::constant(dr, Fp::ONE);
        let infinity = infinity_element.is_equal(dr, &mut (), &one)?;
        Ok(Self { x, y, infinity })
    }

    pub(crate) fn add(dr: &mut D, left: &Self, right: &Self) -> Result<Self> {
        let one = Element::constant(dr, Fp::ONE);
        let same_x = left.x.is_equal(dr, &mut (), &right.x)?;
        let same_y = left.y.is_equal(dr, &mut (), &right.y)?;
        let dx = right.x.sub(dr, &left.x);
        let add_denominator = same_x
            .conditional_select(dr, &dx, &one)?
            .enforce_nonzero(dr)?;
        let dy = right.y.sub(dr, &left.y);
        let add_slope = dy.divide(dr, &add_denominator)?;
        let add_x = add_slope.square(dr)?.sub(dr, &left.x).sub(dr, &right.x);
        let add_difference = left.x.sub(dr, &add_x);
        let add_y = add_slope.mul(dr, &add_difference)?.sub(dr, &left.y);

        let twice_y = left.y.double(dr);
        let double_denominator = left
            .infinity
            .conditional_select(dr, &twice_y, &one)?
            .enforce_nonzero(dr)?;
        let three = Element::constant(dr, Fp::from(3));
        let numerator = left.x.square(dr)?.mul(dr, &three)?;
        let double_slope = numerator.divide(dr, &double_denominator)?;
        let twice_x = left.x.double(dr);
        let double_x = double_slope.square(dr)?.sub(dr, &twice_x);
        let double_difference = left.x.sub(dr, &double_x);
        let double_y = double_slope.mul(dr, &double_difference)?.sub(dr, &left.y);

        let x = same_x.conditional_select(dr, &add_x, &double_x)?;
        let y = same_x.conditional_select(dr, &add_y, &double_y)?;
        let not_same_y = same_y.not(dr);
        let infinity = same_x.and(dr, &not_same_y)?;
        let sum = Self { x, y, infinity };
        let left_corrected_sum = Self::select(dr, &left.infinity, &sum, right)?;
        Self::select(dr, &right.infinity, &left_corrected_sum, left)
    }

    pub(crate) fn scale<const N: usize>(
        dr: &mut D,
        base: &Self,
        bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
    ) -> Result<Self> {
        let mut acc = Self::identity(dr)?;
        for bit in bits.iter().rev().take(N) {
            let doubled = Self::add(dr, &acc, &acc)?;
            let added = Self::add(dr, &doubled, base)?;
            acc = Self::select(dr, bit, &doubled, &added)?;
        }
        Ok(acc)
    }

    #[expect(
        clippy::expect_used,
        reason = "complete group arithmetic preserves the curve equation"
    )]
    pub(crate) fn value(&self) -> DriverValue<D, EpAffine> {
        D::just(|| {
            if self.infinity.value().take() {
                EpAffine::identity()
            } else {
                EpAffine::from_xy(*self.x.value().take(), *self.y.value().take())
                    .expect("complete curve arithmetic preserves the curve equation")
            }
        })
    }

    pub(crate) fn enforce_nonidentity(&self, dr: &mut D) -> Result<()> {
        self.infinity.element().enforce_zero(dr)
    }
}

#[cfg(test)]
mod tests {
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
            .expect("complete addition");
        }
    }
    #[test]
    fn scalar_multiplication_matches_native_at_edge_cases() {
        for scalar in [Fq::ZERO, Fq::ONE, Fq::from(2), -Fq::ONE, Fq::from(12345)] {
            Simulator::<Fp>::simulate(scalar, |dr, assignment| {
                let bits = scalar_bits(dr, assignment.clone())?;
                let base = CurvePoint::constant(dr, EpAffine::generator())?;
                let scaled = CurvePoint::scale(dr, &base, &bits)?;
                assert_eq!(
                    scaled.value().take().to_projective(),
                    EpAffine::generator().to_projective() * assignment.take()
                );
                Ok(())
            })
            .expect("complete scalar multiplication");
        }
    }
}
