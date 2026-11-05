//! Complete point arithmetic, exporting ordinary finite ragu points.

use alloc::vec::Vec;

use ragu_core::{Error, Result, drivers::Driver, maybe::Maybe as _};
use ragu_primitives::{
    Boolean, Element, GadgetExt as _, Point,
    vec::{ConstLen, FixedVec},
};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use crate::{
    pasta::{EpAffine, Fp},
    value,
};

// Only the complete arithmetic below uses an infinity flag. Header fields
// and the exported results remain finite `Point`s.
type CompletePoint<'dr, D> = (Element<'dr, D>, Element<'dr, D>, Boolean<'dr, D>);

pub(crate) fn coordinates<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    point: &Point<'dr, D, EpAffine>,
) -> Result<[Element<'dr, D>; 2]> {
    let mut coordinates = Vec::new();
    point.write(dr, &mut coordinates)?;
    coordinates
        .try_into()
        .map_err(|_err| Error::InvalidWitness("point must write two coordinates".into()))
}

fn from_point<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    point: &Point<'dr, D, EpAffine>,
) -> Result<CompletePoint<'dr, D>> {
    let [x, y] = coordinates(dr, point)?;
    let one = Element::constant(dr, Fp::ONE);
    Ok((x, y, one.is_zero(dr, &mut ())?))
}

fn select<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    condition: &Boolean<'dr, D>,
    left: &CompletePoint<'dr, D>,
    right: &CompletePoint<'dr, D>,
) -> Result<CompletePoint<'dr, D>> {
    let x = condition.conditional_select(dr, &left.0, &right.0)?;
    let y = condition.conditional_select(dr, &left.1, &right.1)?;
    let infinity = condition.conditional_select(dr, &left.2.element(), &right.2.element())?;
    let one = Element::constant(dr, Fp::ONE);
    Ok((x, y, infinity.is_equal(dr, &mut (), &one)?))
}

fn add_complete<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    left: &CompletePoint<'dr, D>,
    right: &CompletePoint<'dr, D>,
) -> Result<CompletePoint<'dr, D>> {
    let one = Element::constant(dr, Fp::ONE);
    let same_x = left.0.is_equal(dr, &mut (), &right.0)?;
    let same_y = left.1.is_equal(dr, &mut (), &right.1)?;
    let dx = right.0.sub(dr, &left.0);
    let denominator = same_x
        .conditional_select(dr, &dx, &one)?
        .enforce_nonzero(dr)?;
    let dy = right.1.sub(dr, &left.1);
    let slope = dy.divide(dr, &denominator)?;
    let add_x = slope.square(dr)?.sub(dr, &left.0).sub(dr, &right.0);
    let difference = left.0.sub(dr, &add_x);
    let add_y = slope.mul(dr, &difference)?.sub(dr, &left.1);

    let twice_y = left.1.double(dr);
    let double_denominator = left
        .2
        .conditional_select(dr, &twice_y, &one)?
        .enforce_nonzero(dr)?;
    let three = Element::constant(dr, Fp::from(3));
    let numerator = left.0.square(dr)?.mul(dr, &three)?;
    let double_slope = numerator.divide(dr, &double_denominator)?;
    let twice_x = left.0.double(dr);
    let double_x = double_slope.square(dr)?.sub(dr, &twice_x);
    let double_difference = left.0.sub(dr, &double_x);
    let double_y = double_slope.mul(dr, &double_difference)?.sub(dr, &left.1);

    let x = same_x.conditional_select(dr, &add_x, &double_x)?;
    let y = same_x.conditional_select(dr, &add_y, &double_y)?;
    let not_same_y = same_y.not(dr);
    let infinity = same_x.and(dr, &not_same_y)?;
    let sum = (x, y, infinity);
    let left_corrected = select(dr, &left.2, &sum, right)?;
    select(dr, &right.2, &left_corrected, left)
}

fn scale_complete<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    base: &CompletePoint<'dr, D>,
    bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
) -> Result<CompletePoint<'dr, D>> {
    let zero_x = Element::constant(dr, Fp::ZERO);
    let zero_y = Element::constant(dr, Fp::ZERO);
    let infinity = zero_x.is_zero(dr, &mut ())?;
    let mut acc = (zero_x, zero_y, infinity);
    for bit in bits.iter().rev().take(N) {
        let doubled = add_complete(dr, &acc, &acc)?;
        let added = add_complete(dr, &doubled, base)?;
        acc = select(dr, bit, &doubled, &added)?;
    }
    Ok(acc)
}

fn finish<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    computed: &CompletePoint<'dr, D>,
) -> Result<Point<'dr, D, EpAffine>> {
    computed.2.element().enforce_zero(dr)?;
    let native = D::try_just(|| {
        EpAffine::from_xy(*computed.0.value().take(), *computed.1.value().take()).ok_or_else(|| {
            Error::InvalidWitness("complete arithmetic produced an invalid point".into())
        })
    })?;
    let point = Point::alloc(dr, native)?;
    let [x, y] = coordinates(dr, &point)?;
    computed.0.enforce_equal(dr, &x)?;
    computed.1.enforce_equal(dr, &y)?;
    Ok(point)
}

pub(crate) fn scale<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    base: &Point<'dr, D, EpAffine>,
    bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
) -> Result<Point<'dr, D, EpAffine>> {
    let complete = from_point(dr, base)?;
    let computed = scale_complete(dr, &complete, bits)?;
    finish(dr, &computed)
}

pub(crate) fn add_scaled<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    addend: &Point<'dr, D, EpAffine>,
    base: &Point<'dr, D, EpAffine>,
    bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
) -> Result<Point<'dr, D, EpAffine>> {
    let addend_complete = from_point(dr, addend)?;
    let base_complete = from_point(dr, base)?;
    let scaled = scale_complete(dr, &base_complete, bits)?;
    let computed = add_complete(dr, &addend_complete, &scaled)?;
    finish(dr, &computed)
}

pub(crate) fn commitment<'dr, D: Driver<'dr, F = Fp>, const N: usize, const M: usize>(
    dr: &mut D,
    amount_bits: &FixedVec<Boolean<'dr, D>, ConstLen<N>>,
    blind_bits: &FixedVec<Boolean<'dr, D>, ConstLen<M>>,
    negative: bool,
) -> Result<Point<'dr, D, EpAffine>> {
    let generator = if negative {
        -*value::VALUE_COMMIT_V
    } else {
        *value::VALUE_COMMIT_V
    };
    let value_generator = Point::constant(dr, generator.to_affine())?;
    let blind_generator = Point::constant(dr, value::VALUE_COMMIT_R.to_affine())?;
    let value_complete = from_point(dr, &value_generator)?;
    let blind_complete = from_point(dr, &blind_generator)?;
    let value_point = scale_complete(dr, &value_complete, amount_bits)?;
    let blind_point = scale_complete(dr, &blind_complete, blind_bits)?;
    let computed = add_complete(dr, &value_point, &blind_point)?;
    finish(dr, &computed)
}

#[cfg(test)]
mod tests;
