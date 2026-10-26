//! Circuit point representation shared by typed domain gadgets.
use alloc::vec::Vec;
use core::marker::PhantomData;

use derive_more::Debug;
use ragu::pasta::{EpAffine, Fp};
use ragu_core::{
    Error, Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget},
};
use ragu_primitives::{
    Boolean, Element, GadgetExt as _, Point,
    allocator::Allocator,
    io::{Buffer, Write},
};
use udon::field::Field;
/// Header point coordinates with an explicit internal infinity flag.
#[derive(Gadget, Debug)]
#[debug("CurvePoint(..)")]
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
}
