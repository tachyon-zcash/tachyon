//! Host-curve commitment encoding for typed set gadgets.
use core::marker::PhantomData;

use derive_more::Debug;
use ragu::pasta::{EqAffine, Fp};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    gadgets::{Bound, Gadget},
    maybe::Maybe as _,
};
use ragu_primitives::{
    Element, GadgetExt as _,
    allocator::Allocator,
    io::{Buffer, Write},
};
use udon::{curve::Affine as _, field::Field};

/// The compressed host-curve commitment representation used by Ragu handles.
#[derive(Gadget, Debug)]
#[debug("HostCommitment(..)")]
pub struct HostCommitment<'dr, D: Driver<'dr>> {
    pub(crate) limbs: [Element<'dr, D>; 2],
}

impl<F: Field> Write<F> for HostCommitment<'static, PhantomData<F>> {
    fn write_gadget<'dr, D: Driver<'dr, F = F>, B: Buffer<'dr, D>>(
        this: &Bound<'dr, D, Self>,
        dr: &mut D,
        buf: &mut B,
    ) -> Result<()> {
        let low_zero = this.limbs[0].is_zero(dr, &mut ())?;
        let high_zero = this.limbs[1].is_zero(dr, &mut ())?;
        low_zero.and(dr, &high_zero)?.element().enforce_zero(dr)?;
        this.limbs.write(dr, buf)
    }
}

impl<'dr, D: Driver<'dr, F = Fp>> HostCommitment<'dr, D> {
    /// Allocate the same two compressed limbs as a host polynomial handle.
    #[expect(
        clippy::expect_used,
        reason = "compressed point limbs contain exactly 16 bytes"
    )]
    pub fn alloc<A: Allocator<'dr, D>>(
        dr: &mut D,
        allocator: &mut A,
        point: DriverValue<D, EqAffine>,
    ) -> Result<Self> {
        let limbs = point.map(|candidate| {
            let bytes = candidate.to_bytes();
            let (low, high) = bytes.split_at(16);
            [
                Fp::from_u128(u128::from_le_bytes(low.try_into().expect("16 byte limb"))),
                Fp::from_u128(u128::from_le_bytes(high.try_into().expect("16 byte limb"))),
            ]
        });
        let low = Element::alloc(dr, allocator, limbs.as_ref().map(|&[low, _]| low))?;
        let high = Element::alloc(dr, allocator, limbs.as_ref().map(|&[_, high]| high))?;
        Ok(Self { limbs: [low, high] })
    }
}
