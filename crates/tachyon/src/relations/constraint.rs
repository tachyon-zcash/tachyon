//! Native evaluation of ragu's enforce-only gadgets.
//!
//! Each function drives the real gadget through [`Simulator`], the checking
//! driver, and restates its generic constraint failure with the caller's
//! message. The wireless emulator is cheaper but never checks constraint
//! satisfaction, so it cannot reject an invalid witness.

use group::Curve as _;
use pasta_curves::{Eq, EqAffine, Fp, Fq};
use ragu_core::{Error, Result, drivers::Driver as _};
use ragu_primitives::{Boolean, Element, GadgetExt as _, Point, Simulator};

/// Enforces `value == 0`.
pub(crate) fn enforce_zero(value: Fp, err: &'static str) -> Result<()> {
    let mut driver = Simulator::<Fp>::new();
    let element = Element::constant(&mut driver, value);

    element
        .enforce_zero(&mut driver)
        .map_err(|_e| Error::InvalidWitness(err.into()))
}

/// Enforces `value != 0`, returning `value`.
pub(crate) fn enforce_nonzero(value: Fp, err: &'static str) -> Result<Fp> {
    let mut driver = Simulator::<Fp>::new();
    let element = Element::constant(&mut driver, value);

    element
        .enforce_nonzero(&mut driver)
        .map(|_nonzero| value)
        .map_err(|_e| Error::InvalidWitness(err.into()))
}

/// Enforces `left == right` when `cond` holds, and nothing otherwise.
pub(crate) fn conditional_enforce_equal(
    cond: bool,
    left: Fp,
    right: Fp,
    err: &'static str,
) -> Result<()> {
    let mut driver = Simulator::<Fp>::new();
    let condition = Boolean::alloc(&mut driver, &mut (), Simulator::<Fp>::just(|| cond))?;
    let left_element = Element::constant(&mut driver, left);
    let right_element = Element::constant(&mut driver, right);

    condition
        .conditional_enforce_equal(&mut driver, &mut (), &left_element, &right_element)
        .map_err(|_e| Error::InvalidWitness(err.into()))
}

/// Enforces `left == right` for two Vesta points.
///
/// A Vesta point's coordinates live in $\mathbb{F}_q$, so this drives the
/// nested-curve view of the comparison. An identity input fails ahead of the
/// equality check, since ragu cannot witness it as a [`Point`].
pub(crate) fn enforce_equal_point(left: Eq, right: Eq, err: &'static str) -> Result<()> {
    let mut driver = Simulator::<Fq>::new();
    let left_point = Point::<'_, _, EqAffine>::constant(&mut driver, left.to_affine())?;
    let right_point = Point::<'_, _, EqAffine>::constant(&mut driver, right.to_affine())?;

    left_point
        .enforce_equal(&mut driver, &right_point)
        .map_err(|_e| Error::InvalidWitness(err.into()))
}
