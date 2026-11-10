//! Native evaluation of ragu's enforce-only gadgets.
//!
//! Each function drives the real gadget through [`Simulator`], the checking
//! driver, and restates its generic constraint failure with the caller's
//! message. The wireless emulator is cheaper but never checks constraint
//! satisfaction, so it cannot reject an invalid witness.

use ragu_core::{Error, Result};
use ragu_primitives::{Element, Simulator};

use crate::pasta::Fp;

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
