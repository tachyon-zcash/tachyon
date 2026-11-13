//! One member of an indexed multiset, evaluated inside a circuit.
//!
//! The [indexed multiset](crate::collections::indexed_multiset) is a
//! polynomial, the product of its members' factors. It is built only
//! natively, and a step holds it only as a commitment in one of ragu's
//! oracle slots. A circuit computes one member's factor at one point, to
//! compare against a slot's opening there.

use ragu_core::{Result, drivers::Driver, gadgets::Gadget};
use ragu_primitives::Element;
use udon::field::Field as _;

use crate::{collections::indexed_multiset::NON_RESIDUE, pasta::Fp};

/// The member with value `value` at `index`.
///
/// The index is any field element; every step passes an epoch.
#[derive(Gadget)]
pub(crate) struct Member<'dr, D: Driver<'dr>> {
    pub index: Element<'dr, D>,
    pub value: Element<'dr, D>,
}

impl<'dr, D: Driver<'dr, F = Fp>> Member<'dr, D> {
    /// The member's factor $F_{i,m}(x) = (m + (i + 1) x)^3 - c$ at `x`, for
    /// $i$ = `index`, $m$ = `value` and the encoding's non-residue $c$.
    ///
    /// Distinct members have distinct factors while `index + 1` stays below
    /// the bound in the native module's Injectivity section; an epoch does.
    /// Comparing the result with an opening at the step's challenge is sound
    /// only if `index` and `value` were fixed before that challenge (see
    /// [`Oracles::zeta`](ragu::step::Oracles::zeta)).
    pub(crate) fn eval(&self, dr: &mut D, x: &Element<'dr, D>) -> Result<Element<'dr, D>> {
        let one = Element::constant(dr, Fp::ONE);
        let indexed = self.index.add(dr, &one).mul(dr, x)?;
        let shifted = self.value.add(dr, &indexed);
        let square = shifted.square(dr)?;
        let cube = square.mul(dr, &shifted)?;
        let non_residue = Element::constant(dr, NON_RESIDUE);
        Ok(cube.sub(dr, &non_residue))
    }
}
