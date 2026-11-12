//! Indexed-multiset members inside a circuit.

use ragu_core::{Result, drivers::Driver};
use ragu_primitives::Element;

use crate::{collections::indexed_multiset::NON_RESIDUE, pasta::Fp};

/// Evaluates at $z$ one member's factor $(i \cdot z + v)^3 - c$ of the
/// [indexed-multiset encoding](crate::collections::indexed_multiset), for
/// $i$ = `index_plus_one`, $v$ = `value` and the encoding's non-residue $c$.
pub(crate) fn member<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    value: &Element<'dr, D>,
    index_plus_one: &Element<'dr, D>,
    z: &Element<'dr, D>,
) -> Result<Element<'dr, D>> {
    let indexed = index_plus_one.mul(dr, z)?;
    let shifted = value.add(dr, &indexed);
    let square = shifted.square(dr)?;
    let cube = square.mul(dr, &shifted)?;
    let non_residue = Element::constant(dr, NON_RESIDUE);
    Ok(cube.sub(dr, &non_residue))
}
