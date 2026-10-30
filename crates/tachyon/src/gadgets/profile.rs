//! Circuit gadgets for profile values.
scalar_gadget!(QrDiscriminantGadget, "QrDiscriminantGadget(..)");

/// A QR routing profile with a depth and path register.
#[derive(ragu_core::gadgets::Gadget, ragu_primitives::io::Write, derive_more::Debug)]
#[debug("QrProfileGadget(..)")]
pub struct QrProfileGadget<'dr, D: Driver<'dr>> {
    pub(crate) depth: Element<'dr, D>,
    pub(crate) bits: Element<'dr, D>,
}

use ragu::pasta::Fp;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe as _,
};
use ragu_primitives::{Boolean, Element, GadgetExt as _};
use udon::field::Field as _;

use super::arithmetic::bits;
use crate::primitives::{QrClassRoot, QrProfile};
impl<'dr, D: Driver<'dr, F = Fp>> QrProfileGadget<'dr, D> {
    /// Validate profile depth and the low-depth-bit register encoding.
    pub(crate) fn validate(&self, dr: &mut D) -> Result<[Element<'dr, D>; 2]> {
        let depth = &self.depth;
        let register = &self.bits;
        let bits = bits::<D, 32>(dr, register)?;
        let mut count = Element::constant(dr, Fp::ZERO);
        let one = Element::constant(dr, Fp::ONE);
        let mut previous = one.is_zero(dr, &mut ())?.not(dr);
        for (index, bit) in (0..32).zip(bits.iter()) {
            let active = Boolean::alloc(
                dr,
                &mut (),
                depth.value().map(|candidate| {
                    let [first, second, third, fourth, ..] = candidate.to_bytes();
                    index < u32::from_le_bytes([first, second, third, fourth])
                }),
            )?;
            let inactive = active.not(dr);
            inactive
                .element()
                .mul(dr, &bit.element())?
                .enforce_zero(dr)?;
            let previous_inactive = previous.not(dr);
            previous_inactive
                .and(dr, &active)?
                .element()
                .enforce_zero(dr)?;
            count = count.add(dr, &active.element());
            previous = active;
        }
        count.enforce_equal(dr, depth)?;
        Ok([depth.clone(), register.clone()])
    }

    /// Fix `value`'s side at every discriminant of the progression from
    /// `discriminant`, and check `profile` is the value's first `depth` sides.
    ///
    /// Shared by QR unspent initialization and lifting.
    #[expect(clippy::indexing_slicing, reason = "fixed 32-position profile arrays")]
    pub(crate) fn enforce_value(
        &self,
        driver: &mut D,
        value: &Element<'dr, D>,
        discriminant: &Element<'dr, D>,
        classes: DriverValue<D, [QrClassRoot; QrProfile::MAX_DEPTH]>,
        mask: DriverValue<D, [bool; QrProfile::MAX_DEPTH]>,
    ) -> Result<()> {
        let mut shifted = value.add(driver, discriminant);
        let mut depth_acc = Element::constant(driver, Fp::ZERO);
        let mut index_acc = Element::constant(driver, Fp::ZERO);
        let mut bits_acc = Element::constant(driver, Fp::ZERO);
        let one = Element::constant(driver, Fp::ONE);
        let five = Element::constant(driver, Fp::from(5));
        let mut position_element = Element::constant(driver, Fp::ZERO);
        for position in 0..QrProfile::MAX_DEPTH {
            let side = Boolean::alloc(
                driver,
                &mut (),
                classes.as_ref().map(|values| values[position].0),
            )?;
            let root = Element::alloc(
                driver,
                &mut (),
                classes.as_ref().map(|values| values[position].1),
            )?;
            let selected = Boolean::alloc(
                driver,
                &mut (),
                mask.as_ref().map(|values| values[position]),
            )?;
            let multiplier = side.conditional_select(driver, &five, &one)?;
            let expected_square = multiplier.mul(driver, &shifted)?;
            root.square(driver)?
                .enforce_equal(driver, &expected_square)
                .map_err(|_err| {
                    ragu_core::Error::InvalidWitness(
                        "QR profile: root does not square to the claimed class".into(),
                    )
                })?;
            side.conditional_select(driver, &shifted, &one)?
                .enforce_nonzero(driver)
                .map_err(|_err| {
                    ragu_core::Error::InvalidWitness(
                        "QR profile: exceptional discriminant claimed the non-residue class".into(),
                    )
                })?;
            depth_acc = depth_acc.add(driver, &selected.element());
            let index_term = selected.element().mul(driver, &position_element)?;
            index_acc = index_acc.add(driver, &index_term);
            let selected_term = bits_acc.add(driver, &side.element());
            let bits_term = selected.element().mul(driver, &selected_term)?;
            bits_acc = bits_acc.add(driver, &bits_term);
            shifted = shifted.add(driver, &one);
            position_element = position_element.add(driver, &one);
        }
        let depth = self.depth.clone();
        let profile_bits = self.bits.clone();
        depth_acc.enforce_equal(driver, &depth).map_err(|_err| {
            ragu_core::Error::InvalidWitness(
                "QR profile: depth mask does not match the bucket's depth".into(),
            )
        })?;
        let depth_minus_one = depth_acc.sub(driver, &one);
        let expected_index_sum = depth_acc.mul(driver, &depth_minus_one)?;
        index_acc
            .double(driver)
            .enforce_equal(driver, &expected_index_sum)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness("QR profile: depth mask is not a prefix".into())
            })?;
        bits_acc
            .enforce_equal(driver, &profile_bits)
            .map_err(|_err| {
                ragu_core::Error::InvalidWitness(
                    "QR profile: value does not take the bucket's profile".into(),
                )
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ragu_primitives::Simulator;

    use super::*;
    use crate::primitives::QrProfile;
    #[test]
    fn profile_rejects_invalid_depth_and_register() {
        for candidate in [
            QrProfile::ROOT,
            QrProfile {
                depth: 32,
                bits: u32::MAX,
            },
        ] {
            Simulator::<Fp>::simulate(candidate, |driver, assignment| {
                let depth = Element::alloc(
                    driver,
                    &mut (),
                    assignment
                        .as_ref()
                        .map(|value| Fp::from(u64::from(value.depth))),
                )?;
                let register = Element::alloc(
                    driver,
                    &mut (),
                    assignment.map(|value| Fp::from(u64::from(value.bits))),
                )?;
                QrProfileGadget {
                    depth: (depth).clone(),
                    bits: (register).clone(),
                }
                .validate(driver)?;
                Ok(())
            })
            .expect("valid profile");
        }
        for candidate in [
            QrProfile { depth: 33, bits: 0 },
            QrProfile { depth: 0, bits: 1 },
            QrProfile { depth: 3, bits: 8 },
        ] {
            assert!(
                Simulator::<Fp>::simulate(candidate, |driver, assignment| {
                    let depth = Element::alloc(
                        driver,
                        &mut (),
                        assignment
                            .as_ref()
                            .map(|value| Fp::from(u64::from(value.depth))),
                    )?;
                    let register = Element::alloc(
                        driver,
                        &mut (),
                        assignment.map(|value| Fp::from(u64::from(value.bits))),
                    )?;
                    QrProfileGadget {
                        depth: (depth).clone(),
                        bits: (register).clone(),
                    }
                    .validate(driver)?;
                    Ok(())
                })
                .is_err()
            );
        }
    }
}
