//! Circuit gadgets for epoch values.

scalar_gadget!(EpochIndexGadget, "EpochIndexGadget(..)");

use ragu::pasta::Fp;
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe as _,
};
use ragu_primitives::Element;
use udon::field::Field as _;

use super::arithmetic::bounded;
use crate::{constants::EPOCH_MAX, primitives::EpochIndex};
impl<'dr, D: Driver<'dr, F = Fp>> EpochIndexGadget<'dr, D> {
    /// A bounded successor, with no field wrap and no final-epoch overflow.
    pub(crate) fn next(&self, dr: &mut D) -> Result<Self> {
        let epoch = &self.element;
        bounded::<D, 32>(dr, epoch, u64::from(EPOCH_MAX))?;
        let one = Element::constant(dr, Fp::ONE);
        let next = epoch.add(dr, &one);
        bounded::<D, 32>(dr, &next, u64::from(EPOCH_MAX))?;
        Ok(next.into())
    }

    /// Read a bounded circuit result into the prover-side Data carrier.
    pub(crate) fn value(&self) -> DriverValue<D, EpochIndex> {
        self.element.value().map(|candidate| {
            let [first, second, third, fourth, ..] = candidate.to_bytes();
            EpochIndex::new(u32::from_le_bytes([first, second, third, fourth]))
        })
    }
}

#[cfg(test)]
mod tests {
    use ragu_primitives::Simulator;

    use super::*;
    use crate::constants::EPOCH_MAX;
    #[test]
    fn epoch_successor_rejects_raw_final_and_out_of_domain_assignments() {
        for index in [Fp::ZERO, Fp::from(u64::from(EPOCH_MAX - 1))] {
            Simulator::<Fp>::simulate(index, |driver, assignment| {
                let epoch = Element::alloc(driver, &mut (), assignment)?;
                EpochIndexGadget::from((epoch).clone())
                    .next(driver)
                    .map(|next| next.element)?;
                Ok(())
            })
            .expect("bounded successor");
        }
        for index in [
            -Fp::ONE,
            Fp::from(u64::from(EPOCH_MAX)),
            Fp::from(u64::from(EPOCH_MAX) + 1),
        ] {
            assert!(
                Simulator::<Fp>::simulate(index, |driver, assignment| {
                    let epoch = Element::alloc(driver, &mut (), assignment)?;
                    EpochIndexGadget::from((epoch).clone())
                        .next(driver)
                        .map(|next| next.element)?;
                    Ok(())
                })
                .is_err()
            );
        }
    }
}
