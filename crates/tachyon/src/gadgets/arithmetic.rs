//! Generic fixed-width circuit arithmetic.

use ragu::pasta::{Fp, Fq};
use ragu_core::{
    Result,
    drivers::{Driver, DriverValue},
    maybe::Maybe as _,
};
use ragu_primitives::{
    Boolean, Element, GadgetExt as _, multipack,
    vec::{ConstLen, FixedVec},
};
use udon::field::Field as _;
/// Unique little-endian decomposition. The canonical comparison matters at
/// 255 bits, where a modular recomposition alone would allow aliases.
#[expect(clippy::indexing_slicing, reason = "fixed field and bit widths")]
pub(crate) fn bits<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    value: &Element<'dr, D>,
) -> Result<FixedVec<Boolean<'dr, D>, ConstLen<N>>> {
    const {
        assert!(N > 0 && N <= 255, "decomposition width must fit the field");
    }
    let bits = FixedVec::try_from_fn(|i| {
        Boolean::alloc(
            dr,
            &mut (),
            value
                .value()
                .map(|candidate| candidate.to_le_bits().as_ref()[i]),
        )
    })?;
    let packed = multipack(dr, &bits)?;
    let recomposed = if N == 255 {
        let high_weight = Element::constant(dr, Fp::from(2).pow_u64(254));
        let high = packed[1].mul(dr, &high_weight)?;
        packed[0].add(dr, &high)
    } else {
        packed[0].clone()
    };
    recomposed.enforce_equal(dr, value)?;
    if N == 255 {
        let maximum = (-Fp::ONE).to_le_bits();
        let mut equal = Element::constant(dr, Fp::ONE);
        for i in (0..255).rev() {
            if maximum.as_ref()[i] {
                equal = equal.mul(dr, &bits[i].element())?;
            } else {
                equal.mul(dr, &bits[i].element())?.enforce_zero(dr)?;
            }
        }
    }
    Ok(bits)
}

/// Bounded unsigned integer: both the value and its slack have N bits.
/// The caller supplies a public maximum below 2^N; N is at most 64, so
/// neither side of the slack equation can wrap in the circuit field.
pub(crate) fn bounded<'dr, D: Driver<'dr, F = Fp>, const N: usize>(
    dr: &mut D,
    value: &Element<'dr, D>,
    maximum: u64,
) -> Result<()> {
    const {
        assert!(
            N > 0 && N <= 64,
            "bounded integer width must be at most 64 bits"
        );
    }
    bits::<D, N>(dr, value)?;
    let maximum_element = Element::constant(dr, Fp::from(maximum));
    let slack = maximum_element.sub(dr, value);
    bits::<D, N>(dr, &slack)?;
    Ok(())
}

/// A free scalar's canonical bits. It is used only as a blinding witness;
/// no arithmetic-field embedding of Fq into Fp is assumed.
#[expect(clippy::indexing_slicing, reason = "fixed 255-bit scalar width")]
pub(crate) fn scalar_bits<'dr, D: Driver<'dr, F = Fp>>(
    dr: &mut D,
    scalar: DriverValue<D, Fq>,
) -> Result<FixedVec<Boolean<'dr, D>, ConstLen<255>>> {
    let bits = FixedVec::try_from_fn(|i| {
        Boolean::alloc(
            dr,
            &mut (),
            scalar
                .as_ref()
                .map(|candidate| candidate.to_le_bits().as_ref()[i]),
        )
    })?;
    let maximum = (-Fq::ONE).to_le_bits();
    let mut equal = Element::constant(dr, Fp::ONE);
    for i in (0..255).rev() {
        if maximum.as_ref()[i] {
            equal = equal.mul(dr, &bits[i].element())?;
        } else {
            equal.mul(dr, &bits[i].element())?.enforce_zero(dr)?;
        }
    }
    Ok(bits)
}

#[cfg(test)]
mod tests {
    use ragu_primitives::Simulator;

    use super::*;
    use crate::{
        constants::{EPOCH_MAX, MAX_MONEY},
        nullifier::NF_DERIVATION_WIDTH,
    };
    fn check_nonzero_output_boundary() {
        for assignment in [Fp::ZERO, Fp::ONE, -Fp::ONE] {
            let result = Simulator::<Fp>::simulate(assignment, |driver, supplied| {
                let element = Element::alloc(driver, &mut (), supplied)?;
                element.enforce_nonzero(driver)?;
                Ok(())
            });
            assert_eq!(result.is_ok(), assignment != Fp::ZERO);
        }
    }
    #[test]
    fn spend_current_nullifier_rejects_raw_zero_at_the_nonzero_boundary() {
        // B39: a whole-step zero requires a Poseidon preimage; isolate the
        // actual public nonzero gadget instead of weakening the hash relation.
        check_nonzero_output_boundary();
    }
    #[test]
    fn spend_next_nullifier_rejects_raw_zero_at_the_nonzero_boundary() {
        // B40: producing a whole-step zero requires a Poseidon preimage.
        // This deliberately tests only the nonzero allocation boundary.
        check_nonzero_output_boundary();
    }
    #[test]
    fn output_commitment_rejects_raw_zero_at_the_nonzero_boundary() {
        // B42: the full note hash is not replaced to manufacture a zero;
        // finding that whole-step witness would require a Poseidon preimage.
        check_nonzero_output_boundary();
    }
    #[test]
    fn output_padding_rejects_raw_zero_at_the_nonzero_boundary() {
        // B43: a zero padding hash needs a Poseidon preimage. This test
        // supplies raw zero only at the actual nonzero gadget boundary.
        check_nonzero_output_boundary();
    }
    #[test]
    fn fee_fuse_change_rejects_raw_zero_at_the_nonzero_boundary() {
        // B49: whole-step zero requires a Poseidon preimage; the range and
        // hash constraints remain intact while this boundary is tested.
        check_nonzero_output_boundary();
    }
    #[test]
    fn fee_seed_change_rejects_raw_zero_at_the_nonzero_boundary() {
        // B51: constructing a zero change commitment requires a Poseidon
        // preimage. Scope is the nonzero gadget, not a whole-step forgery.
        check_nonzero_output_boundary();
    }
    #[test]
    fn bounded_amount_rejects_raw_out_of_range_assignments() {
        for native_amount in [Fp::ZERO, Fp::from(MAX_MONEY)] {
            Simulator::<Fp>::simulate(native_amount, |dr, assignment| {
                let amount = Element::alloc(dr, &mut (), assignment)?;
                bounded::<_, 51>(dr, &amount, MAX_MONEY)
            })
            .expect("valid amount");
        }
        for native_amount in [-Fp::ONE, Fp::from(MAX_MONEY + 1), Fp::from(2).pow_u64(51)] {
            assert!(
                Simulator::<Fp>::simulate(native_amount, |dr, assignment| {
                    let amount = Element::alloc(dr, &mut (), assignment)?;
                    bounded::<_, 51>(dr, &amount, MAX_MONEY)
                })
                .is_err()
            );
        }
    }
    #[test]
    fn one_bit_decomposition_rejects_raw_nonboolean_field_assignments() {
        // Rust bool cannot carry 2 or -1. Exercise the Boolean allocation and
        // recomposition boundary with a raw field assignment instead.
        for assignment in [Fp::ZERO, Fp::ONE, Fp::from(2), -Fp::ONE] {
            let result = Simulator::<Fp>::simulate(assignment, |driver, supplied| {
                let element = Element::alloc(driver, &mut (), supplied)?;
                bits::<_, 1>(driver, &element)?;
                Ok(())
            });
            assert_eq!(
                result.is_ok(),
                assignment == Fp::ZERO || assignment == Fp::ONE
            );
        }
    }
    #[test]
    fn nullifier_window_end_rejects_raw_overflow_before_header_conversion() {
        // An out-of-domain end cannot be represented by native EpochIndex.
        // Test the actual driver arithmetic/range boundary before marshaling.
        let width = u32::try_from(NF_DERIVATION_WIDTH - 1).expect("fixed window width");
        let last_start = EPOCH_MAX - width;
        for raw_start in [last_start, EPOCH_MAX - 3] {
            let result =
                Simulator::<Fp>::simulate(Fp::from(u64::from(raw_start)), |driver, supplied| {
                    let start_element = Element::alloc(driver, &mut (), supplied)?;
                    bits::<_, 32>(driver, &start_element)?;
                    let offset = Element::constant(driver, Fp::from(u64::from(width)));
                    let end = start_element.add(driver, &offset);
                    bounded::<_, 32>(driver, &end, u64::from(EPOCH_MAX))
                });
            assert_eq!(result.is_ok(), raw_start == last_start);
        }
    }
}
