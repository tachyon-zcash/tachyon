#![allow(missing_docs, reason = "todo")]

extern crate alloc;

use alloc::vec::Vec;

use lazy_static::lazy_static;
use pasta_curves::{Eq, Fp};
use ragu::{Domain, Polynomial};
use zcash_mimc::spec::tachyon::TachyonP5R8192;

lazy_static! {
    /// `C` interpolating the rotated constant schedule over `⟨omega⟩`, so
    /// `C(omega^j) = c_{(j+1) mod |D|}` (the wrap node carries `c_0 = 0`). This
    /// is the committed offset constant read by the in-circuit recurrence, so it
    /// must be the interpolant (ifft) of the rotated values, never the raw
    /// values as coefficients.
    pub static ref CONSTANT_SCHEDULE: Polynomial = {
        let mut constants = Vec::from(TachyonP5R8192::CONSTANTS);
        constants.rotate_left(1);
        Domain::new(TachyonP5R8192::ROUNDS.ilog2()).ifft(&mut constants);
        Polynomial::from_coeffs(&constants)
    };
    pub static ref CONSTANT_SCHEDULE_COMMIT: Eq = CONSTANT_SCHEDULE.commit();
}

#[derive(Clone, Copy, Debug)]
pub struct ExpKeySpectrumCommit(pub Eq);

#[derive(Clone, Debug)]
pub struct ExpKeySpectrumPoly(pub Polynomial);

#[derive(Clone, Copy, Debug)]
pub struct ExpandedKeyCommit(pub Eq);

#[derive(Clone, Debug)]
pub struct ExpandedKeyPoly(pub Polynomial);

#[derive(Clone, Debug)]
pub struct NfEmitterPoly(pub Polynomial);
#[derive(Clone, Copy, Debug)]
pub struct NfEmitterCommit(pub Eq);

#[derive(Clone, Copy, Debug)]
pub struct NfEmittersDigest(pub Fp);

#[cfg(test)]
#[expect(
    clippy::as_conversions,
    clippy::integer_division_remainder_used,
    reason = "test code"
)]
mod tests {
    use ff::Field as _;
    use pasta_curves::Fp;
    use ragu::{Domain, Polynomial};
    use zcash_mimc::spec::tachyon::TachyonP5R8192;

    use crate::{
        primitives::trace::{CONSTANT_SCHEDULE, NfEmitterPoly},
        relations::subgroup_generator,
    };

    #[test]
    fn interpolated_poly_reproduces_the_cipher_states() {
        // The cipher→poly bridge: T interpolates the keyed state sequence over
        // ⟨omega⟩, so T(omega^i) returns cipher state i. A real κ=4 pass, sampled.
        let keys = [
            Fp::from(7u64),
            Fp::from(8u64),
            Fp::from(9u64),
            Fp::from(10u64),
        ];
        let mut states =
            zcash_mimc::state_sequence::<TachyonP5R8192, Fp, 5, 8192>(&keys, Fp::from(3u64));
        let evaluations = states;
        Domain::new(TachyonP5R8192::ROUNDS.ilog2()).ifft(&mut states);
        let poly = NfEmitterPoly(Polynomial::from_coeffs(&states));
        let omega = subgroup_generator::<{ TachyonP5R8192::ROUNDS }>();
        for index in [0, 1, 4096, TachyonP5R8192::ROUNDS - 1] {
            assert_eq!(
                poly.0.eval(omega.pow_vartime([index as u64])),
                evaluations[index],
                "T(omega^i) must reproduce cipher state i"
            );
        }
    }

    #[test]
    fn constant_schedule_interpolates_the_rotated_constants() {
        // C(omega^j) = c_{(j+1) mod |D|}; the wrap node omega^{|D|-1} carries c_0 = 0.
        let schedule = CONSTANT_SCHEDULE.clone();
        let constants = TachyonP5R8192::CONSTANTS;
        let omega = subgroup_generator::<{ TachyonP5R8192::ROUNDS }>();
        for node in [0, 1, 4096, TachyonP5R8192::ROUNDS - 1] {
            assert_eq!(
                schedule.eval(omega.pow_vartime([node as u64])),
                constants[(node + 1) % TachyonP5R8192::ROUNDS],
                "C(omega^j) must be the rotated constant c_(j+1 mod |D|)"
            );
        }
        assert_eq!(
            schedule.eval(omega.pow_vartime([(TachyonP5R8192::ROUNDS - 1) as u64])),
            Fp::ZERO,
            "the wrap node carries c_0 = 0"
        );
    }
}
