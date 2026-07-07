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
    /// The commitment to [`CONSTANT_SCHEDULE`], computed once.
    pub static ref CONSTANT_SCHEDULE_COMMIT: Eq = CONSTANT_SCHEDULE.commit();
}

/// The eval-form interpolant of one `mk` part over the order-`MK_PART_LEN`
/// subgroup (`M_p(ζ^r) = part_p[r]`), certified by `MasterSeed` and opened by
/// the committed-key row recurrence.
#[derive(Clone, Debug)]
pub struct NoteMasterKeyPartSpectrum(pub Polynomial);

/// Commitment to a [`NoteMasterKeyPartSpectrum`]; the certified transport of
/// one `mk` part across headers.
#[derive(Clone, Copy, Debug)]
pub struct NoteMasterKeyPartCommit(pub Eq);

/// The interpolant of one expansion part's full cipher-state grid.
///
/// Over the order-`POLY_LEN_MAX` domain, `T(ω^{ROUNDS·r + c})` is row `r`'s
/// round-`c` state; certified by `KeyExpansionStep`'s trace relations.
#[derive(Clone, Debug)]
pub struct ExpandedKeyTraceSpectrum(pub Polynomial);

/// The eval-form interpolant of one expansion part's round-0 cipher inputs.
///
/// The trace grid stores round outputs only, so this is its missing input
/// column, materialized: over the order-`EK_PART_LENGTH` row subgroup,
/// `I(ζ^r) = s + δ·(base + r) + k_0` (the round-0 key folded in). Pinned in
/// `KeyExpansionStep` by the affine recurrence from `(origin, δ)` and read by
/// the strided-column power link into the trace's first column; never rides a
/// header.
#[derive(Clone, Debug)]
pub struct ExpansionInputSpectrum(pub Polynomial);

/// Commitment slot of one certified expanded-key part (`commit(A_p)` plus any
/// non-identity fillers accumulated by the keyset fuse).
#[derive(Clone, Copy, Debug)]
pub struct PartKeyCommit(pub Eq);

/// The eval-form interpolant of one expansion part's `EK_PART_LENGTH` keys.
///
/// Over the order-`EK_PART_LENGTH` subgroup, `A_p(ζ^r) = part_p[r]`; bound to
/// the trace's final column and opened by the emitter's committed-offset
/// recurrence.
#[derive(Clone, Debug)]
pub struct ExpandedKeyPartSpectrum(pub Polynomial);

/// The interpolant of one derivation polynomial's 8192-round emitter trace
/// over the order-`POLY_LEN_MAX` domain (`T_j(ω^i)` is cipher state `i`),
/// read off-domain by the nullifier query.
#[derive(Clone, Debug)]
pub struct NfEmitterSpectrum(pub Polynomial);

/// Commitment to an [`NfEmitterSpectrum`]; the certified transport of one
/// derivation polynomial across headers.
#[derive(Clone, Copy, Debug)]
pub struct NfEmitterCommit(pub Eq);

/// One transcript challenge over all `N` emitter commitments, so downstream
/// consumers absorb a single element for the set.
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
        primitives::trace::{CONSTANT_SCHEDULE, NfEmitterSpectrum},
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

        let states =
            &mut zcash_mimc::state_sequence::<TachyonP5R8192, Fp, 5, 8192>(&keys, Fp::from(3u64));

        let expect_evaluations =
            [0, 1, 4096, TachyonP5R8192::ROUNDS - 1].map(|index| (index, states[index]));

        Domain::new(TachyonP5R8192::ROUNDS.ilog2()).ifft(states);
        let poly = NfEmitterSpectrum(Polynomial::from_coeffs(states));
        let omega = subgroup_generator::<{ TachyonP5R8192::ROUNDS }>();

        for (index, eval) in expect_evaluations {
            assert_eq!(
                poly.0.eval(omega.pow_vartime([index as u64])),
                eval,
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
