//! Fixed generators for host-side polynomial commitments.
//!
//! Re-exports Vesta generators with unknown discrete-log relationships,
//! suitable for Pedersen vector commitments over polynomial coefficient
//! vectors. When tachyon migrates to real ragu, these are replaced by
//! `ragu_pasta::VestaGenerators` from the `Cycle` trait.

extern crate alloc;

use alloc::vec;

use pasta_curves::{Eq, EqAffine, group::Curve as _};

/// Number of Vesta generators.
pub const NUM_GENERATORS: usize = 1 << 13; // 8192

lazy_static::lazy_static! {
    /// Vesta generators for polynomial commitments.
    pub static ref VESTA_GENERATORS: alloc::vec::Vec<EqAffine> = {
        use pasta_curves::arithmetic::CurveExt as _;
        use pasta_curves::group::prime::PrimeCurveAffine as _;
        let hasher = Eq::hash_to_curve("mock_ragu:generators");
        let projective: alloc::vec::Vec<Eq> = (0..NUM_GENERATORS as u32).map(|i| {
            #[expect(clippy::little_endian_bytes, reason = "deterministic derivation")]
            hasher(&i.to_le_bytes())
        }).collect();
        let mut affine = vec![EqAffine::identity(); NUM_GENERATORS];
        Eq::batch_normalize(&projective, &mut affine);
        affine
    };
}

#[cfg(test)]
mod tests {
    use pasta_curves::group::prime::PrimeCurveAffine as _;

    use super::*;

    #[test]
    fn generators_are_not_identity() {
        let g = &*VESTA_GENERATORS;
        assert!(!bool::from(g[0].is_identity()));
        assert!(!bool::from(g[1].is_identity()));
        assert!(!bool::from(g[NUM_GENERATORS - 1].is_identity()));
    }

    #[test]
    fn generators_are_distinct() {
        let g = &*VESTA_GENERATORS;
        assert_ne!(g[0], g[1]);
        assert_ne!(g[0], g[2]);
        assert_ne!(g[1], g[2]);
    }

    #[test]
    fn generator_count() {
        assert_eq!(VESTA_GENERATORS.len(), NUM_GENERATORS);
    }
}
