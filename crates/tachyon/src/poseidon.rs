//! Poseidon hash primitives for Tachyon.
//!
//! All Poseidon usage routes through this module to ensure consistent
//! parameters: P128Pow5T3 (width 3, rate 2, Pow5 S-box, 128-bit security).

#![allow(clippy::redundant_pub_crate, reason = "pub(crate) in private module")]

use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::Fp;

/// Poseidon hash of `L` field elements with P128Pow5T3 parameters.
///
/// Domain separation is implicit via `ConstantLength<L>` — different
/// input lengths produce independent hash functions.
pub(crate) fn hash<const L: usize>(inputs: [Fp; L]) -> Fp {
    Hash::<_, P128Pow5T3, ConstantLength<L>, 3, 2>::init().hash(inputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_2_deterministic() {
        let lhs = Fp::from(42u64);
        let rhs = Fp::from(99u64);
        assert_eq!(hash([lhs, rhs]), hash([lhs, rhs]));
    }

    #[test]
    fn hash_2_not_commutative() {
        let lhs = Fp::from(1u64);
        let rhs = Fp::from(2u64);
        assert_ne!(hash([lhs, rhs]), hash([rhs, lhs]));
    }
}
