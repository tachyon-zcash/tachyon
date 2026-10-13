//! Proptest generators shared across test modules.

use ff::{Field as _, FromUniformBytes as _};
use pasta_curves::Fp;
use proptest::prelude::*;

/// An arbitrary base field element, weighted toward zero, one, minus one and
/// small integers.
pub(crate) fn arb_fp() -> impl Strategy<Value = Fp> {
    prop_oneof![
        1 => Just(Fp::ZERO),
        1 => Just(Fp::ONE),
        1 => Just(-Fp::ONE),
        1 => any::<u64>().prop_map(Fp::from),
        6 => any::<[u8; 64]>().prop_map(|bytes| Fp::from_uniform_bytes(&bytes)),
    ]
}
