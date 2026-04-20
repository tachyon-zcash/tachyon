//! Running accumulator that folds batches of `Fp` elements into an `Fq` state.
//!
//! Each batch is Pedersen-committed as the coefficients of a polynomial with
//! the batch elements as roots, and the resulting Vesta point is absorbed
//! into the state via a Poseidon hash over `Fq`.

use ff::{Field, PrimeField};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{EqAffine, Fp, Fq, arithmetic::CurveAffine as _};

use crate::{Multiset, constants::ACCUMULATOR_DOMAIN};

/// A running accumulator whose state is an `Fq` element at a given height.
///
/// Height is the number of batches that have been absorbed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Accumulator {
    state: Fq,
    height: u64,
}

impl Accumulator {
    /// Initial accumulator (state `Fq::ZERO`, height `0`).
    pub fn new() -> Self {
        Self {
            state: Fq::ZERO,
            height: 0,
        }
    }

    /// Absorb a batch of `Fp` elements, incrementing the height by one.
    pub fn accumulate(self, elements: &[Fp]) -> Self {
        let point = EqAffine::from(Multiset::<Fp>::from(elements).commit());
        let coords = point
            .coordinates()
            .into_option()
            .expect("pedersen commitment is the identity point");
        #[expect(clippy::little_endian_bytes, reason = "specified behavior")]
        let domain = Fq::from_u128(u128::from_le_bytes(*ACCUMULATOR_DOMAIN));
        let next = Hash::<Fq, P128Pow5T3, ConstantLength<4>, 3, 2>::init()
            .hash([domain, self.state, *coords.x(), *coords.y()]);
        Self {
            state: next,
            height: self.height + 1,
        }
    }

    /// Return the current `Fq` state of the accumulator.
    pub fn state(&self) -> Fq {
        self.state
    }

    /// Return the number of batches that have been absorbed.
    pub fn height(&self) -> u64 {
        self.height
    }
}

impl Default for Accumulator {
    fn default() -> Self {
        Self::new()
    }
}
