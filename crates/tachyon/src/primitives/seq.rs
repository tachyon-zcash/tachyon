extern crate alloc;

use alloc::vec::Vec;
use core::ops::Mul;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::{Cycle as _, pasta::Pasta};
use udon::field::Field as _;

use crate::{
    arithmetic,
    collections::indexed_multiset,
    nullifier::Nullifier,
    pasta,
    pasta::{Eq, Fp},
    primitives::EpochIndex,
};

/// Pedersen commitment to a nullifier sequence.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct NfSeqCommit(Eq);

/// Witness polynomial for a nullifier sequence: the product of its members'
/// encodings, one per member.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct NfSeqPoly(Polynomial<Fp, ProductionRank>);

impl NfSeqPoly {
    /// Build the sequence polynomial for one contiguous run: the members of
    /// the consecutive epochs starting at `epoch_start`.
    #[must_use]
    pub fn new(epoch_start: EpochIndex, nfs: &[Nullifier]) -> Self {
        Self(indexed_multiset::encode(
            (epoch_start.into()..).zip(nfs.iter().copied().map(Fp::from)),
        ))
    }

    /// Deterministic (untrapdoored) commitment to the sequence polynomial.
    #[must_use]
    pub fn commit(&self) -> NfSeqCommit {
        NfSeqCommit(self.0.commit(Pasta::host_generators(pasta::baked())))
    }

    /// Evaluate the sequence polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl Default for NfSeqPoly {
    fn default() -> Self {
        Self(Polynomial::from_coeffs(alloc::vec![Fp::ONE]))
    }
}

impl Mul for NfSeqPoly {
    type Output = Self;

    /// Multiset union: the product of two sequences' member multisets.
    ///
    /// # Panics
    ///
    /// If the product exceeds the polynomial coefficient cap.
    fn mul(self, rhs: Self) -> Self {
        let [left, right] = [self.0, rhs.0].map(|poly| {
            let mut coeffs: Vec<Fp> = poly.iter_coeffs().collect();
            coeffs.truncate(
                coeffs
                    .iter()
                    .rposition(|coeff| coeff != &Fp::ZERO)
                    .map_or(0, |idx| idx + 1),
            );
            coeffs
        });
        Self(Polynomial::from_coeffs(arithmetic::poly_mul(&left, &right)))
    }
}
