extern crate alloc;

use core::ops::Mul;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu_arithmetic::Cycle as _;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_pasta::Pasta;

use crate::{
    collections::{indexed_multiset, poly_mul},
    nullifier::Nullifier,
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
        NfSeqCommit(self.0.commit(Pasta::host_generators(Pasta::baked())))
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
        Self(poly_mul(&self.0, &rhs.0))
    }
}
