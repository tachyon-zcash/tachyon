extern crate alloc;

use alloc::vec::Vec;

use pasta_curves::{EqAffine, Fp};
use ragu::{Commitment, Polynomial};

use crate::note::Nullifier;

/// Pedersen commitment to a nullifier sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NullifierSeqCommit(Commitment);

/// Pedersen commitment to a pronullifier sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PronullifierSeqCommit(Commitment);

/// Witness polynomial for a nullifier sequence (members encoded as
/// coefficients, ordered by ascending degree).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NullifierSeqPoly(Polynomial);

/// Witness polynomial for a pronullifier sequence (members encoded as
/// coefficients, ordered by ascending degree).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PronullifierSeqPoly(Polynomial);

impl NullifierSeqPoly {
    /// Deterministic (untrapdoored) commitment to the sequence polynomial.
    #[must_use]
    pub fn commit(&self) -> NullifierSeqCommit {
        NullifierSeqCommit(self.0.commit())
    }

    /// Concatenate two sequences: `self`'s coefficients followed by `other`'s.
    #[must_use]
    pub fn concat(&self, other: &Self) -> Self {
        let mut coeffs = self.0.coefficients().to_vec();
        coeffs.extend_from_slice(other.0.coefficients());
        Self(Polynomial::from_coeffs(&coeffs))
    }

    /// Evaluate the sequence polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl From<NullifierSeqPoly> for Polynomial {
    fn from(poly: NullifierSeqPoly) -> Self {
        poly.0
    }
}

impl PronullifierSeqPoly {
    /// Deterministic (untrapdoored) commitment to the sequence polynomial.
    #[must_use]
    pub fn commit(&self) -> PronullifierSeqCommit {
        PronullifierSeqCommit(self.0.commit())
    }

    /// Concatenate two sequences: `self`'s coefficients followed by `other`'s.
    #[must_use]
    pub fn concat(&self, other: &Self) -> Self {
        let mut coeffs = self.0.coefficients().to_vec();
        coeffs.extend_from_slice(other.0.coefficients());
        Self(Polynomial::from_coeffs(&coeffs))
    }

    /// Evaluate the sequence polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl From<PronullifierSeqPoly> for Polynomial {
    fn from(poly: PronullifierSeqPoly) -> Self {
        poly.0
    }
}

impl From<&[Nullifier]> for NullifierSeqPoly {
    fn from(nfs: &[Nullifier]) -> Self {
        let coeffs: Vec<Fp> = nfs.iter().map(|&nf| Fp::from(nf)).collect();
        Self(Polynomial::from_coeffs(&coeffs))
    }
}

impl From<&[Fp]> for PronullifierSeqPoly {
    fn from(pronfs: &[Fp]) -> Self {
        Self(Polynomial::from_coeffs(pronfs))
    }
}

impl From<&[Nullifier]> for NullifierSeqCommit {
    fn from(nfs: &[Nullifier]) -> Self {
        NullifierSeqPoly::from(nfs).commit()
    }
}

impl From<&[Fp]> for PronullifierSeqCommit {
    fn from(pronfs: &[Fp]) -> Self {
        PronullifierSeqPoly::from(pronfs).commit()
    }
}

impl From<NullifierSeqCommit> for Commitment {
    fn from(commit: NullifierSeqCommit) -> Self {
        commit.0
    }
}

impl From<PronullifierSeqCommit> for Commitment {
    fn from(commit: PronullifierSeqCommit) -> Self {
        commit.0
    }
}

impl From<NullifierSeqCommit> for EqAffine {
    fn from(commit: NullifierSeqCommit) -> Self {
        *commit.0.inner()
    }
}

impl From<PronullifierSeqCommit> for EqAffine {
    fn from(commit: PronullifierSeqCommit) -> Self {
        *commit.0.inner()
    }
}
