extern crate alloc;

use alloc::vec::Vec;

use derive_more::{Debug, Eq as TotalEq, PartialEq};
use group::Group as _;
use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use crate::note::Nullifier;

/// Pedersen commitment to a nullifier sequence $N$.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct NfSeqCommit(Eq);

/// Witness polynomial for a nullifier sequence $N$ (members encoded as
/// coefficients, ordered by ascending degree).
#[derive(Clone, Debug)]
pub struct NfSeqPoly(Polynomial);

impl NfSeqCommit {
    /// The identity commitment: the commit of the empty nullifier sequence.
    #[must_use]
    pub fn identity() -> Self {
        Self(Eq::identity())
    }
}

impl NfSeqPoly {
    /// Deterministic (untrapdoored) commitment to the sequence polynomial.
    #[must_use]
    pub fn commit(&self) -> NfSeqCommit {
        NfSeqCommit(self.0.commit())
    }

    /// Evaluate the sequence polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl From<NfSeqPoly> for Polynomial {
    fn from(poly: NfSeqPoly) -> Self {
        poly.0
    }
}

impl FromIterator<Nullifier> for NfSeqPoly {
    fn from_iter<I: IntoIterator<Item = Nullifier>>(iter: I) -> Self {
        let coeffs: Vec<Fp> = iter.into_iter().map(Fp::from).collect();
        Self(Polynomial::from_coeffs(&coeffs))
    }
}

impl From<Eq> for NfSeqCommit {
    fn from(point: Eq) -> Self {
        Self(point)
    }
}

impl From<NfSeqCommit> for Eq {
    fn from(commit: NfSeqCommit) -> Self {
        commit.0
    }
}
