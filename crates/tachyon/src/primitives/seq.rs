extern crate alloc;

use alloc::vec::Vec;

use pasta_curves::{EqAffine, Fp};
use ragu::{Commitment, Polynomial};

use crate::note::Nullifier;

/// Pedersen commitment to a nullifier sequence $N$.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NfSeqCommit(Commitment);

/// Witness polynomial for a nullifier sequence $N$ (members encoded as
/// coefficients, ordered by ascending degree).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NfSeqPoly(Polynomial);

impl NfSeqCommit {
    /// The identity commitment: the commit of the empty nullifier sequence.
    #[must_use]
    pub fn identity() -> Self {
        Self(Commitment::identity())
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

impl From<&[Nullifier]> for NfSeqPoly {
    fn from(nfs: &[Nullifier]) -> Self {
        let coeffs: Vec<Fp> = nfs.iter().map(|&nf| Fp::from(nf)).collect();
        Self(Polynomial::from_coeffs(&coeffs))
    }
}

impl From<&[Nullifier]> for NfSeqCommit {
    fn from(nfs: &[Nullifier]) -> Self {
        NfSeqPoly::from(nfs).commit()
    }
}

impl From<Commitment> for NfSeqCommit {
    fn from(commit: Commitment) -> Self {
        Self(commit)
    }
}

impl From<NfSeqCommit> for Commitment {
    fn from(commit: NfSeqCommit) -> Self {
        commit.0
    }
}

impl From<NfSeqCommit> for EqAffine {
    fn from(commit: NfSeqCommit) -> Self {
        *commit.0.inner()
    }
}
