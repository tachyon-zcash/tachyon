extern crate alloc;

use alloc::vec::Vec;
use core::iter;

use derive_more::{Debug, Eq as TotalEq, PartialEq};
use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use crate::note::Nullifier;

/// Pedersen commitment to a nullifier sequence $N$.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct NfSeqCommit(Eq);

/// Witness polynomial for a nullifier sequence $N$: members encoded as
/// coefficients ordered by ascending degree, terminated by a sentinel
/// coefficient $1$ one degree above the members.
///
/// The sentinel makes the polynomial nonzero for every sequence (the empty
/// sequence is the constant $1$), so the commitment is never the identity
/// point, which the in-circuit point representation cannot hold. It also pins
/// the sequence's exact length: commit-equality alone bounds rank only from
/// above (trailing zeros are invisible), while the sentinel fixes the top
/// coefficient at the statement's span.
#[derive(Clone, Debug)]
pub struct NfSeqPoly(Polynomial);

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
        let coeffs: Vec<Fp> = iter
            .into_iter()
            .map(Fp::from)
            .chain(iter::once(Fp::ONE))
            .collect();
        Self(Polynomial::from_coeffs(&coeffs))
    }
}

/// A finalized nullifier range: members as plain coefficients ordered by
/// ascending degree, with **no** sentinel terminator.
///
/// Where [`NfSeqPoly`] is the in-flight sequence encoding (sentinel-terminated
/// so its commitment is never the identity and its length is pinned), a range
/// is the *finalized* form the arc machinery consumes: coefficient $d$ is the
/// nullifier at offset $d$, with nothing above the top leaf, so a Horner
/// evaluation $q(\beta) = \sum_d \mathit{nf}_d\,\beta^d$ carries no stray
/// sentinel term. [`UnspentBind`](crate::stamp::proof::pool::UnspentBind)
/// finalizes an `elapsed` [`NfSeqPoly`] into an `NfRangePoly` by overwriting
/// the sentinel slot with the tip nullifier (a shifted combination with no
/// re-terminating monomial, via
/// [`enforce_shifted_combination`](crate::relations::enforce::enforce_shifted_combination)),
/// and guards the top leaf nonzero so the commitment stays off the identity.
#[derive(Clone, Debug)]
pub struct NfRangePoly(Polynomial);

impl NfRangePoly {
    /// Deterministic (untrapdoored) commitment to the range polynomial.
    #[must_use]
    pub fn commit(&self) -> NfSeqCommit {
        NfSeqCommit(self.0.commit())
    }

    /// Evaluate the range polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl From<NfRangePoly> for Polynomial {
    fn from(poly: NfRangePoly) -> Self {
        poly.0
    }
}

impl FromIterator<Nullifier> for NfRangePoly {
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

#[cfg(test)]
mod tests {
    use group::Group as _;

    use super::*;

    /// The empty sequence commits to the sentinel constant $1$, never the
    /// identity point.
    #[test]
    fn empty_sequence_commit_is_not_identity() {
        let empty: NfSeqPoly = iter::empty().collect();
        assert_eq!(empty.eval(Fp::ZERO), Fp::ONE);
        assert_ne!(Eq::from(empty.commit()), Eq::identity());
    }
}
