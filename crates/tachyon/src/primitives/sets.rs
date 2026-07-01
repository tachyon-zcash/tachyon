extern crate alloc;

use alloc::vec::Vec;

use derive_more::{Debug, Eq as TotalEq, From, Into, PartialEq};
use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use super::{ActionDigest, Tachygram};

/// Pedersen commitment to a stamp's tachygram set.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct TachygramSetCommit(Eq);

/// Pedersen commitment to a stamp's action-digest set.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct ActionSetCommit(Eq);

/// Witness polynomial for a stamp's tachygram set (members encoded as roots).
#[derive(Clone, Debug, Into)]
pub struct TachygramSetPoly(Polynomial);

/// Witness polynomial for a stamp's action-digest set (members encoded as
/// roots).
#[derive(Clone, Debug, Into)]
pub struct ActionSetPoly(Polynomial);

impl TachygramSetPoly {
    /// Deterministic (untrapdoored) commitment to the set polynomial.
    #[must_use]
    pub fn commit(&self) -> TachygramSetCommit {
        TachygramSetCommit(self.0.commit())
    }

    /// Evaluate the set polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl ActionSetPoly {
    /// Deterministic (untrapdoored) commitment to the set polynomial.
    #[must_use]
    pub fn commit(&self) -> ActionSetCommit {
        ActionSetCommit(self.0.commit())
    }

    /// Evaluate the set polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl FromIterator<ActionDigest> for ActionSetPoly {
    fn from_iter<I: IntoIterator<Item = ActionDigest>>(iter: I) -> Self {
        let roots: Vec<Fp> = iter.into_iter().map(Fp::from).collect();
        Self(Polynomial::from_roots(&roots))
    }
}

impl FromIterator<Tachygram> for TachygramSetPoly {
    fn from_iter<I: IntoIterator<Item = Tachygram>>(iter: I) -> Self {
        let roots: Vec<Fp> = iter.into_iter().map(Fp::from).collect();
        Self(Polynomial::from_roots(&roots))
    }
}
