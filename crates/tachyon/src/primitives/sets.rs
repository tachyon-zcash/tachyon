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

impl From<&[ActionDigest]> for ActionSetPoly {
    fn from(ads: &[ActionDigest]) -> Self {
        let roots: Vec<Fp> = ads.iter().map(|&ad| Fp::from(ad)).collect();
        Self(Polynomial::from_roots(&roots))
    }
}

impl From<&[Tachygram]> for TachygramSetPoly {
    fn from(tgs: &[Tachygram]) -> Self {
        let roots: Vec<Fp> = tgs.iter().map(|&tg| Fp::from(tg)).collect();
        Self(Polynomial::from_roots(&roots))
    }
}
