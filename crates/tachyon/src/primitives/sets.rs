extern crate alloc;

use alloc::vec::Vec;
use core::cmp;

use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use super::{ActionDigest, Tachygram};
use crate::{Action, ActionDigestError};

/// Pedersen commitment to a stamp's tachygram set.
#[derive(Clone, Copy, Debug, cmp::Eq, PartialEq)]
pub struct TachygramSetCommit(Eq);

/// Pedersen commitment to a stamp's action-digest set.
#[derive(Clone, Copy, Debug, cmp::Eq, PartialEq)]
pub struct ActionSetCommit(Eq);

/// Witness polynomial for a stamp's tachygram set (members encoded as roots).
#[derive(Clone, Debug)]
pub struct TachygramSetPoly(Polynomial);

/// Witness polynomial for a stamp's action-digest set (members encoded as
/// roots).
#[derive(Clone, Debug)]
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

impl From<TachygramSetPoly> for Polynomial {
    fn from(poly: TachygramSetPoly) -> Self {
        poly.0
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

impl From<ActionSetPoly> for Polynomial {
    fn from(poly: ActionSetPoly) -> Self {
        poly.0
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

impl From<&[ActionDigest]> for ActionSetCommit {
    fn from(ads: &[ActionDigest]) -> Self {
        ActionSetPoly::from(ads).commit()
    }
}

impl TryFrom<&[Action]> for ActionSetCommit {
    type Error = ActionDigestError;

    fn try_from(actions: &[Action]) -> Result<Self, Self::Error> {
        let ads: Vec<ActionDigest> = actions
            .iter()
            .map(Action::digest)
            .collect::<Result<Vec<ActionDigest>, ActionDigestError>>()?;
        Ok(ActionSetPoly::from(ads.as_slice()).commit())
    }
}

impl From<&[Tachygram]> for TachygramSetCommit {
    fn from(tgs: &[Tachygram]) -> Self {
        TachygramSetPoly::from(tgs).commit()
    }
}

impl From<ActionSetCommit> for Eq {
    fn from(commit: ActionSetCommit) -> Self {
        commit.0
    }
}

impl From<Eq> for ActionSetCommit {
    fn from(point: Eq) -> Self {
        Self(point)
    }
}

impl From<TachygramSetCommit> for Eq {
    fn from(commit: TachygramSetCommit) -> Self {
        commit.0
    }
}

impl From<Eq> for TachygramSetCommit {
    fn from(point: Eq) -> Self {
        Self(point)
    }
}
