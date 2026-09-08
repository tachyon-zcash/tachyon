use core::iter;

use corez::io::{self, Read, Write};
use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use group::Curve as _;
use pasta_curves::{Eq, Fp};
use ragu_arithmetic::Cycle as _;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_pasta::Pasta;

use super::{ActionDigest, Tachygram};
use crate::{collections::multiset, serialization};

/// Pedersen commitment to a stamp's tachygram set.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct TachygramSetCommit(Eq);

impl TachygramSetCommit {
    /// Read as an affine point from the consensus wire format.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let commit = serialization::read_eq_affine(&mut reader)?;
        Ok(Self(commit.into()))
    }

    /// Write as an affine point to the consensus wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_eq_affine(&mut writer, &self.0.to_affine())?;
        Ok(())
    }
}

impl Default for TachygramSetCommit {
    /// A commitment to an empty set.
    fn default() -> Self {
        TachygramSetPoly::from_iter(iter::empty()).commit()
    }
}

/// Pedersen commitment to a stamp's action-digest set.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct ActionSetCommit(Eq);

impl ActionSetCommit {
    /// Read as an affine point from the consensus wire format.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let commit = serialization::read_eq_affine(&mut reader)?;
        Ok(Self(commit.into()))
    }

    /// Write as an affine point to the consensus wire format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_eq_affine(&mut writer, &self.0.to_affine())?;
        Ok(())
    }
}

impl Default for ActionSetCommit {
    /// A commitment to an empty set.
    fn default() -> Self {
        ActionSetPoly::from_iter(iter::empty()).commit()
    }
}

/// Witness polynomial for a stamp's tachygram set (members encoded as roots).
#[derive(AsRef, Clone, Debug, Into)]
pub struct TachygramSetPoly(Polynomial<Fp, ProductionRank>);

/// Witness polynomial for a stamp's action-digest set (members encoded as
/// roots).
#[derive(AsRef, Clone, Debug, Into)]
pub struct ActionSetPoly(Polynomial<Fp, ProductionRank>);

impl TachygramSetPoly {
    /// Deterministic (untrapdoored) commitment to the set polynomial.
    #[must_use]
    pub fn commit(&self) -> TachygramSetCommit {
        TachygramSetCommit(self.0.commit(Pasta::host_generators(Pasta::baked())))
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
        ActionSetCommit(self.0.commit(Pasta::host_generators(Pasta::baked())))
    }

    /// Evaluate the set polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl FromIterator<ActionDigest> for ActionSetPoly {
    fn from_iter<I: IntoIterator<Item = ActionDigest>>(iter: I) -> Self {
        Self(multiset::encode(iter.into_iter().map(Fp::from)))
    }
}

impl FromIterator<Tachygram> for TachygramSetPoly {
    fn from_iter<I: IntoIterator<Item = Tachygram>>(iter: I) -> Self {
        Self(multiset::encode(iter.into_iter().map(Fp::from)))
    }
}
