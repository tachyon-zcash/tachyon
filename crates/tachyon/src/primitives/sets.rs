extern crate alloc;

use alloc::vec::Vec;

use corez::io::{self, Read, Write};
use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use group::{Curve as _, GroupEncoding as _};
use pasta_curves::{Eq, Fp};
use ragu::{Polynomial, poly_with_roots};

use super::{ActionDigest, Tachygram};
use crate::serialization;

/// Pedersen commitment to a stamp's tachygram set.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct TachygramSetCommit(Eq);

impl TachygramSetCommit {
    /// The 32-byte compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_affine().to_bytes()
    }

    /// Read a 32-byte compressed commitment.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        serialization::read_eq_affine(&mut reader).map(|point| Self(point.into()))
    }

    /// Write a 32-byte compressed commitment.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_eq_affine(&mut writer, &self.0.to_affine())
    }
}

/// Pedersen commitment to a stamp's action-digest set.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct ActionSetCommit(Eq);

/// Witness polynomial for a stamp's tachygram set (members encoded as roots).
#[derive(AsRef, Clone, Debug, Into)]
pub struct TachygramSetPoly(Polynomial);

/// Witness polynomial for a stamp's action-digest set (members encoded as
/// roots).
#[derive(AsRef, Clone, Debug, Into)]
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
        Self(Polynomial::from_coeffs(poly_with_roots(&roots)))
    }
}

impl FromIterator<Tachygram> for TachygramSetPoly {
    fn from_iter<I: IntoIterator<Item = Tachygram>>(iter: I) -> Self {
        let roots: Vec<Fp> = iter.into_iter().map(Fp::from).collect();
        Self(Polynomial::from_coeffs(poly_with_roots(&roots)))
    }
}
