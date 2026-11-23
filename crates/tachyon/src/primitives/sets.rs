use core::iter;

use corez::io::{self, Read, Write};
use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu::{
    Cycle as _, Polynomial, WalletRank,
    pasta::Pasta,
    udon::curve::{Affine as _, Projective as _},
};

use super::{ActionDigest, Anchor, PolySlot, Tachygram};
use crate::{
    collections::multiset,
    pasta,
    pasta::{EpAffine, EqAffine, Fp},
    serialization,
};

/// Pedersen commitment to a tachygram set.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct TachygramSetCommit(EqAffine);

/// Bridge hash of a tachygram-set commitment: a Pallas point.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct TachygramSetBridge(EpAffine);

impl TachygramSetCommit {
    /// Read as an affine point from the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails, the point is not canonically
    /// encoded, or the point is the identity.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let point = serialization::read_eq_affine(&mut reader)?;
        if point.is_identity() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tachygram set commitment is the identity",
            ));
        }
        Ok(Self(point))
    }

    /// Write as an affine point to the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_eq_affine(&mut writer, &self.0)?;
        Ok(())
    }
}

impl Default for TachygramSetCommit {
    /// A commitment to an empty set.
    fn default() -> Self {
        iter::empty().collect::<TachygramSetPoly>().commit()
    }
}

/// Pedersen commitment to a stamp's action-digest set.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct ActionSetCommit(EqAffine);

/// Pedersen commitment to an anchor span's member set.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct AnchorSetCommit(EqAffine);

/// Witness polynomial for a tachygram set (members encoded as roots).
#[derive(AsRef, Clone, Debug, Into)]
pub struct TachygramSetPoly(Polynomial<Fp, WalletRank>);

/// Witness polynomial for a stamp's action-digest set (members encoded as
/// roots).
#[derive(AsRef, Clone, Debug, Into)]
pub struct ActionSetPoly(Polynomial<Fp, WalletRank>);

/// Witness polynomial for an anchor span's member set (members encoded as
/// roots).
#[derive(AsRef, Clone, Debug, Into)]
pub struct AnchorSetPoly(Polynomial<Fp, WalletRank>);

impl AnchorSetPoly {
    /// Names this polynomial in a header that carries one.
    pub const SLOT: PolySlot<Self> = PolySlot::new();

    /// Deterministic (untrapdoored) commitment to the set polynomial.
    #[must_use]
    pub fn commit(&self) -> AnchorSetCommit {
        AnchorSetCommit(
            self.0
                .commit(Pasta::host_generators(pasta::baked()))
                .to_affine(),
        )
    }
}

impl FromIterator<Anchor> for AnchorSetPoly {
    fn from_iter<I: IntoIterator<Item = Anchor>>(iter: I) -> Self {
        Self(multiset::encode(iter.into_iter().map(Fp::from)))
    }
}

impl TachygramSetPoly {
    /// Names this polynomial in a header that carries one.
    pub const SLOT: PolySlot<Self> = PolySlot::new();

    /// Wraps an arbitrary polynomial, skipping set encoding, to exercise step
    /// inputs.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub const fn arbitrary(poly: Polynomial<Fp, WalletRank>) -> Self {
        Self(poly)
    }

    /// Deterministic (untrapdoored) commitment to the set polynomial.
    #[must_use]
    pub fn commit(&self) -> TachygramSetCommit {
        TachygramSetCommit(
            self.0
                .commit(Pasta::host_generators(pasta::baked()))
                .to_affine(),
        )
    }
}

impl ActionSetPoly {
    /// Names this polynomial in a header that carries one.
    pub const SLOT: PolySlot<Self> = PolySlot::new();

    /// Deterministic (untrapdoored) commitment to the set polynomial.
    #[must_use]
    pub fn commit(&self) -> ActionSetCommit {
        ActionSetCommit(
            self.0
                .commit(Pasta::host_generators(pasta::baked()))
                .to_affine(),
        )
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
