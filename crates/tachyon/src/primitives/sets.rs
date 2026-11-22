//! Set polynomials, their accumulators and the bridge hash of an
//! accumulator.
//!
//! # Injectivity
//!
//! An accumulator determines its polynomial, by the
//! [Commitments assumption](crate::stamp::proof#assumptions), because no slot
//! holds more than $2^{13}$ coefficients. The accumulator of a set polynomial
//! therefore determines its members, by the [multiset] encoding. The types
//! here hold any polynomial and any point, and a header that carries one says
//! which polynomial its slot holds.
//!
//! The three kinds differ only in what a member is, and nothing in an
//! accumulator says which kind it is. A header's `OnlinePolyCommit` fixes the
//! kind of each slot and a step names the kind it opens, so a step reads a
//! slot only as the kind its header declares.

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

/// Accumulator of a tachygram set, the Pedersen commitment to its
/// [`TachygramSetPoly`] ([Injectivity](self#injectivity)).
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct TachygramSetCommit(EqAffine);

/// Bridge hash of a tachygram accumulator: a Pallas point.
///
/// It commits to the accumulator's two coordinates under the nested
/// generators and determines the accumulator, by the
/// [Commitments assumption](crate::stamp::proof#assumptions). One accumulator
/// has many bridge hashes. [`bridge_hash`](crate::bridge_hash::bridge_hash)
/// computes the one an honest prover uses, and [`Anchor::next_stamp`] absorbs
/// that one. A step reads its own as two wires that are not fixed before its
/// challenge.
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

/// Accumulator of a stamp's action-digest set, the Pedersen commitment to its
/// [`ActionSetPoly`] ([Injectivity](self#injectivity)).
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct ActionSetCommit(EqAffine);

/// Accumulator of an anchor span's member set, the Pedersen commitment to
/// its [`AnchorSetPoly`] ([Injectivity](self#injectivity)).
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct AnchorSetCommit(EqAffine);

/// Set polynomial of a tachygram set (members encoded as roots).
///
/// A member is a [`Tachygram`]. The set is one stamp's, or the multiset sum
/// of several stamps' where a step multiplies their polynomials.
///
/// A step that takes one from its prover as a stamp's does not show that it
/// is a set polynomial. The step absorbs a bridge hash of its accumulator
/// into an [`Anchor`], and an anchor of a pool history determines the
/// accumulator of each stamp behind it.
#[derive(AsRef, Clone, Debug, Into)]
pub struct TachygramSetPoly(Polynomial<Fp, WalletRank>);

/// Set polynomial of a stamp's action-digest set (members encoded as roots).
///
/// A member is an [`ActionDigest`] or a fee digest.
#[derive(AsRef, Clone, Debug, Into)]
pub struct ActionSetPoly(Polynomial<Fp, WalletRank>);

/// Set polynomial of an anchor span's member set (members encoded as roots).
///
/// A member is an [`Anchor`].
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
