//! Set polynomials, their accumulators and the bridge hash of an
//! accumulator.
//!
//! # Injectivity
//!
//! A set polynomial is the [multiset] encoding of its members and determines
//! them. An accumulator is the commitment to a polynomial under the host
//! generators, without a blinding term. It determines its polynomial among
//! those of at most $2^{13}$ coefficients, by the
//! [Commitments assumption](crate::stamp::proof#assumptions), and no slot
//! holds a longer one. The accumulator of a set polynomial therefore
//! determines a multiset of fewer than $2^{13}$ members.
//!
//! The polynomial types below hold any polynomial, and the commitment types
//! any point. A header that carries one says which polynomial its slot
//! holds. [`FromIterator`] builds a set polynomial natively.
//!
//! The three kinds are built the same way and differ in what a member is.
//! Nothing in an accumulator says which kind it is. A header's
//! `OnlinePolyCommit` fixes the kind of each of its slots, and a step names
//! the kind it opens, so a step reads a slot only as the kind its header
//! declares.

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
/// [`TachygramSetPoly`].
///
/// It determines the polynomial, and the tachygrams when the polynomial is a
/// set polynomial, by the [module's Injectivity section](self#injectivity).
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct TachygramSetCommit(EqAffine);

/// Bridge hash of a tachygram accumulator: a Pallas point.
///
/// A bridge hash of an accumulator is a commitment, under the nested
/// generators, to a polynomial that holds the accumulator's two coordinates.
/// It determines the accumulator, by the
/// [Commitments assumption](crate::stamp::proof#assumptions), and with it the
/// polynomial.
///
/// One accumulator has many bridge hashes.
/// [`bridge_hash`](crate::bridge_hash::bridge_hash) computes the one an
/// honest prover uses, and [`Anchor::next_stamp`] absorbs that one. A step
/// reads the bridge hash of its own last output slot as two wires. Ragu holds
/// them to a bridge hash of that slot's accumulator. They are not fixed
/// before the step's challenge.
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
/// [`ActionSetPoly`].
///
/// It determines the polynomial, and the digests when the polynomial is a
/// set polynomial, by the [module's Injectivity section](self#injectivity).
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct ActionSetCommit(EqAffine);

/// Accumulator of an anchor span's member set, the Pedersen commitment to
/// its [`AnchorSetPoly`].
///
/// It determines the polynomial, and the anchors when the polynomial is a
/// set polynomial, by the [module's Injectivity section](self#injectivity).
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct AnchorSetCommit(EqAffine);

/// Set polynomial of a tachygram set (members encoded as roots).
///
/// A member is a [`Tachygram`]. The set is one stamp's, or the multiset sum
/// of several stamps' where a step multiplies their polynomials.
///
/// The type itself holds any polynomial. A step that takes one from its
/// prover as a stamp's does not show that it is a set polynomial. The step
/// absorbs a bridge hash of its accumulator into an [`Anchor`], and an anchor
/// of a pool history determines the accumulator of each stamp behind it.
#[derive(AsRef, Clone, Debug, Into)]
pub struct TachygramSetPoly(Polynomial<Fp, WalletRank>);

/// Set polynomial of a stamp's action-digest set (members encoded as roots).
///
/// A member is an [`ActionDigest`] or a fee digest. The type itself holds any
/// polynomial.
#[derive(AsRef, Clone, Debug, Into)]
pub struct ActionSetPoly(Polynomial<Fp, WalletRank>);

/// Set polynomial of an anchor span's member set (members encoded as roots).
///
/// A member is an [`Anchor`]. The type itself holds any polynomial.
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
