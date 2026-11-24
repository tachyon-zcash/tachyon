//! Set polynomials, their accumulators and accumulator bridge hashes.
//!
//! # Injectivity
//!
//! Because no slot exceeds $2^{13}$ coefficients, an accumulator determines its
//! polynomial under the
//! [Commitments assumption](crate::stamp::proof#assumptions). A set
//! polynomial's accumulator therefore determines its fewer than $2^{13}$
//! members via the [multiset] encoding. These types accept any polynomial or
//! point, and each header specifies which polynomial occupies its slot.
//!
//! Although an accumulator carries no member-kind tag, a header's
//! `OnlinePolyCommit` fixes each slot's kind and steps name the kind they open,
//! so every step reads a slot as its declared kind.

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

/// Bridge hash of a tachygram accumulator as a Pallas point.
///
/// Committing to the accumulator's two coordinates under the nested generators,
/// a bridge hash determines the accumulator and its polynomial under the
/// [Commitments assumption](crate::stamp::proof#assumptions). Each accumulator
/// has many bridge hashes. Honest provers compute the canonical one via
/// [`bridge_hash`](crate::bridge_hash::bridge_hash) for [`Anchor::next_stamp`],
/// whereas steps read it as two wires not fixed before the challenge.
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
/// Members are [`Tachygram`] values from one stamp, or from the multiset sum of
/// several stamps when a step multiplies their polynomials.
///
/// Steps taking a stamp polynomial from the prover do not establish that it is
/// a monic product of linear factors. Instead, they absorb a bridge hash of its
/// accumulator into an [`Anchor`], and a pool-history anchor determines each
/// preceding stamp's accumulator.
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
