//! Set polynomials, their accumulators and accumulator bridge hashes.
//!
//! # Injectivity
//!
//! An accumulator $\sum_j c_j G_j$ weights host generators by polynomial
//! coefficients without a blinding term. No discrete-log relation is known
//! among the host generators, so at these wrappers' limit of $2^{13}$
//! coefficients, each accumulator determines its polynomial and hence, for a
//! [multiset], its fewer than $2^{13}$ members.
//! The wrappers accept arbitrary polynomials and points.

extern crate alloc;

use alloc::vec::Vec;
use core::iter;

use corez::io::{self, Read, Write};
use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu::{
    Cycle as _, Polynomial, WalletRank,
    pasta::Pasta,
    udon::{
        curve::{Affine as _, Projective as _},
        field::Field as _,
    },
};

use super::{ActionDigest, Anchor, PolySlot, Tachygram};
use crate::{
    collections::multiset,
    pasta,
    pasta::{EpAffine, EqAffine, Fp},
    serialization,
};

/// A set polynomial's coefficients in ascending degree through its leading
/// one, as a decompression takes them.
fn monic_coefficients(poly: &Polynomial<Fp, WalletRank>) -> Vec<Fp> {
    let len = poly
        .iter_coeffs()
        .rposition(|coefficient| coefficient != Fp::ZERO)
        .map_or(0, |leading| leading + 1);
    poly.iter_coeffs().take(len).collect()
}

/// Accumulator of a tachygram set, the Pedersen commitment to its
/// [`TachygramSetPoly`] ([Injectivity](self#injectivity)).
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct TachygramSetCommit(EqAffine);

/// Bridge hash of a tachygram accumulator as a Pallas point.
///
/// Committing to the accumulator's two coordinates under the nested generators,
/// a bridge hash determines the accumulator and its polynomial, assuming no
/// known discrete-log relation among those generators. Each accumulator has
/// many bridge hashes. Honest provers compute the canonical one via
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
#[derive(AsRef, Clone, Debug, Into)]
pub struct TachygramSetPoly(Polynomial<Fp, WalletRank>);

/// Set polynomial with one root per [`ActionDigest`] or fee digest.
#[derive(AsRef, Clone, Debug, Into)]
pub struct ActionSetPoly(Polynomial<Fp, WalletRank>);

/// Set polynomial with one root per member [`Anchor`] of a span.
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

    /// Coefficients in ascending degree through the leading one.
    pub(crate) fn coefficients(&self) -> Vec<Fp> {
        monic_coefficients(&self.0)
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

    /// Coefficients in ascending degree through the leading one.
    pub(crate) fn coefficients(&self) -> Vec<Fp> {
        monic_coefficients(&self.0)
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
