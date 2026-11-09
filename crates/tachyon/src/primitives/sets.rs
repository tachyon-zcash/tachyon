use core::iter;

use corez::io::{self, Read, Write};
use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::{Cycle as _, FixedGenerators as _, pasta::Pasta};
use udon::curve::{Affine as _, Projective as _};

use super::{ActionDigest, Anchor, Tachygram};
use crate::{
    collections::multiset,
    pasta,
    pasta::{EpAffine, Eq, Fp},
    serialization,
    stamp::proof::PROOF_SYSTEM,
};

/// Pedersen commitment to a stamp's tachygram set.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct TachygramSetCommit(Eq);

/// Bridge hash of a tachygram-set commitment: a non-identity Pallas point.
#[derive(Clone, Copy, Debug, Into, PartialEq, TotalEq)]
pub struct TachygramSetBridge(EpAffine);

impl TachygramSetBridge {
    /// Builds the bridge hash from its affine coordinates.
    ///
    /// # Errors
    ///
    /// Fails if `(x, y)` is not on the curve or encodes the identity.
    pub fn from_xy(x: Fp, y: Fp) -> ragu_core::Result<Self> {
        EpAffine::from_xy(x, y)
            .filter(|point| !point.is_identity())
            .map(Self)
            .ok_or_else(|| {
                ragu_core::Error::InvalidWitness(
                    "bridge hash is not a non-identity curve point".into(),
                )
            })
    }

    /// The point's affine coordinates $(x, y)$.
    ///
    /// # Panics
    ///
    /// Never: every constructor rejects the identity.
    #[must_use]
    #[expect(clippy::expect_used, reason = "the bridge hash is never the identity")]
    pub fn coordinates(&self) -> (Fp, Fp) {
        self.0
            .coordinates()
            .expect("bridge hash is a non-identity point")
    }
}

impl TachygramSetCommit {
    /// Hashes this commitment through the application's bridge-hash stage.
    ///
    /// # Errors
    ///
    /// Fails if the commitment or its bridge hash is the identity.
    pub fn bridge(self) -> ragu_core::Result<TachygramSetBridge> {
        let point = PROOF_SYSTEM.bridge_hash(self.0.to_affine())?;
        if point.is_identity() {
            return Err(ragu_core::Error::InvalidWitness(
                "bridge hash is the identity".into(),
            ));
        }
        Ok(TachygramSetBridge(point))
    }

    /// Read as an affine point from the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or the bytes are not a canonical
    /// curve point.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let commit = serialization::read_eq_affine(&mut reader)?;
        Ok(Self(commit.into()))
    }

    /// Write as an affine point to the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_eq_affine(&mut writer, &self.0.to_affine())?;
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
pub struct ActionSetCommit(Eq);

impl ActionSetCommit {
    /// Read as an affine point from the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if reading fails or the bytes are not a canonical
    /// curve point.
    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let commit = serialization::read_eq_affine(&mut reader)?;
        Ok(Self(commit.into()))
    }

    /// Write as an affine point to the consensus wire format.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        serialization::write_eq_affine(&mut writer, &self.0.to_affine())?;
        Ok(())
    }
}

impl Default for ActionSetCommit {
    /// A commitment to an empty set.
    fn default() -> Self {
        iter::empty().collect::<ActionSetPoly>().commit()
    }
}

/// Pedersen commitment to an anchor span's member set.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct AnchorSetCommit(Eq);

impl AnchorSetCommit {
    /// Commitment to the one-member set $\\{\mathsf{anchor}\\}$, the
    /// polynomial $X - \mathsf{anchor}$, computed from the fixed generators:
    ///
    /// $$
    ///   G_1 - [\mathsf{anchor}]\,G_0
    /// $$
    #[must_use]
    #[expect(
        clippy::indexing_slicing,
        reason = "the generator table spans every coefficient of a production-rank polynomial"
    )]
    pub fn singleton(anchor: Anchor) -> Self {
        let generators = Pasta::host_generators(pasta::baked()).g();
        Self(Eq::from(generators[1]) - generators[0] * Fp::from(anchor))
    }
}

/// Witness polynomial for a stamp's tachygram set (members encoded as roots).
#[derive(AsRef, Clone, Debug, Into)]
pub struct TachygramSetPoly(Polynomial<Fp, ProductionRank>);

/// Witness polynomial for a stamp's action-digest set (members encoded as
/// roots).
#[derive(AsRef, Clone, Debug, Into)]
pub struct ActionSetPoly(Polynomial<Fp, ProductionRank>);

/// Witness polynomial for an anchor span's member set (members encoded as
/// roots).
#[derive(AsRef, Clone, Debug, Into)]
pub struct AnchorSetPoly(Polynomial<Fp, ProductionRank>);

impl AnchorSetPoly {
    /// Deterministic (untrapdoored) commitment to the set polynomial.
    #[must_use]
    pub fn commit(&self) -> AnchorSetCommit {
        AnchorSetCommit(self.0.commit(Pasta::host_generators(pasta::baked())))
    }

    /// Evaluate the set polynomial at a given point.
    #[must_use]
    pub fn eval(&self, x: Fp) -> Fp {
        self.0.eval(x)
    }
}

impl FromIterator<Anchor> for AnchorSetPoly {
    fn from_iter<I: IntoIterator<Item = Anchor>>(iter: I) -> Self {
        Self(multiset::encode(iter.into_iter().map(Fp::from)))
    }
}

impl TachygramSetPoly {
    /// Deterministic (untrapdoored) commitment to the set polynomial.
    #[must_use]
    pub fn commit(&self) -> TachygramSetCommit {
        TachygramSetCommit(self.0.commit(Pasta::host_generators(pasta::baked())))
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
        ActionSetCommit(self.0.commit(Pasta::host_generators(pasta::baked())))
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
