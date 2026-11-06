use core::iter;

use corez::io::{self, Read, Write};
use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::{Cycle as _, FixedGenerators as _, pasta::Pasta};
use udon::{
    curve::{Affine as _, Projective as _},
    field::Field as _,
};

use super::{ActionDigest, Anchor, Tachygram};
use crate::{
    collections::multiset,
    pasta,
    pasta::{Eq, Fp},
    serialization,
};

/// Pedersen commitment to a stamp's tachygram set.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct TachygramSetCommit(Eq);

impl TachygramSetCommit {
    /// The compressed point encoding as two 128-bit $\mathbb{F}_p$ limbs.
    ///
    /// # Errors
    ///
    /// Returns an error if the commitment is the identity.
    pub(crate) fn to_limbs(self) -> ragu_core::Result<[Fp; 2]> {
        commitment_limbs(self.0)
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
    /// The compressed point encoding as two 128-bit $\mathbb{F}_p$ limbs.
    ///
    /// # Errors
    ///
    /// Returns an error if the commitment is the identity.
    pub(crate) fn to_limbs(self) -> ragu_core::Result<[Fp; 2]> {
        commitment_limbs(self.0)
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

fn commitment_limbs(commitment: Eq) -> ragu_core::Result<[Fp; 2]> {
    let point = commitment.to_affine();
    if point.is_identity() {
        return Err(ragu_core::Error::InvalidWitness(
            "cannot encode the identity commitment".into(),
        ));
    }
    let bytes = point.to_bytes();
    let mut limbs = [[0u8; 16]; 2];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(16)) {
        limb.copy_from_slice(chunk);
    }
    Ok(limbs.map(|limb| Fp::from_u128(u128::from_le_bytes(limb))))
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
