use alloc::vec::Vec;
use core::array;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu::{
    Cycle as _, Polynomial, WalletRank,
    pasta::Pasta,
    udon::{curve::Projective as _, field::Field as _},
};
use rand_core::CryptoRng;

use super::{PolySlot, Tachygram, TachygramSetPoly};
use crate::{
    collections::qr,
    pasta,
    pasta::{EqAffine, Fp},
};

/// The choice of multiplier $m$ in the class equation
/// $r^2 = m \cdot (x + R)$.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub enum QrClass {
    /// $x + R$ has no square root.
    NonResidue,
    /// $x + R$ is a square or zero.
    Residue,
}

impl QrClass {
    /// The other class at a split.
    #[must_use]
    pub const fn sibling(self) -> Self {
        match self {
            Self::NonResidue => Self::Residue,
            Self::Residue => Self::NonResidue,
        }
    }

    /// The class multiplier $m$: one for the residue class, the fixed
    /// non-residue $c$ for the non-residue class.
    #[must_use]
    pub const fn multiplier(self) -> Fp {
        match self {
            Self::NonResidue => qr::QUADRATIC_NON_RESIDUE,
            Self::Residue => Fp::ONE,
        }
    }

    /// The staged class bit, set for the residue class.
    pub(crate) const fn bit(self) -> bool {
        matches!(self, Self::Residue)
    }

    /// The class whose bit is `bit`.
    pub(crate) const fn from_bit(bit: bool) -> Self {
        if bit { Self::Residue } else { Self::NonResidue }
    }
}

/// A network's discriminants $R_j = R_0 + j$, indexed by depth.
/// The network's headers carry this collection as its first discriminant.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrDiscriminants(Fp);

impl QrDiscriminants {
    /// Sample a uniformly random first discriminant.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(|bytes| rng.fill_bytes(bytes)))
    }

    /// The discriminant $R_j$ at the given depth.
    #[must_use]
    pub fn at(self, depth: u32) -> QrDiscriminant {
        QrDiscriminant(self.0 + Fp::from(u64::from(depth)))
    }

    /// The profile `value` takes through `depth` splits.
    ///
    /// # Panics
    ///
    /// Panics if `depth` exceeds [`QrProfile::MAX_DEPTH`].
    #[must_use]
    pub fn profile(self, value: Tachygram, depth: u32) -> QrProfile {
        (0..depth).fold(QrProfile::ROOT, |profile, level| {
            profile.descend(self.at(level).classify(value).class())
        })
    }

    /// The claim for `value` at each of the [`QrProfile::MAX_DEPTH`] profile
    /// depths, as given to a query step.
    #[must_use]
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "array indices are below QrProfile::MAX_DEPTH"
    )]
    pub fn class_claims(self, value: Tachygram) -> [QrClassClaim; QrProfile::MAX_DEPTH] {
        array::from_fn(|level| self.at(level as u32).classify(value).claim())
    }
}

/// One discriminant $R$.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrDiscriminant(Fp);

impl QrDiscriminant {
    /// Classify `value` at this discriminant by solving the class equation
    /// for the multiplier $m$ and root $r$.
    ///
    /// # Panics
    ///
    /// Panics if neither branch has a root, which is impossible in this field.
    #[must_use]
    pub fn classify(self, value: Tachygram) -> QrClassification {
        let shifted = Fp::from(value) + self.0;
        let (class, root) = shifted.sqrt().map_or_else(
            || {
                let class = QrClass::NonResidue;
                #[expect(
                    clippy::expect_used,
                    reason = "multiplying a non-square by the non-residue gives a square"
                )]
                let root = (class.multiplier() * shifted)
                    .sqrt()
                    .expect("non-residue branch has a root");
                (class, root)
            },
            |root| (QrClass::Residue, root),
        );
        QrClassification {
            value,
            discriminant: self,
            class,
            root,
        }
    }

    /// Split `members` at this discriminant into `(non_residue, residue)`.
    /// Each list retains its input order and any repeats.
    #[must_use]
    pub fn split(self, members: &[Tachygram]) -> (QrSide, QrSide) {
        let mut non_residue = QrSide {
            discriminant: self,
            class: QrClass::NonResidue,
            points: Vec::new(),
        };
        let mut residue = QrSide {
            discriminant: self,
            class: QrClass::Residue,
            points: Vec::new(),
        };
        for &member in members {
            let classification = self.classify(member);
            let side = match classification.class() {
                QrClass::NonResidue => &mut non_residue,
                QrClass::Residue => &mut residue,
            };
            side.points
                .push((classification.value(), classification.root()));
        }
        (non_residue, residue)
    }
}

/// One side of a split: the classifications that share a class at one
/// discriminant.
#[derive(Debug)]
pub struct QrSide {
    discriminant: QrDiscriminant,
    class: QrClass,
    points: Vec<(Tachygram, Fp)>,
}

impl QrSide {
    /// The discriminant $R$ of this side.
    #[must_use]
    pub const fn discriminant(&self) -> QrDiscriminant {
        self.discriminant
    }

    /// The class of this side.
    #[must_use]
    pub const fn class(&self) -> QrClass {
        self.class
    }

    /// The side's classifications, in the order the members were given.
    pub fn classifications(&self) -> impl ExactSizeIterator<Item = QrClassification> + '_ {
        self.points.iter().map(|&(value, root)| QrClassification {
            value,
            discriminant: self.discriminant,
            class: self.class,
            root,
        })
    }

    /// The side's members, in the order they were given.
    pub fn members(&self) -> impl ExactSizeIterator<Item = Tachygram> + '_ {
        self.points.iter().map(|&(value, _root)| value)
    }

    /// The side's set polynomial $q$.
    #[must_use]
    pub fn set_poly(&self) -> TachygramSetPoly {
        self.members().collect()
    }

    /// The class decomposition $(u, h)$ of this side, with $u$ interpolating
    /// its member and root pairs $(x, r)$.
    ///
    /// $$
    /// u(X)^2 - m \cdot (X + R) = q(X) \cdot h(X).
    /// $$
    ///
    /// [`QrSideSelect`](crate::stamp::proof::qr::QrSideSelect) commits the
    /// pair. [`QrSideDescend`](crate::stamp::proof::qr::QrSideDescend)
    /// checks the identity against the sibling's slot.
    ///
    /// Returns `None` when a member repeats.
    #[must_use]
    pub fn class_decomposition(&self) -> Option<(QrInterpolantPoly, QrQuotientPoly)> {
        let points = self
            .points
            .iter()
            .map(|&(value, root)| (Fp::from(value), root));
        qr::decomposition(points, self.class.multiplier(), self.discriminant.into()).map(
            |(interpolant, quotient)| (QrInterpolantPoly(interpolant), QrQuotientPoly(quotient)),
        )
    }
}

/// Witness polynomial interpolating one class's roots: $u(x_i) = y_i$ with
/// $y_i^2 = c \cdot (x_i + s)$ at that class's multiplier $c$ and offset $s$.
#[derive(AsRef, Clone, Debug, Into)]
pub struct QrInterpolantPoly(Polynomial<Fp, WalletRank>);

impl QrInterpolantPoly {
    /// Names this polynomial in a header that carries one.
    pub const SLOT: PolySlot<Self> = PolySlot::new();

    /// Deterministic (untrapdoored) commitment to the interpolant.
    #[must_use]
    pub fn commit(&self) -> QrInterpolantCommit {
        QrInterpolantCommit(
            self.0
                .commit(Pasta::host_generators(pasta::baked()))
                .to_affine(),
        )
    }
}

/// Pedersen commitment to a class interpolant.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrInterpolantCommit(EqAffine);

/// Witness polynomial for one class decomposition's quotient: $h$ in $u^2 -
/// c \cdot (X + s) = q \cdot h$.
#[derive(AsRef, Clone, Debug, Into)]
pub struct QrQuotientPoly(Polynomial<Fp, WalletRank>);

impl QrQuotientPoly {
    /// Names this polynomial in a header that carries one.
    pub const SLOT: PolySlot<Self> = PolySlot::new();

    /// Wraps an arbitrary polynomial, skipping the decomposition, to exercise
    /// step inputs.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub const fn arbitrary(poly: Polynomial<Fp, WalletRank>) -> Self {
        Self(poly)
    }

    /// Deterministic (untrapdoored) commitment to the quotient.
    #[must_use]
    pub fn commit(&self) -> QrQuotientCommit {
        QrQuotientCommit(
            self.0
                .commit(Pasta::host_generators(pasta::baked()))
                .to_affine(),
        )
    }
}

/// Pedersen commitment to a class-decomposition quotient.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrQuotientCommit(EqAffine);

/// A QR profile: the number of splits taken and the side taken at each.
///
/// A profile descends at most [`MAX_DEPTH`](Self::MAX_DEPTH) times; within
/// that bound two paths never share an encoding.
#[derive(Clone, Copy, Debug, Ord, PartialEq, PartialOrd, TotalEq)]
pub struct QrProfile {
    /// The number of splits taken.
    pub depth: u32,
    /// The side taken at each split, outermost first from the high end.
    pub bits: u32,
}

impl QrProfile {
    /// The greatest depth a profile reaches, and the number of discriminants a
    /// value is classified at.
    #[expect(clippy::as_conversions, reason = "constant value")]
    pub const MAX_DEPTH: usize = u32::BITS as usize;
    /// The depth-zero profile.
    pub const ROOT: Self = Self { depth: 0, bits: 0 };

    /// The child profile of `class`.
    ///
    /// # Panics
    ///
    /// Panics at depth [`MAX_DEPTH`](Self::MAX_DEPTH).
    #[must_use]
    pub fn descend(self, class: QrClass) -> Self {
        assert!(
            self.depth < u32::BITS,
            "profile has no bit left for another side"
        );
        Self {
            depth: self.depth + 1,
            bits: (self.bits << 1) | u32::from(class.bit()),
        }
    }

    /// The positions below this profile's depth: `depth` leading ones, then
    /// zeros.
    ///
    /// # Panics
    ///
    /// Panics when `depth` exceeds [`MAX_DEPTH`](Self::MAX_DEPTH).
    #[must_use]
    pub fn depth_mask(self) -> [bool; Self::MAX_DEPTH] {
        assert!(self.depth <= u32::BITS, "depth out of range");
        array::from_fn(|position| {
            u32::try_from(position).is_ok_and(|selected| selected < self.depth)
        })
    }
}

/// A value classified at a discriminant: a solution of the equation
/// $r^2 = m \cdot (x + R)$, with $x + R \neq 0$ when $m = c$.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct QrClassification {
    value: Tachygram,
    discriminant: QrDiscriminant,
    class: QrClass,
    root: Fp,
}

impl QrClassification {
    /// The classified value $x$.
    #[must_use]
    pub const fn value(&self) -> Tachygram {
        self.value
    }

    /// The discriminant $R$.
    #[must_use]
    pub const fn discriminant(&self) -> QrDiscriminant {
        self.discriminant
    }

    /// The class of the value at this discriminant.
    #[must_use]
    pub const fn class(&self) -> QrClass {
        self.class
    }

    /// The root $r$.
    #[must_use]
    pub const fn root(&self) -> Fp {
        self.root
    }

    /// The class and root a step is given for this classification.
    #[must_use]
    pub const fn claim(&self) -> QrClassClaim {
        QrClassClaim {
            class: self.class,
            root: self.root,
        }
    }
}

/// A prover's unchecked claim of a value's class and root at a discriminant.
/// The step supplies $x$ and $R$ and checks $r^2 = m \cdot (x + R)$.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub struct QrClassClaim {
    /// The claimed class, which determines $m$.
    pub class: QrClass,
    /// The claimed root $r$.
    pub root: Fp,
}

#[cfg(test)]
mod tests;
