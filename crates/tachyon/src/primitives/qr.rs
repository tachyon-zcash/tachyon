use alloc::vec::Vec;
use core::array;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu::{
    Cycle as _, Polynomial, WalletRank,
    pasta::Pasta,
    udon::{curve::Projective as _, field::Field as _},
};
use rand_core::CryptoRng;

use super::{PolySlot, Tachygram};
use crate::{
    collections::qr,
    pasta,
    pasta::{EqAffine, Fp},
};

/// The class of a value $x$ at a discriminant $R$.
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
    pub(crate) const fn multiplier(self) -> Fp {
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

/// A QR discriminant $R$. A value $x$ takes the residue side at $R$ iff
/// $x + R$ is a square or zero. A network's headers carry its first
/// discriminant $R_0$; depth $j$ classifies at `R_0.at(j)`.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrDiscriminant(Fp);

impl QrDiscriminant {
    /// Sample a uniformly random first discriminant.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(|bytes| rng.fill_bytes(bytes)))
    }

    /// This discriminant plus `depth`: $R_j$ from $R_0$.
    #[must_use]
    pub fn at(self, depth: u32) -> Self {
        Self(self.0 + Fp::from(u64::from(depth)))
    }

    /// The class of `value` at this discriminant.
    #[must_use]
    pub fn class(self, value: Tachygram) -> QrClass {
        if (Fp::from(value) + self.0).sqrt().is_some() {
            QrClass::Residue
        } else {
            QrClass::NonResidue
        }
    }

    /// The class root of `value` at this discriminant.
    ///
    /// # Panics
    ///
    /// Panics if neither branch has a root, which is impossible in this field.
    #[must_use]
    pub fn class_root(self, value: Tachygram) -> QrClassRoot {
        let shifted = Fp::from(value) + self.0;
        if let Some(root) = shifted.sqrt() {
            return QrClassRoot::Residue(root);
        }
        let root = (qr::QUADRATIC_NON_RESIDUE * shifted).sqrt();
        #[expect(
            clippy::expect_used,
            reason = "multiplying a non-square by the non-residue gives a square"
        )]
        QrClassRoot::NonResidue(root.expect("non-residue branch has a root"))
    }

    /// Split `members` at this discriminant into `(non_residue, residue)`.
    /// Each list retains its input order and any repeats.
    #[must_use]
    pub fn split(self, members: &[Tachygram]) -> (Vec<Tachygram>, Vec<Tachygram>) {
        members
            .iter()
            .copied()
            .partition(|&member| self.class(member) == QrClass::NonResidue)
    }

    /// The class decomposition $(u, h)$ of `members` at this discriminant.
    /// With the set polynomial $q$ and class multiplier $m$,
    ///
    /// $$
    /// u(X)^2 - m \cdot (X + R) = q(X) \cdot h(X).
    /// $$
    ///
    /// [`QrSideSelect`](crate::stamp::proof::qr::QrSideSelect) commits the
    /// pair. [`QrSideDescend`](crate::stamp::proof::qr::QrSideDescend)
    /// checks the identity against the sibling's slot.
    ///
    /// Returns `None` if a member is of the other class or is repeated.
    #[must_use]
    pub fn class_decomposition(
        self,
        class: QrClass,
        members: &[Tachygram],
    ) -> Option<(QrInterpolantPoly, QrQuotientPoly)> {
        let multiplier = class.multiplier();
        let points = members
            .iter()
            .map(|&member| {
                let value = Fp::from(member);
                let shifted = value + self.0;
                let root = match class {
                    QrClass::NonResidue if shifted == Fp::ZERO => return None,
                    QrClass::NonResidue => (multiplier * shifted).sqrt(),
                    QrClass::Residue => shifted.sqrt(),
                }?;
                Some((value, root))
            })
            .collect::<Option<Vec<_>>>()?;
        qr::decomposition(points, multiplier, self.0).map(|(interpolant, quotient)| {
            (QrInterpolantPoly(interpolant), QrQuotientPoly(quotient))
        })
    }

    /// The profile `value` takes through `depth` splits, with this as the
    /// first discriminant.
    ///
    /// # Panics
    ///
    /// Panics if `depth` exceeds [`QrProfile::MAX_DEPTH`].
    #[must_use]
    pub fn profile(self, value: Tachygram, depth: u32) -> QrProfile {
        (0..depth).fold(QrProfile::ROOT, |profile, level| {
            profile.descend(self.at(level).class(value))
        })
    }

    /// The class root of `value` at each depth, with this as the first
    /// discriminant.
    #[must_use]
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "array indices are below QrProfile::MAX_DEPTH"
    )]
    pub fn class_roots(self, value: Tachygram) -> [QrClassRoot; QrProfile::MAX_DEPTH] {
        array::from_fn(|level| self.at(level as u32).class_root(value))
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

/// A class root of a value $x$ at a discriminant $R$.
#[derive(Clone, Copy, Debug, PartialEq, TotalEq)]
pub enum QrClassRoot {
    /// $r$ with $r^2 = c \cdot (x + R)$ for $x + R \neq 0$.
    NonResidue(Fp),
    /// $r$ with $r^2 = x + R$.
    Residue(Fp),
}

impl QrClassRoot {
    /// The class this root attests.
    #[must_use]
    pub const fn class(self) -> QrClass {
        match self {
            Self::NonResidue(_) => QrClass::NonResidue,
            Self::Residue(_) => QrClass::Residue,
        }
    }

    /// The root $r$.
    #[must_use]
    pub const fn root(self) -> Fp {
        match self {
            Self::NonResidue(root) | Self::Residue(root) => root,
        }
    }
}

#[cfg(test)]
mod tests;
