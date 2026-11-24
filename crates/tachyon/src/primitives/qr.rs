use alloc::vec::Vec;
use core::array;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu::{
    Cycle as _, Polynomial, Rank as _, WalletRank,
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
    /// The other class.
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

/// A QR discriminant $R$: a term of the class equation
/// $r^2 = m \cdot (x + R)$. Discriminants progress by one. A network samples
/// a first discriminant $R_0$ and splits at depth $j$ under $R_0 + j$.
///
/// # Choosing the first discriminant
///
/// The builder chooses $R_0$. No step proves that it is random, secret, or
/// selected by the chain. Keeping it private until the epoch closes is a
/// load-balancing policy. A biased or early-revealed choice affects that
/// builder's buckets.
///
/// A seed fixes its own $R_0$. Routing headers carry it unchanged. A merge
/// requires equal first discriminants on its inputs, and a descent requires
/// equality between the split and the selection. Reopening an evidence leaf
/// binds the same $R_0$.
///
/// A descent's challenge binds both input headers, their online commitments,
/// and the staged child bit. The step computes $R = R_0 + \mathsf{depth}$
/// from the header. It neither hashes nor stages $R$ separately, and the
/// challenge does not absorb the output header. The seal copies $R_0$;
/// its free witness is `anchor_final_prev`.
///
/// # Injectivity
///
/// Together with a depth-$d$ [`QrProfile`], $R_0$ determines one value class,
/// and every value belongs to one class at each depth. Adding $j$ in the field
/// gives each element a [side](crate::collections::qr#sides) at $R_0 + j$, and
/// a profile's class holds the values matching its first $d$ sides. Any field
/// element serves as $R_0$. Intake seeds witness $R_0$ via `Step::Witness`,
/// later routing steps copy it or equate two inputs' copies, and query steps
/// that test a value's class use their bucket's $R_0$.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrDiscriminant(Fp);

impl QrDiscriminant {
    /// Sample a uniformly random discriminant.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(|bytes| rng.fill_bytes(bytes)))
    }

    /// The discriminant $R + \mathsf{depth}$, counting `depth` from this
    /// discriminant.
    #[must_use]
    pub fn at(self, depth: u32) -> Self {
        Self(self.0 + Fp::from(u64::from(depth)))
    }

    /// `value`'s class path from this discriminant, with the class root at
    /// each step.
    #[must_use]
    pub(crate) fn classify_path(
        self,
        value: Tachygram,
    ) -> (
        [QrClass; QrProfile::MAX_DEPTH],
        [QrClassRoot; QrProfile::MAX_DEPTH],
    ) {
        let mut discriminant = self;
        let mut path = [QrClass::NonResidue; QrProfile::MAX_DEPTH];
        let mut roots = [QrClassRoot(Fp::ZERO); QrProfile::MAX_DEPTH];
        for (class, root) in path.iter_mut().zip(&mut roots) {
            (*class, *root) = discriminant.classify(value);
            discriminant = discriminant.at(1);
        }
        (path, roots)
    }

    /// Classify `value` at this discriminant by solving the class equation
    /// for the multiplier $m$ and root $r$.
    ///
    /// # Panics
    ///
    /// Panics if neither branch has a root, which is impossible in this field.
    #[must_use]
    pub fn classify(self, value: Tachygram) -> (QrClass, QrClassRoot) {
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
        (class, QrClassRoot(root))
    }

    /// Split `members` at this discriminant, retaining order and repeats
    /// within each class.
    #[must_use]
    pub fn split(self, members: &[Tachygram]) -> QrSplit {
        let mut split = QrSplit {
            discriminant: self,
            non_residue: Vec::new(),
            residue: Vec::new(),
        };
        for &member in members {
            let (class, root) = self.classify(member);
            let side = match class {
                QrClass::NonResidue => &mut split.non_residue,
                QrClass::Residue => &mut split.residue,
            };
            side.push((member, root));
        }
        split
    }
}

/// A set split at one discriminant: its members of each class, with their
/// class roots.
#[derive(Debug)]
pub struct QrSplit {
    discriminant: QrDiscriminant,
    non_residue: Vec<(Tachygram, QrClassRoot)>,
    residue: Vec<(Tachygram, QrClassRoot)>,
}

impl QrSplit {
    /// The members of `class`, in the order they were given.
    /// These members form the child's set for the next split. The factors
    /// are polynomials and do not give back the member list.
    pub fn members(&self, class: QrClass) -> impl ExactSizeIterator<Item = Tachygram> + '_ {
        let points = match class {
            QrClass::NonResidue => &self.non_residue,
            QrClass::Residue => &self.residue,
        };
        points.iter().map(|&(value, _root)| value)
    }

    /// The two sides' set polynomials, `(non_residue, residue)`.
    ///
    /// # Panics
    ///
    /// Panics if either side has at least `WalletRank::num_coeffs()` members:
    /// its monic set polynomial needs one more coefficient than members.
    #[must_use]
    pub fn factors(&self) -> (TachygramSetPoly, TachygramSetPoly) {
        let non_residue = self.members(QrClass::NonResidue);
        let residue = self.members(QrClass::Residue);
        assert!(
            non_residue.len() < WalletRank::num_coeffs()
                && residue.len() < WalletRank::num_coeffs(),
            "side's set polynomial exceeds WalletRank"
        );
        (non_residue.collect(), residue.collect())
    }

    /// The class decomposition $(u, h)$ of the side of `class`, with $u$
    /// interpolating its member and root pairs $(x, r)$.
    ///
    /// $$
    /// u(X)^2 - m \cdot (X + R) = q(X) \cdot h(X).
    /// $$
    ///
    /// [`QrSideSelect`](crate::stamp::proof::qr::QrSideSelect) commits the
    /// pair. [`QrSideDescend`](crate::stamp::proof::qr::QrSideDescend)
    /// checks the identity against the sibling's slot.
    ///
    /// Returns `None` when a member repeats or the side has more than
    /// `WalletRank::num_coeffs()` members.
    ///
    /// At exactly `WalletRank::num_coeffs()` distinct members, the hints
    /// still fit, but the monic set polynomial needs one more coefficient.
    /// The decomposition uses that polynomial as a temporary divisor and
    /// does not commit it. A committed intake cannot hold a side that large.
    #[must_use]
    pub fn class_decomposition(
        &self,
        class: QrClass,
    ) -> Option<(QrInterpolantPoly, QrQuotientPoly)> {
        let points = match class {
            QrClass::NonResidue => &self.non_residue,
            QrClass::Residue => &self.residue,
        };
        if points.len() > WalletRank::num_coeffs() {
            return None;
        }
        let field_points = points
            .iter()
            .map(|&(value, root)| (Fp::from(value), Fp::from(root)));
        qr::decomposition(field_points, class.multiplier(), self.discriminant.into()).map(
            |(interpolant, quotient)| (QrInterpolantPoly(interpolant), QrQuotientPoly(quotient)),
        )
    }
}

/// Witness polynomial interpolating the class roots $u(x_i) = r_i$, where
/// $r_i^2 = m \cdot (x_i + R)$ at multiplier $m$ and discriminant $R$.
///
/// No step checks how the hint was built. What the
/// [class decomposition](crate::collections::qr#class-decomposition) proves
/// does not depend on how $u$ was built.
#[derive(AsRef, Clone, Debug, From, Into)]
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

/// Witness polynomial for the class decomposition quotient $h$ in
/// $u(X)^2 - m \cdot (X + R) = q(X) \cdot h(X)$.
///
/// As with [`QrInterpolantPoly`], descent checks the class identity, not how
/// the hint was built.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct QrQuotientPoly(Polynomial<Fp, WalletRank>);

impl QrQuotientPoly {
    /// Names this polynomial in a header that carries one.
    pub const SLOT: PolySlot<Self> = PolySlot::new();

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
/// # Injectivity
///
/// Within bounds, `(depth, bits)` determines a path $b_0, \dots, b_{d-1}$ of
/// sides at depths $0$ to $d - 1$, where $b_j = 1$ marks the residue side.
/// `depth` holds $d \leq$ [`MAX_DEPTH`](Self::MAX_DEPTH), and `bits` packs
/// $\sum_{j < d} b_j \cdot 2^{d - 1 - j} < 2^d$. Same-length paths differ in
/// `bits` and different-length paths differ in `depth`. Leading non-residue
/// sides pack as zeros, so `bits` alone does not fix the path.
///
/// The native fields accept any pair of `u32`s; out-of-bounds pairs represent
/// no path. In circuits, `descend` extends a path into a path, and
/// `enforce_sides_of` accepts only paths.
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

/// A class root $r$ in the class equation $r^2 = m \cdot (x + R)$.
/// It carries no class and is distinct from a root $x$ of a set polynomial.
///
/// A class root [shows the side](crate::collections::qr#sides) except that
/// when $x + R = 0$, root zero satisfies either multiplier. The separate
/// nonzero check for the non-residue side leaves only the residue side there.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrClassRoot(Fp);

#[cfg(test)]
mod tests;
