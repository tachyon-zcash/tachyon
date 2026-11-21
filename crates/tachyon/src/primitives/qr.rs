use core::array;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ragu::{
    Cycle as _, Polynomial, WalletRank,
    pasta::Pasta,
    udon::{curve::Projective as _, field::Field as _},
};
use rand_core::CryptoRng;

use super::PolySlot;
use crate::{
    collections::qr,
    pasta,
    pasta::{EqAffine, Fp},
};

/// A routing network's first discriminant $R_0$.
///
/// Depth $j$ classifies at $R_j = R_0 + j$, a sum in the field. The builder of
/// a network chooses $R_0$ and can sample it privately, so a network can be
/// routed while its epoch is still in flight.
///
/// # Injectivity
///
/// $R_0$ stands for a rule that gives every field element a
/// [side](crate::collections::qr#sides) at every depth. Write
/// $\mathsf{side}_j(x)$ for the side of $x$ at $R_j$. It is a function of
/// $x$, $R_0$ and $j$, so $R_0$ and a [`QrProfile`] of depth $d$ determine
/// one class of values, those $x$ whose $\mathsf{side}_0(x), \dots,
/// \mathsf{side}_{d-1}(x)$ are the profile's sides. A value is in one class of
/// each depth.
///
/// Every element is a valid $R_0$, and no step constrains the choice. A step
/// that starts an intake takes $R_0$ from its `Step::Witness`. Every later
/// step copies it from an input header or holds two inputs' copies equal, and
/// a step that tests a value classifies at the $R_0$ of the bucket it reads.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrDiscriminant(pub Fp);

impl QrDiscriminant {
    /// Sample a uniformly random first discriminant.
    pub fn random<RNG: CryptoRng>(rng: &mut RNG) -> Self {
        Self(Fp::random(|bytes| rng.fill_bytes(bytes)))
    }

    /// The discriminant a split at `depth` classifies at.
    #[must_use]
    pub fn at(self, depth: u32) -> Fp {
        self.0 + Fp::from(u64::from(depth))
    }
}

/// Witness polynomial interpolating one class's roots: $u(x_i) = y_i$ with
/// $y_i^2 = c \cdot (x_i + s)$ at that class's multiplier $c$ and shift $s$.
///
/// A hint. No step checks how it was built. `QrSideDescend` checks the
/// [class decomposition](crate::collections::qr#class-decomposition) it
/// enters with [`QrQuotientPoly`]. What that identity shows does not depend
/// on how the two hints were built.
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

/// Witness polynomial for one class decomposition's quotient: $h$ in $u^2 -
/// c \cdot (X + s) = q \cdot h$.
///
/// A hint, as [`QrInterpolantPoly`] is.
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
/// A profile stands for a path, the sides $b_0, \dots, b_{d-1}$ taken at
/// depths $0$ to $d - 1$, with $b_j = 1$ for the residue side. `depth` is $d$
/// and
///
/// $$
///   \mathsf{bits} = \sum_{j < d} b_j \cdot 2^{d - 1 - j}.
/// $$
///
/// A path has at most [`MAX_DEPTH`](Self::MAX_DEPTH) sides, so `bits` is an
/// integer below $2^d$ and the sum is its binary expansion. Two paths of one
/// length differ in `bits`, and two paths of different lengths differ in
/// `depth`. `bits` alone does not determine a path, because a path that starts
/// on the non-residue side has leading zeros.
///
/// The type holds any two integers. A profile with `depth` above
/// [`MAX_DEPTH`](Self::MAX_DEPTH), or with `bits` at or above $2^d$, is no
/// path. The circuit gadget's `descend` builds a path from a path, and its
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

    /// The child profile on side `bit`, the residue side when set.
    ///
    /// # Panics
    ///
    /// Panics at depth [`MAX_DEPTH`](Self::MAX_DEPTH).
    #[must_use]
    pub fn descend(self, bit: bool) -> Self {
        assert!(
            self.depth < u32::BITS,
            "profile has no bit left for another side"
        );
        Self {
            depth: self.depth + 1,
            bits: (self.bits << 1) | u32::from(bit),
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

/// A value's side and square root at one discriminant: `(true, r)` with
/// $r^2 = s$, or `(false, r)` with $r^2 = n \cdot s$, for $s$ the shifted
/// value and $n$ the
/// [non-residue](crate::collections::qr::QUADRATIC_NON_RESIDUE).
///
/// The root is what [shows the side](crate::collections::qr#sides) to a
/// circuit. A zero $s$ has the root zero and the residue side.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrClassRoot(pub bool, pub Fp);

impl QrClassRoot {
    /// Classify `value` at `discriminant`.
    #[must_use]
    pub fn of(value: Fp, discriminant: Fp) -> Self {
        qr::classify(value, discriminant).into()
    }

    /// Classify `value` at every discriminant of the progression from
    /// `discriminant`, in depth order.
    #[must_use]
    pub fn along(value: Fp, discriminant: QrDiscriminant) -> [Self; QrProfile::MAX_DEPTH] {
        let mut shifted = value + Fp::from(discriminant);
        array::from_fn(|_| {
            let class = Self::of(shifted, Fp::ZERO);
            shifted += Fp::ONE;
            class
        })
    }
}

#[cfg(test)]
mod tests;
