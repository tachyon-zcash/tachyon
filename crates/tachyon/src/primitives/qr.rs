use core::array;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu_arithmetic::Cycle as _;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_pasta::Pasta;

use super::Anchor;
use crate::collections::qr;

/// An epoch's first discriminant $R_1$: the closing boundary anchor
/// $H_\mathsf{ep}(\mathsf{anchor\_last}, \mathsf{epoch} + 1)$ that the
/// epoch's terminal anchor ticks to, pinned at `QrBucketSeal`.
///
/// Depth $j$ classifies at $R_{j+1} = R_1 + j$.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrDiscriminant(pub Fp);

impl From<Anchor> for QrDiscriminant {
    fn from(anchor: Anchor) -> Self {
        Self(anchor.0)
    }
}

impl QrDiscriminant {
    /// The discriminant a split at `depth` classifies at.
    #[must_use]
    pub fn at(self, depth: u32) -> Fp {
        self.0 + Fp::from(u64::from(depth))
    }
}

/// Witness polynomial interpolating one class's roots: $u(x_i) = y_i$ with
/// $y_i^2 = c\,(x_i + s)$ at that class's multiplier $c$ and shift $s$.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct QrInterpolantPoly(Polynomial<Fp, ProductionRank>);

impl QrInterpolantPoly {
    /// Deterministic (untrapdoored) commitment to the interpolant.
    #[must_use]
    pub fn commit(&self) -> QrInterpolantCommit {
        QrInterpolantCommit(self.0.commit(Pasta::host_generators(Pasta::baked())))
    }

    /// Evaluate the interpolant at a given point.
    #[must_use]
    pub fn eval(&self, at: Fp) -> Fp {
        self.0.eval(at)
    }
}

/// Pedersen commitment to a class interpolant.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrInterpolantCommit(Eq);

/// Witness polynomial for one class decomposition's quotient: $h$ in $u^2 -
/// c\,(X + s) = q\,h$.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct QrQuotientPoly(Polynomial<Fp, ProductionRank>);

impl QrQuotientPoly {
    /// Deterministic (untrapdoored) commitment to the quotient.
    #[must_use]
    pub fn commit(&self) -> QrQuotientCommit {
        QrQuotientCommit(self.0.commit(Pasta::host_generators(Pasta::baked())))
    }

    /// Evaluate the quotient at a given point.
    #[must_use]
    pub fn eval(&self, at: Fp) -> Fp {
        self.0.eval(at)
    }
}

/// Pedersen commitment to a class-decomposition quotient.
#[derive(AsRef, Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrQuotientCommit(Eq);

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
/// $r^2 = s$, or `(false, r)` with $r^2 = c\,s$, for $s$ the shifted value.
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
mod tests {
    use super::*;

    #[test]
    fn the_root_profile_has_no_bits() {
        assert_eq!(QrProfile::ROOT.depth, 0);
        assert_eq!(QrProfile::ROOT.bits, 0);
    }

    #[test]
    fn the_bits_record_the_splits_outermost_first() {
        let low = QrProfile::ROOT.descend(false).descend(false).descend(true);
        assert_eq!(low.depth, 3);
        assert_eq!(low.bits, 0b001);
        let high = QrProfile::ROOT.descend(true).descend(false).descend(false);
        assert_eq!(high.bits, 0b100);
    }

    #[test]
    fn distinct_split_histories_yield_distinct_profiles() {
        let deep_zeroes = QrProfile::ROOT.descend(false).descend(false);
        let shallow_zero = QrProfile::ROOT.descend(false);
        assert_ne!(deep_zeroes, shallow_zero);
        assert_ne!(deep_zeroes, QrProfile::ROOT);
    }

    #[test]
    #[should_panic(expected = "profile has no bit left for another side")]
    fn descending_past_the_maximum_depth_panics() {
        let mut profile = QrProfile::ROOT;
        for _ in 0..=QrProfile::MAX_DEPTH {
            profile = profile.descend(true);
        }
    }

    #[test]
    fn the_profile_reaches_the_maximum_depth() {
        let mut profile = QrProfile::ROOT;
        for _ in 0..QrProfile::MAX_DEPTH {
            profile = profile.descend(true);
        }
        assert_eq!(profile.depth, u32::BITS);
        assert_eq!(profile.bits, u32::MAX);
    }

    #[test]
    fn the_discriminants_progress_by_one() {
        let first = QrDiscriminant::from(Fp::from(7));
        assert_eq!(first.at(0), Fp::from(7));
        assert_eq!(first.at(1), Fp::from(8));
        assert_eq!(first.at(u32::BITS), Fp::from(7 + 32));
        assert_eq!(QrDiscriminant::from(-Fp::ONE).at(1), Fp::ZERO);
    }

    #[test]
    fn class_roots_square_to_the_shifted_value() {
        let discriminant = QrDiscriminant::from(Fp::from(11));
        for value in [Fp::from(3), Fp::from(1_000_003), -Fp::from(9)] {
            for (depth, QrClassRoot(side, root)) in
                (0..).zip(QrClassRoot::along(value, discriminant))
            {
                let shifted = value + discriminant.at(depth);
                assert_eq!(root.square(), qr::class_multiplier(side) * shifted);
            }
        }
    }

    #[test]
    fn the_fixed_point_takes_the_residue_side_with_root_zero() {
        let discriminant = QrDiscriminant::from(Fp::from(13));
        let position = 5;
        let value = -discriminant.at(position);
        let classes = QrClassRoot::along(value, discriminant);
        assert_eq!(
            classes[usize::try_from(position).unwrap()],
            QrClassRoot(true, Fp::ZERO)
        );
    }

    #[test]
    fn the_depth_mask_is_a_prefix_of_the_depth() {
        for depth in [0, 1, 31, 32] {
            let mask = QrProfile { depth, bits: 0 }.depth_mask();
            let ones = mask.iter().filter(|&&selected| selected).count();
            assert_eq!(ones, usize::try_from(depth).unwrap());
            assert!(
                mask.iter()
                    .zip(mask.iter().skip(1))
                    .all(|(&earlier, &later)| earlier || !later)
            );
        }
    }

    #[test]
    #[should_panic(expected = "depth out of range")]
    fn a_depth_mask_past_the_maximum_depth_panics() {
        let _mask = QrProfile {
            depth: u32::BITS + 1,
            bits: 0,
        }
        .depth_mask();
    }

    #[test]
    #[should_panic(expected = "depth out of range")]
    fn a_depth_mask_at_the_integer_limit_panics() {
        let _mask = QrProfile {
            depth: u32::MAX,
            bits: 0,
        }
        .depth_mask();
    }
}
