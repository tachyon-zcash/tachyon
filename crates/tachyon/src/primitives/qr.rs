use core::array;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu::Polynomial;

use super::Anchor;
use crate::{collections::qr, digest::poseidon};

/// One depth's discriminant $R_j$, with $R_1 = H(\mathsf{boundary})$ and
/// $R_{j+1} = R_j + 1$. Every discriminant postdates the epoch's tachygrams.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrDiscriminant(pub Fp);

impl QrDiscriminant {
    /// The epoch's first discriminant, seeded on the boundary anchor that
    /// closes the epoch.
    #[must_use]
    pub fn of(boundary: Anchor) -> Self {
        Self(poseidon::qr_discriminant(Fp::from(boundary)))
    }

    /// The next depth's discriminant.
    #[must_use]
    pub fn next(self) -> Self {
        Self(self.0 + Fp::ONE)
    }
}

/// Witness polynomial interpolating one class's roots: $g(x_i) = y_i$ with
/// $y_i^2 = c\,(x_i + s)$ at that class's multiplier $c$ and shift $s$.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct QrInterpolantPoly(Polynomial);

impl QrInterpolantPoly {
    /// Deterministic (untrapdoored) commitment to the interpolant.
    #[must_use]
    pub fn commit(&self) -> QrInterpolantCommit {
        QrInterpolantCommit(self.0.commit())
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

/// Witness polynomial for one class decomposition's quotient: $h$ in $g^2 -
/// c\,(X + s) = q\,h$.
#[derive(AsRef, Clone, Debug, From, Into)]
pub struct QrQuotientPoly(Polynomial);

impl QrQuotientPoly {
    /// Deterministic (untrapdoored) commitment to the quotient.
    #[must_use]
    pub fn commit(&self) -> QrQuotientCommit {
        QrQuotientCommit(self.0.commit())
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
#[derive(Clone, Copy, Debug, PartialEq, TotalEq, PartialOrd, Ord)]
pub struct QrProfile {
    /// The number of splits taken.
    pub depth: u32,
    /// The side taken at each split, outermost first from the high end.
    pub bits: u32,
}

impl QrProfile {
    #[expect(clippy::as_conversions, reason = "constant value")]
    /// The greatest depth a profile reaches, and the number of discriminants a
    /// value is classified at.
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
}

/// A value's side and square root at each of an epoch's discriminants, in
/// depth order: `(true, r)` with $r^2 = x + R_j$, or `(false, r)` with $r^2 =
/// c\,(x + R_j)$.
#[derive(Clone, Copy, Debug, From, Into)]
pub struct QrClassRoots(pub [(bool, Fp); QrProfile::MAX_DEPTH]);

impl QrClassRoots {
    /// Classify `value` at every discriminant of the epoch closed by
    /// `boundary`.
    #[must_use]
    pub fn of(value: Fp, boundary: Anchor) -> Self {
        let mut discriminant = QrDiscriminant::of(boundary);
        Self(array::from_fn(|_| {
            let class = qr::classify(value, Fp::from(discriminant));
            discriminant = discriminant.next();
            class
        }))
    }
}

/// The positions below a profile's depth: `depth` leading ones, then zeros.
#[derive(Clone, Copy, Debug, From, Into)]
pub struct QrDepthMask(pub [bool; QrProfile::MAX_DEPTH]);

impl QrDepthMask {
    /// The mask selecting the first `depth` positions.
    ///
    /// # Panics
    ///
    /// Panics when `depth` exceeds [`QrProfile::MAX_DEPTH`].
    #[must_use]
    pub fn of(depth: u32) -> Self {
        assert!(depth <= u32::BITS, "depth out of range");
        Self(array::from_fn(|position| {
            u32::try_from(position).is_ok_and(|selected| selected < depth)
        }))
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
        let boundary = Anchor::from(Fp::from(7));
        let first = QrDiscriminant::of(boundary);
        assert_eq!(first, QrDiscriminant::of(boundary));
        assert_eq!(first.next().0, first.0 + Fp::ONE);
        assert_eq!(QrDiscriminant(-Fp::ONE).next().0, Fp::ZERO);
    }

    #[test]
    fn class_roots_square_to_the_shifted_value() {
        let boundary = Anchor::from(Fp::from(11));
        for value in [Fp::from(3), Fp::from(1_000_003), -Fp::from(9)] {
            let QrClassRoots(classes) = QrClassRoots::of(value, boundary);
            let mut discriminant = QrDiscriminant::of(boundary);
            for (side, root) in classes {
                let shifted = value + Fp::from(discriminant);
                assert_eq!(root.square(), qr::class_multiplier(side) * shifted);
                discriminant = discriminant.next();
            }
        }
    }

    #[test]
    fn the_fixed_point_takes_the_residue_side_with_root_zero() {
        let boundary = Anchor::from(Fp::from(13));
        let position = 5;
        let value = -(Fp::from(QrDiscriminant::of(boundary)) + Fp::from(position));
        let QrClassRoots(classes) = QrClassRoots::of(value, boundary);
        assert_eq!(
            classes[usize::try_from(position).unwrap()],
            (true, Fp::ZERO)
        );
    }

    #[test]
    fn the_depth_mask_is_a_prefix_of_the_depth() {
        for depth in [0, 1, 31, 32] {
            let QrDepthMask(mask) = QrDepthMask::of(depth);
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
        let _mask = QrDepthMask::of(u32::BITS + 1);
    }

    #[test]
    #[should_panic(expected = "depth out of range")]
    fn a_depth_mask_at_the_integer_limit_panics() {
        let _mask = QrDepthMask::of(u32::MAX);
    }
}
