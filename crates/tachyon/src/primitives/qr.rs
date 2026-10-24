use core::array;

use derive_more::{AsRef, Debug, Eq as TotalEq, From, Into, PartialEq};
use ff::Field as _;
use pasta_curves::{Eq, Fp};
use ragu_arithmetic::Cycle as _;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_pasta::Pasta;

use crate::collections::qr;

/// A routing network's first discriminant $R_0$.
///
/// Prover-chosen and sampled privately, so a network can be routed while its
/// epoch is still in flight. It is threaded unchanged from the root intake and
/// required equal across `QrIntakeMerge`, so one network classifies at one
/// progression throughout. No step checks it, and every descent absorbs it
/// into its challenge. It moves how members distribute
/// across buckets, never which bucket holds a given value under it, so a
/// biased or prematurely revealed choice affects only that builder's buckets,
/// and a wallet can use any valid network.
///
/// Depth $j$ classifies at $R_j = R_0 + j$.
#[derive(Clone, Copy, Debug, From, Into, PartialEq, TotalEq)]
pub struct QrDiscriminant(pub Fp);

impl QrDiscriminant {
    /// The discriminant a split at `depth` classifies at.
    #[must_use]
    pub fn at(self, depth: u32) -> Fp {
        self.0 + Fp::from(u64::from(depth))
    }
}

/// Witness polynomial interpolating one class's roots: $u(x_i) = y_i$ with
/// $y_i^2 = c \cdot (x_i + s)$ at that class's multiplier $c$ and shift $s$.
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
/// c \cdot (X + s) = q \cdot h$.
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
/// $r^2 = s$, or `(false, r)` with $r^2 = c \cdot s$, for $s$ the shifted
/// value.
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
    use alloc::vec::Vec;

    use proptest::{option, prelude::*};
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::testing::check;

    /// The profile reached by taking `path`'s sides from the root.
    fn profile_of(path: &[bool]) -> QrProfile {
        path.iter()
            .fold(QrProfile::ROOT, |profile, &side| profile.descend(side))
    }

    /// Along the progression, each root squares to its side's class times
    /// the value shifted by that depth's discriminant, and the value that
    /// cancels a discriminant takes the residue side with root zero there.
    #[test]
    fn class_roots_square_to_the_shifted_value() {
        let strategy = (any::<u64>(), option::of(0..u32::BITS));
        check(256, strategy, |(seed, fixed_point)| {
            let rng = &mut StdRng::seed_from_u64(seed);
            let discriminant = QrDiscriminant::from(Fp::random(&mut *rng));
            let value = fixed_point.map_or_else(
                || Fp::random(&mut *rng),
                |position| -discriminant.at(position),
            );
            let classes = QrClassRoot::along(value, discriminant);
            for (depth, &QrClassRoot(side, root)) in (0..).zip(&classes) {
                prop_assert_eq!(
                    root.square(),
                    qr::class_multiplier(side) * (value + discriminant.at(depth))
                );
            }
            if let Some(position) = fixed_point {
                prop_assert_eq!(
                    classes[usize::try_from(position).unwrap()],
                    QrClassRoot(true, Fp::ZERO)
                );
            }
            Ok(())
        });
    }

    #[test]
    fn the_depth_mask_is_a_prefix_of_the_depth() {
        check(256, (0..=u32::BITS, any::<u32>()), |(depth, bits)| {
            let mask = QrProfile { depth, bits }.depth_mask();
            let selected: Vec<usize> = (0..)
                .zip(mask)
                .filter(|&(_, on)| on)
                .map(|(position, _)| position)
                .collect();
            prop_assert_eq!(
                selected,
                (0..usize::try_from(depth).unwrap()).collect::<Vec<_>>()
            );
            Ok(())
        });
    }

    #[test]
    #[should_panic(expected = "profile has no bit left for another side")]
    fn descending_past_the_maximum_depth_panics() {
        let _profile = profile_of(&[true; QrProfile::MAX_DEPTH + 1]);
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
}
