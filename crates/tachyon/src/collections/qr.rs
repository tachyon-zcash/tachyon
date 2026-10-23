//! # Quadratic-residue classification
//!
//! A value $x$ takes the residue side at a discriminant $R$ iff $x + R$ is a
//! square or zero, and the non-residue side otherwise. A root $y$ attests
//! either side: $y^2 = x + R$ on the residue side, $y^2 = n \cdot (x + R)$ for
//! a fixed non-residue $n$ on the other.
//!
//! ## Class decomposition
//!
//! With $q$ one side's values as roots and $u$ interpolating their roots
//! $y_i$, at that side's class multiplier $c$,
//!
//! $$
//!   u(X)^2 - c \cdot (X + R) = q(X) \cdot h(X),
//! $$
//!
//! so every root of $q$ takes that side. The exceptional value $-R$ has root
//! $0$ under either class; $q_\mathsf{non}(-R) \neq 0$ files it residue-side.
//!
//! The identity also reads over one value against many discriminants: with
//! the $R_j$ as the roots of $q$ and $x$ as the shift, $u(R_j)^2 = c(x +
//! R_j)$ at each.

extern crate alloc;

use alloc::vec::Vec;

use ff::Field as _;
use pasta_curves::Fp;
use ragu_arithmetic as arithmetic;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};

/// The least quadratic non-residue of the Pallas base field. Distinct from
/// the cubic non-residue the sequence encoding uses.
pub(crate) const QUADRATIC_NON_RESIDUE: Fp = Fp::from_raw([5, 0, 0, 0]);

/// The class multiplier $c$ of a side: $1$ on the residue side, the quadratic
/// non-residue otherwise.
pub(crate) const fn class_multiplier(side: bool) -> Fp {
    if side { Fp::ONE } else { QUADRATIC_NON_RESIDUE }
}

/// Classify $v$ at the discriminant $R$: the residue-side bit, set iff $v +
/// R$ is a square or zero, and a root with $\mathsf{root}^2 = c \cdot (v + R)$
/// at that side's [`class_multiplier`].
///
/// # Panics
///
/// Panics if neither character branch has a root. The character is
/// multiplicative and the multiplier is a non-residue, so exactly one branch
/// always does, and this is unreachable.
#[must_use]
pub fn classify(value: Fp, discriminant: Fp) -> (bool, Fp) {
    let shifted = value + discriminant;
    if let Some(root) = Option::<Fp>::from(shifted.sqrt()) {
        return (true, root);
    }
    // The character is multiplicative and n is a non-residue, so exactly
    // one of the two character branches has a root.
    let root = Option::<Fp>::from((QUADRATIC_NON_RESIDUE * shifted).sqrt());
    #[expect(
        clippy::expect_used,
        reason = "one of the two character branches always has a root"
    )]
    (false, root.expect("non-residue branch has a root"))
}

/// One side's points $(x_i, y_i)$, each $y_i$ the root of $x_i$ on that side.
pub(crate) type ClassificationPoints = Vec<(Fp, Fp)>;

/// Split values by side at `discriminant`, returning the residue-side then
/// the non-residue-side points.
#[must_use]
pub(crate) fn split(
    values: impl IntoIterator<Item = Fp>,
    discriminant: Fp,
) -> (ClassificationPoints, ClassificationPoints) {
    let mut residue = Vec::new();
    let mut non_residue = Vec::new();
    for value in values {
        let (bit, root) = classify(value, discriminant);
        if bit {
            residue.push((value, root));
        } else {
            non_residue.push((value, root));
        }
    }
    (residue, non_residue)
}

/// Divides `coeffs` by $(X - \mathsf{root})$ in place, exactly.
///
/// Returns `None` when the division leaves a remainder.
fn divide_by_root(coeffs: &mut Vec<Fp>, root: Fp) -> Option<()> {
    let mut carry = Fp::ZERO;
    for coeff in coeffs.iter_mut().rev() {
        let quotient_coeff = carry;
        carry = *coeff + (carry * root);
        *coeff = quotient_coeff;
    }
    // After the pass, `carry` is the remainder and the vector holds the
    // quotient with one trailing zero coefficient.
    (carry == Fp::ZERO).then(|| coeffs.pop())?;
    Some(())
}

/// Class decomposition $(u, h)$ of `points` at class multiplier $c$ and shift
/// $s$:
///
/// $$
///   u(X)^2 - c \cdot (X + s) = q(X) \cdot h(X),
/// $$
///
/// with $q$ the abscissas as roots and $u$ interpolating the points. An empty
/// side takes $u = 1$ and an all-zero side takes $u = q$, so neither
/// polynomial is zero.
///
/// Returns `None` when two abscissas coincide or a point lies off the side.
#[must_use]
pub(crate) fn decomposition(
    points: &[(Fp, Fp)],
    class: Fp,
    shift: Fp,
) -> Option<(
    Polynomial<Fp, ProductionRank>,
    Polynomial<Fp, ProductionRank>,
)> {
    let mut interpolant_coeffs = if points.is_empty() {
        [Fp::ONE].to_vec()
    } else {
        super::interpolate(points)?
    };
    if interpolant_coeffs.iter().all(|coeff| coeff == &Fp::ZERO) {
        let abscissas: Vec<Fp> = points.iter().map(|&(abscissa, _)| abscissa).collect();
        interpolant_coeffs = arithmetic::poly_with_roots(&abscissas);
    }

    let translate = [class * shift, class];
    let mut h_coeffs = Vec::new();
    arithmetic::poly_mul(&interpolant_coeffs, &interpolant_coeffs, &mut h_coeffs);
    if h_coeffs.len() < translate.len() {
        h_coeffs.resize(translate.len(), Fp::ZERO);
    }
    for (coeff, &translate_coeff) in h_coeffs.iter_mut().zip(&translate) {
        *coeff -= translate_coeff;
    }
    for &(abscissa, _) in points {
        divide_by_root(&mut h_coeffs, abscissa)?;
    }

    Some((
        Polynomial::from_coeffs(interpolant_coeffs),
        Polynomial::from_coeffs(h_coeffs),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::min_ident_chars, reason = "test code")]

    use core::iter;

    use ff::PrimeField as _;
    use proptest::prelude::*;
    use ragu_circuits::polynomials::Rank as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::{collections::multiset, testing::check};

    /// `count` random values and a discriminant, drawn from `seed`.
    fn values_at(seed: u64, count: usize) -> (Vec<Fp>, Fp) {
        let rng = &mut StdRng::seed_from_u64(seed);
        let discriminant = Fp::random(&mut *rng);
        let values = iter::repeat_with(|| Fp::random(&mut *rng))
            .take(count)
            .collect();
        (values, discriminant)
    }

    /// $(p - 1) / 2$ as `pow_vartime` limbs, computed from field constants.
    fn half_order() -> [u64; 4] {
        let half = -Fp::ONE * Fp::TWO_INV;
        let repr = half.to_repr();
        let mut limbs = [0u64; 4];
        for (limb, bytes) in limbs.iter_mut().zip(repr.as_ref().chunks(8)) {
            *limb = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        limbs
    }

    /// Euler-criterion quadratic character: $1$, $-1$, or $0$.
    fn chi(x: Fp) -> Fp {
        x.pow_vartime(half_order())
    }

    #[test]
    fn the_non_residue_constant_satisfies_the_euler_criterion() {
        assert_eq!(chi(QUADRATIC_NON_RESIDUE), -Fp::ONE);
    }

    #[test]
    fn small_cubic_non_residues_are_quadratic_residues() {
        assert_eq!(chi(Fp::from(2)), Fp::ONE);
        assert_eq!(chi(Fp::from(3)), Fp::ONE);
    }

    /// The side is the Euler criterion of $x + R$, and the root squares to
    /// that side's class times $x + R$, and to nothing on the other side
    /// unless $x = -R$, which takes the residue side with root zero.
    #[test]
    fn classification_matches_the_euler_criterion() {
        check(256, any::<u64>(), |seed| {
            let (values, discriminant) = values_at(seed, 1);
            let x = values[0];
            let (bit, root) = classify(x, discriminant);
            prop_assert_eq!(bit, chi(x + discriminant) != -Fp::ONE);
            prop_assert_eq!(root.square(), class_multiplier(bit) * (x + discriminant));
            let opposite = class_multiplier(!bit) * (x + discriminant);
            prop_assert!(
                Option::<Fp>::from(opposite.sqrt()).is_none(),
                "a non-exceptional value classified on both sides"
            );
            prop_assert_eq!(classify(-discriminant, discriminant), (true, Fp::ZERO));
            Ok(())
        });
    }

    /// A split files every value once, each on its own side with a root for
    /// that side.
    #[test]
    fn splits_are_exhaustive_and_disjoint() {
        check(256, (any::<u64>(), 0usize..=48), |(seed, count)| {
            let (values, discriminant) = values_at(seed, count);
            let (residue, non_residue) = split(values.iter().copied(), discriminant);
            prop_assert_eq!(residue.len() + non_residue.len(), values.len());
            for &(value, root) in &residue {
                prop_assert_ne!(chi(value + discriminant), -Fp::ONE);
                prop_assert_eq!(root.square(), value + discriminant);
            }
            for &(value, root) in &non_residue {
                prop_assert_eq!(chi(value + discriminant), -Fp::ONE);
                prop_assert_eq!(
                    root.square(),
                    QUADRATIC_NON_RESIDUE * (value + discriminant)
                );
            }
            Ok(())
        });
    }

    /// Collects a polynomial's coefficients with the sparse capacity padding
    /// trimmed; the zero polynomial densifies to `[0]`.
    fn dense(poly: &Polynomial<Fp, ProductionRank>) -> Vec<Fp> {
        let mut coeffs = poly.iter_coeffs().collect::<Vec<_>>();
        let last_nonzero = coeffs.iter().rposition(|coeff| coeff != &Fp::ZERO);
        coeffs.truncate(last_nonzero.map_or(1, |idx| idx + 1));
        coeffs
    }

    fn abscissas_of(points: &[(Fp, Fp)]) -> Vec<Fp> {
        points.iter().map(|&(abscissa, _)| abscissa).collect()
    }

    /// Verifies $u^2 - c \cdot (X + s) = q \cdot h$ coefficient by coefficient
    /// for one side.
    fn verify_side(
        points: &[(Fp, Fp)],
        class: Fp,
        shift: Fp,
        u: &Polynomial<Fp, ProductionRank>,
        h: &Polynomial<Fp, ProductionRank>,
    ) {
        let q = multiset::encode(abscissas_of(points));
        let mut lhs = dense(&super::super::poly_mul(u, u));
        if lhs.len() < 2 {
            lhs.resize(2, Fp::ZERO);
        }
        lhs[0] -= class * shift;
        lhs[1] -= class;
        let rhs = dense(&super::super::poly_mul(&q, h));
        assert_eq!(dense(&Polynomial::from_coeffs(lhs)), rhs);
        for &(abscissa, root) in points {
            assert_eq!(u.eval(abscissa), root);
        }
    }

    /// Both sides of any split decompose, an exceptional value among them or
    /// not, and the exceptional value lands residue-side with root zero
    /// where the non-residue side opens nonzero.
    #[test]
    fn the_decomposition_holds_on_both_sides() {
        let strategy = (any::<u64>(), 0usize..=24, any::<bool>());
        check(256, strategy, |(seed, count, exceptional)| {
            let (mut values, discriminant) = values_at(seed, count);
            if exceptional {
                values.push(-discriminant);
            }
            let (residue, non_residue) = split(values, discriminant);
            if exceptional {
                prop_assert!(residue.contains(&(-discriminant, Fp::ZERO)));
                prop_assert_ne!(
                    multiset::encode(abscissas_of(&non_residue)).eval(-discriminant),
                    Fp::ZERO
                );
            }
            for (points, side) in [(&residue, true), (&non_residue, false)] {
                let class = class_multiplier(side);
                let (u, h) = decomposition(points, class, discriminant).unwrap();
                verify_side(points, class, discriminant, &u, &h);
            }
            Ok(())
        });
    }

    #[test]
    fn the_decomposition_holds_at_the_polynomial_capacity() {
        let rng = &mut StdRng::seed_from_u64(26);
        let discriminant = Fp::random(&mut *rng);
        let values: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
            .take(ProductionRank::num_coeffs() - 1)
            .collect();
        let (residue, non_residue) = split(values, discriminant);
        for (points, class) in [
            (&residue, class_multiplier(true)),
            (&non_residue, class_multiplier(false)),
        ] {
            let (u, h) = decomposition(points, class, discriminant).unwrap();
            let q = multiset::encode(abscissas_of(points));
            // The full coefficient compare is quadratic in B; evaluation at
            // random points verifies the identity in linear time instead.
            for _ in 0..4 {
                let z = Fp::random(&mut *rng);
                assert_eq!(
                    u.eval(z).square() - (class * (z + discriminant)),
                    q.eval(z) * h.eval(z)
                );
            }
        }
    }

    /// A value of the other side filed among a side's points, or a repeated
    /// abscissa, leaves the division with a remainder.
    #[test]
    fn a_misfiled_or_repeated_value_has_no_decomposition() {
        let strategy = (any::<u64>(), 2usize..=24, any::<bool>());
        check(256, strategy, |(seed, count, onto_residue)| {
            let (values, discriminant) = values_at(seed, count);
            let repeated = values[0];
            let (mut residue, mut non_residue) = split(values, discriminant);

            let (side, root) = classify(repeated, discriminant);
            let mut with_repeat = if side {
                residue.clone()
            } else {
                non_residue.clone()
            };
            with_repeat.push((repeated, root));
            prop_assert!(
                decomposition(&with_repeat, class_multiplier(side), discriminant).is_none()
            );

            prop_assume!(!residue.is_empty() && !non_residue.is_empty());
            let (points, class) = if onto_residue {
                residue.push(non_residue.pop().unwrap());
                (residue, class_multiplier(true))
            } else {
                non_residue.push(residue.pop().unwrap());
                (non_residue, class_multiplier(false))
            };
            prop_assert!(decomposition(&points, class, discriminant).is_none());
            Ok(())
        });
    }

    #[test]
    fn an_all_zero_side_takes_the_vanishing_polynomial() {
        check(256, any::<u64>(), |seed| {
            let (_, discriminant) = values_at(seed, 0);
            let points = [(-discriminant, Fp::ZERO)];
            let (u, h) = decomposition(&points, class_multiplier(true), discriminant).unwrap();
            prop_assert_eq!(dense(&u), [discriminant, Fp::ONE]);
            verify_side(&points, class_multiplier(true), discriminant, &u, &h);
            Ok(())
        });
    }

    /// Read over one value against many discriminants, each side's
    /// interpolant squares to that side's class times the shifted value at
    /// every discriminant it holds.
    #[test]
    fn the_decomposition_reads_as_a_profile_over_discriminants() {
        check(256, (any::<u64>(), 0usize..=16), |(seed, count)| {
            let (discriminants, value) = values_at(seed, count);
            let (residue, non_residue): (Vec<_>, Vec<_>) = discriminants
                .iter()
                .map(|&discriminant| (discriminant, classify(value, discriminant)))
                .partition(|&(_, (bit, _))| bit);
            for (side, entries) in [(true, residue), (false, non_residue)] {
                let points: Vec<(Fp, Fp)> = entries
                    .iter()
                    .map(|&(discriminant, (_, root))| (discriminant, root))
                    .collect();
                let class = class_multiplier(side);
                let (u, h) = decomposition(&points, class, value).unwrap();
                verify_side(&points, class, value, &u, &h);
                for &(discriminant, _) in &points {
                    prop_assert_eq!(
                        u.eval(discriminant).square(),
                        class * (value + discriminant)
                    );
                }
            }
            Ok(())
        });
    }
}
