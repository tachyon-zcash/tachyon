//! # Quadratic-residue classification
//!
//! A value $x$ takes the residue side at a discriminant $R$ iff $x + R$ is a
//! square or zero, and the non-residue side otherwise. A root $y$ attests
//! either side: $y^2 = x + R$ on the residue side, $y^2 = n\,(x + R)$ for a
//! fixed non-residue $n$ on the other.
//!
//! ## Class decomposition
//!
//! With $q$ one side's values as roots and $g$ interpolating their roots
//! $y_i$, at that side's class multiplier $c$,
//!
//! $$
//!   g(X)^2 - c\,(X + R) = q(X)\, h(X),
//! $$
//!
//! so every root of $q$ takes that side. The exceptional value $-R$ has root
//! $0$ under either class; $q_\mathsf{non}(-R) \neq 0$ files it residue-side.
//!
//! The identity also reads over one value against many discriminants: with
//! the $R_j$ as the roots of $q$ and $x$ as the shift, $g(R_j)^2 = c\,(x +
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
/// R$ is a square or zero, and a root with $\mathsf{root}^2 = c\,(v + R)$ at
/// that side's [`class_multiplier`].
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

/// Class decomposition $(g, h)$ of `points` at class multiplier $c$ and shift
/// $s$:
///
/// $$
///   g(X)^2 - c\,(X + s) = q(X)\, h(X),
/// $$
///
/// with $q$ the abscissas as roots and $g$ interpolating the points. An empty
/// side takes $g = 1$ and an all-zero side takes $g = q$, so neither
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
    let mut g_coeffs = if points.is_empty() {
        [Fp::ONE].to_vec()
    } else {
        super::interpolate(points)?
    };
    if g_coeffs.iter().all(|coeff| coeff == &Fp::ZERO) {
        let abscissas: Vec<Fp> = points.iter().map(|&(abscissa, _)| abscissa).collect();
        g_coeffs = arithmetic::poly_with_roots(&abscissas);
    }

    let translate = [class * shift, class];
    let mut h_coeffs = Vec::new();
    arithmetic::poly_mul(&g_coeffs, &g_coeffs, &mut h_coeffs);
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
        Polynomial::from_coeffs(g_coeffs),
        Polynomial::from_coeffs(h_coeffs),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::min_ident_chars, reason = "test code")]

    use core::iter;

    use ff::PrimeField as _;
    use ragu_circuits::polynomials::Rank as _;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::collections::multiset;

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

    #[test]
    fn classification_matches_the_legendre_symbol() {
        let rng = &mut StdRng::seed_from_u64(21);
        for _ in 0..64 {
            let discriminant = Fp::random(&mut *rng);
            let x = Fp::random(&mut *rng);
            let (bit, root) = classify(x, discriminant);
            assert_eq!(bit, chi(x + discriminant) != -Fp::ONE);
            assert_eq!(root.square(), class_multiplier(bit) * (x + discriminant));
        }
    }

    #[test]
    fn the_exceptional_value_is_pinned_to_the_residue_side() {
        let rng = &mut StdRng::seed_from_u64(22);
        let discriminant = Fp::random(&mut *rng);
        assert_eq!(classify(-discriminant, discriminant), (true, Fp::ZERO));
    }

    #[test]
    fn a_value_takes_exactly_one_side() {
        let rng = &mut StdRng::seed_from_u64(28);
        let discriminant = Fp::random(&mut *rng);
        for _ in 0..32 {
            let x = Fp::random(&mut *rng);
            let (bit, root) = classify(x, discriminant);
            let opposite = class_multiplier(!bit) * (x + discriminant);
            assert!(
                Option::<Fp>::from(opposite.sqrt()).is_none() || x == -discriminant,
                "a non-exceptional value classified on both sides"
            );
            assert_eq!(root.square(), class_multiplier(bit) * (x + discriminant));
        }
    }

    #[test]
    fn splits_are_exhaustive_and_disjoint() {
        let rng = &mut StdRng::seed_from_u64(30);
        let discriminant = Fp::random(&mut *rng);
        let values: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
            .take(64)
            .collect();

        let (residue, non_residue) = split(values.iter().copied(), discriminant);
        assert_eq!(residue.len() + non_residue.len(), values.len());
        for &(value, root) in &residue {
            assert_ne!(chi(value + discriminant), -Fp::ONE);
            assert_eq!(root.square(), value + discriminant);
        }
        for &(value, root) in &non_residue {
            assert_eq!(chi(value + discriminant), -Fp::ONE);
            assert_eq!(
                root.square(),
                QUADRATIC_NON_RESIDUE * (value + discriminant)
            );
        }
    }

    /// Collects a polynomial's coefficients with the sparse capacity padding
    /// trimmed; the zero polynomial densifies to `[0]`.
    fn dense(poly: &Polynomial<Fp, ProductionRank>) -> Vec<Fp> {
        let mut coeffs = Vec::from_iter(poly.iter_coeffs());
        let last_nonzero = coeffs.iter().rposition(|coeff| coeff != &Fp::ZERO);
        coeffs.truncate(last_nonzero.map_or(1, |idx| idx + 1));
        coeffs
    }

    fn abscissas_of(points: &[(Fp, Fp)]) -> Vec<Fp> {
        points.iter().map(|&(abscissa, _)| abscissa).collect()
    }

    /// Verifies $g^2 - c\,(X + s) = q\,h$ coefficient by coefficient for one
    /// side.
    fn verify_side(
        points: &[(Fp, Fp)],
        class: Fp,
        shift: Fp,
        g: &Polynomial<Fp, ProductionRank>,
        h: &Polynomial<Fp, ProductionRank>,
    ) {
        let q = multiset::encode(abscissas_of(points));
        let mut lhs = dense(&super::super::poly_mul(g, g));
        if lhs.len() < 2 {
            lhs.resize(2, Fp::ZERO);
        }
        lhs[0] -= class * shift;
        lhs[1] -= class;
        let rhs = dense(&super::super::poly_mul(&q, h));
        assert_eq!(dense(&Polynomial::from_coeffs(lhs)), rhs);
        for &(abscissa, root) in points {
            assert_eq!(g.eval(abscissa), root);
        }
    }

    #[test]
    fn the_set_encoding_is_monic() {
        let rng = &mut StdRng::seed_from_u64(33);
        for count in [0, 1, 5] {
            let values: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
                .take(count)
                .collect();
            let encoded = dense(&multiset::encode(values));
            assert_eq!(encoded.len(), count + 1);
            assert_eq!(encoded.last(), Some(&Fp::ONE));
        }
    }

    #[test]
    fn the_decomposition_holds_on_both_sides() {
        let rng = &mut StdRng::seed_from_u64(23);
        for count in [0, 1, 2, 7] {
            let discriminant = Fp::random(&mut *rng);
            let values: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
                .take((2 * count) + 2)
                .collect();
            let (residue, non_residue) = split(values, discriminant);
            let (g1, h1) = decomposition(&residue, class_multiplier(true), discriminant).unwrap();
            let (g2, h2) =
                decomposition(&non_residue, class_multiplier(false), discriminant).unwrap();
            verify_side(&residue, class_multiplier(true), discriminant, &g1, &h1);
            verify_side(
                &non_residue,
                class_multiplier(false),
                discriminant,
                &g2,
                &h2,
            );
        }
    }

    #[test]
    fn the_decomposition_holds_at_the_polynomial_capacity() {
        let rng = &mut StdRng::seed_from_u64(26);
        let discriminant = Fp::random(&mut *rng);
        let values: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
            .take((1 << ProductionRank::RANK) - 1)
            .collect();
        let (residue, non_residue) = split(values, discriminant);
        for (points, class) in [
            (&residue, class_multiplier(true)),
            (&non_residue, class_multiplier(false)),
        ] {
            let (g, h) = decomposition(points, class, discriminant).unwrap();
            let q = multiset::encode(abscissas_of(points));
            // The full coefficient compare is quadratic in B; evaluation at
            // random points verifies the identity in linear time instead.
            for _ in 0..4 {
                let z = Fp::random(&mut *rng);
                assert_eq!(
                    g.eval(z).square() - (class * (z + discriminant)),
                    q.eval(z) * h.eval(z)
                );
            }
        }
    }

    #[test]
    fn a_misfiled_value_has_no_decomposition() {
        let rng = &mut StdRng::seed_from_u64(31);
        let discriminant = Fp::random(&mut *rng);
        let values: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
            .take(16)
            .collect();
        let (mut residue, mut non_residue) = split(values, discriminant);
        residue.push(non_residue.pop().unwrap());
        assert!(decomposition(&residue, class_multiplier(true), discriminant).is_none());
    }

    #[test]
    fn a_repeated_value_has_no_decomposition() {
        let rng = &mut StdRng::seed_from_u64(32);
        let discriminant = Fp::random(&mut *rng);
        let value = Fp::random(&mut *rng);
        let (residue, non_residue) = split([value, value], discriminant);
        let (points, class) = if residue.is_empty() {
            (&non_residue, class_multiplier(false))
        } else {
            (&residue, class_multiplier(true))
        };
        assert_eq!(points.len(), 2);
        assert!(decomposition(points, class, discriminant).is_none());
    }

    #[test]
    fn an_exceptional_value_lands_residue_side_with_root_zero() {
        let rng = &mut StdRng::seed_from_u64(34);
        let discriminant = Fp::random(&mut *rng);
        let values: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
            .take(16)
            .chain(iter::once(-discriminant))
            .collect();

        let (residue, non_residue) = split(values, discriminant);
        assert!(
            residue.contains(&(-discriminant, Fp::ZERO)),
            "the exceptional value must land on the residue side"
        );
        let q2 = multiset::encode(abscissas_of(&non_residue));
        assert_ne!(
            q2.eval(-discriminant),
            Fp::ZERO,
            "the non-residue side must open nonzero at -R"
        );
        let (g1, h1) = decomposition(&residue, class_multiplier(true), discriminant).unwrap();
        let (g2, h2) = decomposition(&non_residue, class_multiplier(false), discriminant).unwrap();
        verify_side(&residue, class_multiplier(true), discriminant, &g1, &h1);
        verify_side(
            &non_residue,
            class_multiplier(false),
            discriminant,
            &g2,
            &h2,
        );
    }

    #[test]
    fn an_all_zero_side_takes_the_vanishing_polynomial() {
        let rng = &mut StdRng::seed_from_u64(35);
        let discriminant = Fp::random(&mut *rng);
        let points = [(-discriminant, Fp::ZERO)];
        let (g, h) = decomposition(&points, class_multiplier(true), discriminant).unwrap();
        assert_eq!(dense(&g), [discriminant, Fp::ONE]);
        verify_side(&points, class_multiplier(true), discriminant, &g, &h);
    }

    #[test]
    fn the_decomposition_reads_as_a_profile_over_discriminants() {
        let rng = &mut StdRng::seed_from_u64(50);
        let value = Fp::random(&mut *rng);
        let discriminants: Vec<Fp> = iter::repeat_with(|| Fp::random(&mut *rng))
            .take(9)
            .collect();
        let mut residue = Vec::new();
        let mut non_residue = Vec::new();
        for &discriminant in &discriminants {
            let (bit, root) = classify(value, discriminant);
            if bit {
                residue.push((discriminant, root));
            } else {
                non_residue.push((discriminant, root));
            }
        }
        let (g1, h1) = decomposition(&residue, class_multiplier(true), value).unwrap();
        let (g2, h2) = decomposition(&non_residue, class_multiplier(false), value).unwrap();
        verify_side(&residue, class_multiplier(true), value, &g1, &h1);
        verify_side(&non_residue, class_multiplier(false), value, &g2, &h2);
        for &(discriminant, _) in &residue {
            assert_eq!(g1.eval(discriminant).square(), value + discriminant);
        }
        for &(discriminant, _) in &non_residue {
            assert_eq!(
                g2.eval(discriminant).square(),
                QUADRATIC_NON_RESIDUE * (value + discriminant)
            );
        }
    }
}
