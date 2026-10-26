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

use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::pasta;
use udon::field::{Fp, Reduced};

use super::arithmetic;

/// The least quadratic non-residue of the Pallas base field. Distinct from
/// the cubic non-residue the sequence encoding uses.
pub(crate) const QUADRATIC_NON_RESIDUE: Fp =
    udon::fp_hex!("0x0000000000000000000000000000000000000000000000000000000000000005");

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
pub fn classify(value: Fp<Reduced>, discriminant: Fp<Reduced>) -> (bool, Fp<Reduced>) {
    let shifted = value.add(&discriminant).reduce();
    if let Some(root) = shifted.sqrt() {
        return (true, root);
    }
    // The character is multiplicative and n is a non-residue, so exactly
    // one of the two character branches has a root.
    let root = QUADRATIC_NON_RESIDUE.mul(&shifted).reduce().sqrt();
    #[expect(
        clippy::expect_used,
        reason = "one of the two character branches always has a root"
    )]
    (false, root.expect("non-residue branch has a root"))
}

/// One side's points $(x_i, y_i)$, each $y_i$ the root of $x_i$ on that side.
pub(crate) type ClassificationPoints = Vec<(Fp<Reduced>, Fp<Reduced>)>;

/// Split values by side at `discriminant`, returning the residue-side then
/// the non-residue-side points.
#[must_use]
pub(crate) fn split(
    values: impl IntoIterator<Item = Fp<Reduced>>,
    discriminant: Fp<Reduced>,
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
fn divide_by_root(coeffs: &mut Vec<Fp>, root: Fp<Reduced>) -> Option<()> {
    let mut carry = <Fp>::ZERO;
    for coeff in coeffs.iter_mut().rev() {
        let quotient_coeff = carry;
        carry = coeff.add(&carry.mul(&root));
        *coeff = quotient_coeff;
    }
    // After the pass, `carry` is the remainder and the vector holds the
    // quotient with one trailing zero coefficient.
    carry.is_zero().then(|| coeffs.pop())?;
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
    points: &[(Fp<Reduced>, Fp<Reduced>)],
    class: Fp,
    shift: Fp<Reduced>,
) -> Option<(
    Polynomial<pasta::Fp, ProductionRank>,
    Polynomial<pasta::Fp, ProductionRank>,
)> {
    let mut interpolant_coeffs = if points.is_empty() {
        [<Fp>::ONE].to_vec()
    } else {
        super::interpolate(points)?
    };
    if interpolant_coeffs.iter().all(Fp::is_zero) {
        let abscissas: Vec<Fp> = points
            .iter()
            .map(|&(abscissa, _)| abscissa.into_loose())
            .collect();
        interpolant_coeffs = arithmetic::poly_with_roots(&abscissas);
    }

    let translate = [class.mul(&shift), class];
    let mut h_coeffs = Vec::new();
    arithmetic::poly_mul(&interpolant_coeffs, &interpolant_coeffs, &mut h_coeffs);
    if h_coeffs.len() < translate.len() {
        h_coeffs.resize(translate.len(), <Fp>::ZERO);
    }
    for (coeff, translate_coeff) in h_coeffs.iter_mut().zip(&translate) {
        *coeff = coeff.sub(translate_coeff);
    }
    for &(abscissa, _) in points {
        divide_by_root(&mut h_coeffs, abscissa)?;
    }

    Some((
        Polynomial::from_coeffs(interpolant_coeffs.into_iter().map(pasta::Fp::new).collect()),
        Polynomial::from_coeffs(h_coeffs.into_iter().map(pasta::Fp::new).collect()),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::min_ident_chars, reason = "test code")]

    use core::iter;

    use ragu_circuits::polynomials::Rank as _;
    use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
    use udon::field::random;

    use super::*;
    use crate::collections::multiset;

    /// $(p - 1) / 2$ as little-endian limbs, computed from field constants.
    fn half_order() -> [u64; 4] {
        let half = <Fp>::ONE.neg().mul(&<Fp>::TWO_INVERSE);
        let repr = half.to_bytes();
        let mut limbs = [0u64; 4];
        for (limb, bytes) in limbs.iter_mut().zip(repr.chunks(8)) {
            *limb = u64::from_le_bytes(bytes.try_into().unwrap());
        }
        limbs
    }

    /// Euler-criterion quadratic character: $1$, $-1$, or $0$.
    fn chi(x: Fp<Reduced>) -> Fp<Reduced> {
        let mut result = <Fp>::ONE;
        for limb in half_order().iter().rev() {
            for bit in (0..u64::BITS).rev() {
                result = result.square();
                if (limb >> bit) & 1 == 1 {
                    result = result.mul(&x);
                }
            }
        }
        result.reduce()
    }

    fn minus_one() -> Fp<Reduced> {
        <Fp>::ONE.neg().reduce()
    }

    fn eval_at(poly: &Polynomial<pasta::Fp, ProductionRank>, at: Fp<Reduced>) -> Fp<Reduced> {
        poly.eval(at.into_loose().into()).into_inner().reduce()
    }

    #[test]
    fn the_non_residue_constant_satisfies_the_euler_criterion() {
        assert_eq!(chi(QUADRATIC_NON_RESIDUE.reduce()), minus_one());
    }

    #[test]
    fn small_cubic_non_residues_are_quadratic_residues() {
        assert_eq!(chi(Fp::from_u64(2)), Fp::ONE);
        assert_eq!(chi(Fp::from_u64(3)), Fp::ONE);
    }

    #[test]
    fn classification_matches_the_legendre_symbol() {
        let rng = &mut StdRng::seed_from_u64(21);
        for _ in 0..64 {
            let discriminant = random(|bytes| rng.fill_bytes(bytes)).reduce();
            let x = random(|bytes| rng.fill_bytes(bytes)).reduce();
            let (bit, root) = classify(x, discriminant);
            assert_eq!(bit, chi(x.add(&discriminant).reduce()) != minus_one());
            assert_eq!(
                root.square().reduce(),
                class_multiplier(bit).mul(&x.add(&discriminant)).reduce()
            );
        }
    }

    #[test]
    fn the_exceptional_value_is_pinned_to_the_residue_side() {
        let rng = &mut StdRng::seed_from_u64(22);
        let discriminant: Fp<Reduced> = random(|bytes| rng.fill_bytes(bytes)).reduce();
        assert_eq!(
            classify(discriminant.neg().reduce(), discriminant),
            (true, Fp::ZERO)
        );
    }

    #[test]
    fn a_value_takes_exactly_one_side() {
        let rng = &mut StdRng::seed_from_u64(28);
        let discriminant: Fp<Reduced> = random(|bytes| rng.fill_bytes(bytes)).reduce();
        for _ in 0..32 {
            let x = random(|bytes| rng.fill_bytes(bytes)).reduce();
            let (bit, root) = classify(x, discriminant);
            let opposite = class_multiplier(!bit).mul(&x.add(&discriminant)).reduce();
            assert!(
                opposite.sqrt().is_none() || x == discriminant.neg().reduce(),
                "a non-exceptional value classified on both sides"
            );
            assert_eq!(
                root.square().reduce(),
                class_multiplier(bit).mul(&x.add(&discriminant)).reduce()
            );
        }
    }

    #[test]
    fn splits_are_exhaustive_and_disjoint() {
        let rng = &mut StdRng::seed_from_u64(30);
        let discriminant = random(|bytes| rng.fill_bytes(bytes)).reduce();
        let values: Vec<Fp<Reduced>> =
            iter::repeat_with(|| random(|bytes| rng.fill_bytes(bytes)).reduce())
                .take(64)
                .collect();

        let (residue, non_residue) = split(values.iter().copied(), discriminant);
        assert_eq!(residue.len() + non_residue.len(), values.len());
        for &(value, root) in &residue {
            assert_ne!(chi(value.add(&discriminant).reduce()), minus_one());
            assert_eq!(root.square().reduce(), value.add(&discriminant).reduce());
        }
        for &(value, root) in &non_residue {
            assert_eq!(chi(value.add(&discriminant).reduce()), minus_one());
            assert_eq!(
                root.square().reduce(),
                QUADRATIC_NON_RESIDUE
                    .mul(&value.add(&discriminant))
                    .reduce()
            );
        }
    }

    /// Collects a polynomial's coefficients with the sparse capacity padding
    /// trimmed; the zero polynomial densifies to `[0]`.
    fn dense(poly: &Polynomial<pasta::Fp, ProductionRank>) -> Vec<Fp<Reduced>> {
        let mut coeffs = poly
            .iter_coeffs()
            .map(|coeff| coeff.into_inner().reduce())
            .collect::<Vec<_>>();
        let last_nonzero = coeffs.iter().rposition(|coeff| !coeff.is_zero());
        coeffs.truncate(last_nonzero.map_or(1, |idx| idx + 1));
        coeffs
    }

    fn abscissas_of(points: &[(Fp<Reduced>, Fp<Reduced>)]) -> Vec<Fp<Reduced>> {
        points.iter().map(|&(abscissa, _)| abscissa).collect()
    }

    /// Verifies $u^2 - c \cdot (X + s) = q \cdot h$ coefficient by coefficient
    /// for one side.
    fn verify_side(
        points: &[(Fp<Reduced>, Fp<Reduced>)],
        class: Fp,
        shift: Fp<Reduced>,
        u: &Polynomial<pasta::Fp, ProductionRank>,
        h: &Polynomial<pasta::Fp, ProductionRank>,
    ) {
        let q = multiset::encode(abscissas_of(points));
        let mut lhs = dense(&super::super::poly_mul(u, u));
        if lhs.len() < 2 {
            lhs.resize(2, Fp::ZERO);
        }
        lhs[0] = lhs[0].sub(&class.mul(&shift)).reduce();
        lhs[1] = lhs[1].sub(&class).reduce();
        let rhs = dense(&super::super::poly_mul(&q, h));
        let lhs_coeffs = lhs.iter().map(|coeff| coeff.into_loose().into()).collect();
        assert_eq!(dense(&Polynomial::from_coeffs(lhs_coeffs)), rhs);
        for &(abscissa, root) in points {
            assert_eq!(eval_at(u, abscissa), root);
        }
    }

    #[test]
    fn the_set_encoding_is_monic() {
        let rng = &mut StdRng::seed_from_u64(33);
        for count in [0, 1, 5] {
            let values: Vec<Fp<Reduced>> =
                iter::repeat_with(|| random(|bytes| rng.fill_bytes(bytes)).reduce())
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
            let discriminant = random(|bytes| rng.fill_bytes(bytes)).reduce();
            let values: Vec<Fp<Reduced>> =
                iter::repeat_with(|| random(|bytes| rng.fill_bytes(bytes)).reduce())
                    .take((2 * count) + 2)
                    .collect();
            let (residue, non_residue) = split(values, discriminant);
            let (u1, h1) = decomposition(&residue, class_multiplier(true), discriminant).unwrap();
            let (u2, h2) =
                decomposition(&non_residue, class_multiplier(false), discriminant).unwrap();
            verify_side(&residue, class_multiplier(true), discriminant, &u1, &h1);
            verify_side(
                &non_residue,
                class_multiplier(false),
                discriminant,
                &u2,
                &h2,
            );
        }
    }

    #[test]
    fn the_decomposition_holds_at_the_polynomial_capacity() {
        let rng = &mut StdRng::seed_from_u64(26);
        let discriminant = random(|bytes| rng.fill_bytes(bytes)).reduce();
        let values: Vec<Fp<Reduced>> =
            iter::repeat_with(|| random(|bytes| rng.fill_bytes(bytes)).reduce())
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
                let z = random(|bytes| rng.fill_bytes(bytes)).reduce();
                assert_eq!(
                    eval_at(&u, z)
                        .square()
                        .sub(&class.mul(&z.add(&discriminant)))
                        .reduce(),
                    eval_at(&q, z).mul(&eval_at(&h, z)).reduce()
                );
            }
        }
    }

    #[test]
    fn a_misfiled_value_has_no_decomposition() {
        let rng = &mut StdRng::seed_from_u64(31);
        let discriminant = random(|bytes| rng.fill_bytes(bytes)).reduce();
        let values: Vec<Fp<Reduced>> =
            iter::repeat_with(|| random(|bytes| rng.fill_bytes(bytes)).reduce())
                .take(16)
                .collect();
        let (mut residue, mut non_residue) = split(values, discriminant);
        residue.push(non_residue.pop().unwrap());
        assert!(decomposition(&residue, class_multiplier(true), discriminant).is_none());
    }

    #[test]
    fn a_repeated_value_has_no_decomposition() {
        let rng = &mut StdRng::seed_from_u64(32);
        let discriminant = random(|bytes| rng.fill_bytes(bytes)).reduce();
        let value = random(|bytes| rng.fill_bytes(bytes)).reduce();
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
        let discriminant: Fp<Reduced> = random(|bytes| rng.fill_bytes(bytes)).reduce();
        let exceptional = discriminant.neg().reduce();
        let values: Vec<Fp<Reduced>> =
            iter::repeat_with(|| random(|bytes| rng.fill_bytes(bytes)).reduce())
                .take(16)
                .chain(iter::once(exceptional))
                .collect();

        let (residue, non_residue) = split(values, discriminant);
        assert!(
            residue.contains(&(exceptional, Fp::ZERO)),
            "the exceptional value must land on the residue side"
        );
        let q2 = multiset::encode(abscissas_of(&non_residue));
        assert_ne!(
            eval_at(&q2, exceptional),
            Fp::ZERO,
            "the non-residue side must open nonzero at -R"
        );
        let (u1, h1) = decomposition(&residue, class_multiplier(true), discriminant).unwrap();
        let (u2, h2) = decomposition(&non_residue, class_multiplier(false), discriminant).unwrap();
        verify_side(&residue, class_multiplier(true), discriminant, &u1, &h1);
        verify_side(
            &non_residue,
            class_multiplier(false),
            discriminant,
            &u2,
            &h2,
        );
    }

    #[test]
    fn an_all_zero_side_takes_the_vanishing_polynomial() {
        let rng = &mut StdRng::seed_from_u64(35);
        let discriminant: Fp<Reduced> = random(|bytes| rng.fill_bytes(bytes)).reduce();
        let points = [(discriminant.neg().reduce(), Fp::ZERO)];
        let (u, h) = decomposition(&points, class_multiplier(true), discriminant).unwrap();
        assert_eq!(dense(&u), [discriminant, Fp::ONE]);
        verify_side(&points, class_multiplier(true), discriminant, &u, &h);
    }

    #[test]
    fn the_decomposition_reads_as_a_profile_over_discriminants() {
        let rng = &mut StdRng::seed_from_u64(50);
        let value: Fp<Reduced> = random(|bytes| rng.fill_bytes(bytes)).reduce();
        let discriminants: Vec<Fp<Reduced>> =
            iter::repeat_with(|| random(|bytes| rng.fill_bytes(bytes)).reduce())
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
        let (u1, h1) = decomposition(&residue, class_multiplier(true), value).unwrap();
        let (u2, h2) = decomposition(&non_residue, class_multiplier(false), value).unwrap();
        verify_side(&residue, class_multiplier(true), value, &u1, &h1);
        verify_side(&non_residue, class_multiplier(false), value, &u2, &h2);
        for &(discriminant, _) in &residue {
            assert_eq!(
                eval_at(&u1, discriminant).square().reduce(),
                value.add(&discriminant).reduce()
            );
        }
        for &(discriminant, _) in &non_residue {
            assert_eq!(
                eval_at(&u2, discriminant).square().reduce(),
                QUADRATIC_NON_RESIDUE
                    .mul(&value.add(&discriminant))
                    .reduce()
            );
        }
    }
}
