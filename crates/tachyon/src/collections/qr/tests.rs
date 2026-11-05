#![allow(clippy::min_ident_chars, reason = "test code")]

use core::iter;

use ragu_circuits::polynomials::Rank as _;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;
use crate::collections::multiset;

fn chi(x: Fp) -> Fp {
    let half = -Fp::ONE * Fp::TWO_INVERSE;
    let repr = half.to_bytes();
    let mut half_order = [0u64; 4];
    for (limb, bytes) in half_order.iter_mut().zip(repr.as_ref().chunks(8)) {
        *limb = u64::from_le_bytes(bytes.try_into().unwrap());
    }
    let mut result = Fp::ONE;
    for limb in half_order.iter().rev() {
        for bit in (0..u64::BITS).rev() {
            result = result.square();
            if (limb >> bit) & 1 == 1 {
                result *= x;
            }
        }
    }
    result
}

#[test]
fn classification_matches_the_legendre_symbol() {
    assert_eq!(chi(QUADRATIC_NON_RESIDUE), -Fp::ONE);
    let rng = &mut StdRng::seed_from_u64(21);
    for _ in 0..64 {
        let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
        let x = Fp::random(|bytes| rng.fill_bytes(bytes));
        let (bit, root) = classify(x, discriminant);
        assert_eq!(bit, chi(x + discriminant) != -Fp::ONE);
        assert_eq!(root.square(), class_multiplier(bit) * (x + discriminant));
    }
}

#[test]
fn a_value_takes_exactly_one_side() {
    let rng = &mut StdRng::seed_from_u64(28);
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    for _ in 0..32 {
        let x = Fp::random(|bytes| rng.fill_bytes(bytes));
        let (bit, root) = classify(x, discriminant);
        let opposite = class_multiplier(!bit) * (x + discriminant);
        assert!(opposite.sqrt().is_none() || x == -discriminant);
        assert_eq!(root.square(), class_multiplier(bit) * (x + discriminant));
    }
}

#[test]
fn splits_are_exhaustive_and_disjoint() {
    let rng = &mut StdRng::seed_from_u64(30);
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    let values: Vec<Fp> = iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
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

fn dense(poly: &Polynomial<Fp, ProductionRank>) -> Vec<Fp> {
    let mut coeffs = poly.iter_coeffs().collect::<Vec<_>>();
    let last_nonzero = coeffs.iter().rposition(|coeff| coeff != &Fp::ZERO);
    coeffs.truncate(last_nonzero.map_or(1, |idx| idx + 1));
    coeffs
}

fn verify_side(
    points: &[(Fp, Fp)],
    class: Fp,
    shift: Fp,
    u: &Polynomial<Fp, ProductionRank>,
    h: &Polynomial<Fp, ProductionRank>,
) {
    let q = multiset::encode(points.iter().map(|&(abscissa, _)| abscissa));
    let mut lhs = arithmetic::poly_mul(&dense(u), &dense(u));
    if lhs.len() < 2 {
        lhs.resize(2, Fp::ZERO);
    }
    lhs[0] -= class * shift;
    lhs[1] -= class;
    let rhs = arithmetic::poly_mul(&dense(&q), &dense(h));
    assert_eq!(dense(&Polynomial::from_coeffs(lhs)), rhs);
    for &(abscissa, root) in points {
        assert_eq!(u.eval(abscissa), root);
    }
}

#[test]
fn the_set_encoding_is_monic() {
    let rng = &mut StdRng::seed_from_u64(33);
    for count in [0, 1, 5] {
        let values: Vec<Fp> = iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
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
        let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
        let values: Vec<Fp> = iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
            .take((2 * count) + 2)
            .collect();
        let (residue, non_residue) = split(values, discriminant);
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
}

#[test]
fn the_decomposition_holds_at_the_polynomial_capacity() {
    let rng = &mut StdRng::seed_from_u64(26);
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    let values: Vec<Fp> = iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
        .take(ProductionRank::num_coeffs() - 1)
        .collect();
    let (residue, non_residue) = split(values, discriminant);
    for (points, class) in [
        (&residue, class_multiplier(true)),
        (&non_residue, class_multiplier(false)),
    ] {
        let (u, h) = decomposition(points, class, discriminant).unwrap();
        let q = multiset::encode(points.iter().map(|&(abscissa, _)| abscissa));
        // Random points avoid the quadratic full coefficient compare.
        for _ in 0..4 {
            let z = Fp::random(|bytes| rng.fill_bytes(bytes));
            assert_eq!(
                u.eval(z).square() - (class * (z + discriminant)),
                q.eval(z) * h.eval(z)
            );
        }
    }
}

#[test]
fn a_misfiled_value_has_no_decomposition() {
    let rng = &mut StdRng::seed_from_u64(31);
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    let values: Vec<Fp> = iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
        .take(16)
        .collect();
    let (mut residue, mut non_residue) = split(values, discriminant);
    residue.push(non_residue.pop().unwrap());
    assert!(decomposition(&residue, class_multiplier(true), discriminant).is_none());
}

#[test]
fn a_repeated_value_has_no_decomposition() {
    let rng = &mut StdRng::seed_from_u64(32);
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    let value = Fp::random(|bytes| rng.fill_bytes(bytes));
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
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    let values: Vec<Fp> = iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
        .take(16)
        .chain(iter::once(-discriminant))
        .collect();

    let (residue, non_residue) = split(values, discriminant);
    assert!(residue.contains(&(-discriminant, Fp::ZERO)));
    let q2 = multiset::encode(non_residue.iter().map(|&(abscissa, _)| abscissa));
    assert_ne!(q2.eval(-discriminant), Fp::ZERO);
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
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    let points = [(-discriminant, Fp::ZERO)];
    let (u, h) = decomposition(&points, class_multiplier(true), discriminant).unwrap();
    assert_eq!(dense(&u), [discriminant, Fp::ONE]);
    verify_side(&points, class_multiplier(true), discriminant, &u, &h);
}
