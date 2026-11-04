#![allow(clippy::min_ident_chars, reason = "test code")]

use core::iter;

use ragu_circuits::polynomials::Rank as _;
use rand::{Rng as _, SeedableRng as _, rngs::StdRng};
use udon::field::Field;

use super::*;
use crate::collections::multiset;

fn values_at(count: usize) -> (Vec<Fp>, Fp) {
    let rng = &mut StdRng::seed_from_u64(0);
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    let values = iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
        .take(count)
        .collect();
    (values, discriminant)
}

fn half_order() -> [u64; 4] {
    let half = -Fp::ONE * Fp::TWO_INVERSE;
    let repr = half.to_bytes();
    let mut limbs = [0u64; 4];
    for (limb, bytes) in limbs.iter_mut().zip(repr.as_ref().chunks(8)) {
        *limb = u64::from_le_bytes(bytes.try_into().unwrap());
    }
    limbs
}

fn chi(x: Fp) -> Fp {
    let mut result = Fp::ONE;
    for limb in half_order().iter().rev() {
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
fn the_non_residue_constant_satisfies_the_euler_criterion() {
    assert_eq!(chi(QUADRATIC_NON_RESIDUE), -Fp::ONE);
}

#[test]
fn classification_matches_the_euler_criterion() {
    let rng = &mut StdRng::seed_from_u64(0);
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    let square = Fp::random(|bytes| rng.fill_bytes(bytes)).square();
    for (label, x, side) in [
        ("a residue-side value", square - discriminant, true),
        (
            "a non-residue-side value",
            QUADRATIC_NON_RESIDUE * square - discriminant,
            false,
        ),
        ("the exceptional value", -discriminant, true),
    ] {
        let (bit, root) = classify(x, discriminant);
        assert_eq!(bit, side, "{label} takes its side");
        assert_eq!(
            bit,
            chi(x + discriminant) != -Fp::ONE,
            "{label} by the Euler criterion"
        );
        assert_eq!(
            root.square(),
            class_multiplier(bit) * (x + discriminant),
            "{label} root"
        );
        let opposite = class_multiplier(!bit) * (x + discriminant);
        assert_eq!(
            opposite.sqrt().is_some(),
            x == -discriminant,
            "{label} has a root on the other side"
        );
    }
    assert_eq!(classify(-discriminant, discriminant), (true, Fp::ZERO));
}

#[test]
fn splits_are_exhaustive_and_disjoint() {
    for count in [0, 1, 17, 48] {
        let (values, discriminant) = values_at(count);
        let (residue, non_residue) = split(values.iter().copied(), discriminant);
        let mut filed: Vec<[u8; 32]> = residue
            .iter()
            .chain(&non_residue)
            .map(|&(value, _)| value.to_bytes())
            .collect();
        let mut given: Vec<[u8; 32]> = values.iter().map(Field::to_bytes).collect();
        filed.sort_unstable();
        given.sort_unstable();
        assert_eq!(filed, given, "{count} values file as themselves, once each");
        for &(value, root) in &residue {
            assert_ne!(
                chi(value + discriminant),
                -Fp::ONE,
                "{count} values: residue side"
            );
            assert_eq!(
                root.square(),
                value + discriminant,
                "{count} values: residue root"
            );
        }
        for &(value, root) in &non_residue {
            assert_eq!(
                chi(value + discriminant),
                -Fp::ONE,
                "{count} values: non-residue side"
            );
            assert_eq!(
                root.square(),
                QUADRATIC_NON_RESIDUE * (value + discriminant),
                "{count} values: non-residue root"
            );
        }
    }
}

fn dense(poly: &Polynomial<Fp, ProductionRank>) -> Vec<Fp> {
    let mut coeffs = poly.iter_coeffs().collect::<Vec<_>>();
    let last_nonzero = coeffs.iter().rposition(|coeff| coeff != &Fp::ZERO);
    coeffs.truncate(last_nonzero.map_or(1, |idx| idx + 1));
    coeffs
}

fn abscissas_of(points: &[(Fp, Fp)]) -> Vec<Fp> {
    points.iter().map(|&(abscissa, _)| abscissa).collect()
}

fn verify_side(
    points: &[(Fp, Fp)],
    class: Fp,
    shift: Fp,
    u: &Polynomial<Fp, ProductionRank>,
    h: &Polynomial<Fp, ProductionRank>,
) {
    let q = multiset::encode(abscissas_of(points));
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
fn the_decomposition_holds_on_both_sides() {
    for count in [0, 1, 24] {
        for exceptional in [false, true] {
            let (mut values, discriminant) = values_at(count);
            if exceptional {
                values.push(-discriminant);
            }
            let (residue, non_residue) = split(values, discriminant);
            if exceptional {
                assert!(
                    residue.contains(&(-discriminant, Fp::ZERO)),
                    "{count} values: the exceptional value files residue-side"
                );
                assert_ne!(
                    multiset::encode(abscissas_of(&non_residue)).eval(-discriminant),
                    Fp::ZERO,
                    "{count} values: the non-residue side opens nonzero"
                );
            }
            for (points, side) in [(&residue, true), (&non_residue, false)] {
                let class = class_multiplier(side);
                let (u, h) = decomposition(points, class, discriminant).unwrap();
                verify_side(points, class, discriminant, &u, &h);
            }
        }
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
        let q = multiset::encode(abscissas_of(points));
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
fn a_misfiled_or_repeated_value_has_no_decomposition() {
    let rng = &mut StdRng::seed_from_u64(0);
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    let mut square = || Fp::random(|bytes| rng.fill_bytes(bytes)).square();
    let values = [
        square() - discriminant,
        square() - discriminant,
        QUADRATIC_NON_RESIDUE * square() - discriminant,
        QUADRATIC_NON_RESIDUE * square() - discriminant,
    ];
    let (residue, non_residue) = split(values, discriminant);
    assert_eq!((residue.len(), non_residue.len()), (2, 2), "the sides");
    for (name, side, points, others) in [
        ("residue", true, &residue, &non_residue),
        ("non-residue", false, &non_residue, &residue),
    ] {
        let class = class_multiplier(side);
        let repeated = [points.as_slice(), &points[..1]].concat();
        assert!(
            decomposition(&repeated, class, discriminant).is_none(),
            "a repeated {name}-side value"
        );
        let misfiled = [points.as_slice(), &others[..1]].concat();
        assert!(
            decomposition(&misfiled, class, discriminant).is_none(),
            "a value misfiled {name}-side"
        );
    }
}

#[test]
fn an_all_zero_side_takes_the_vanishing_polynomial() {
    let (_, discriminant) = values_at(0);
    let points = [(-discriminant, Fp::ZERO)];
    let (u, h) = decomposition(&points, class_multiplier(true), discriminant).unwrap();
    assert_eq!(dense(&u), [discriminant, Fp::ONE]);
    verify_side(&points, class_multiplier(true), discriminant, &u, &h);
}

#[test]
fn the_decomposition_reads_as_a_profile_over_discriminants() {
    for count in [0, 1, 16] {
        let (discriminants, value) = values_at(count);
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
                assert_eq!(
                    u.eval(discriminant).square(),
                    class * (value + discriminant),
                    "{count} discriminants, side {side}"
                );
            }
        }
    }
}
