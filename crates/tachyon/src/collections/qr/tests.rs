#![allow(clippy::min_ident_chars, reason = "test code")]

use core::iter;

use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;
use crate::collections::multiset;

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
fn the_decomposition_holds_on_both_sides() {
    let rng = &mut StdRng::seed_from_u64(23);
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    let values: Vec<Fp> = iter::repeat_with(|| Fp::random(|bytes| rng.fill_bytes(bytes)))
        .take(600)
        .collect();
    let (residue, non_residue) = split(values, discriminant);
    for (points, class) in [
        (&residue, class_multiplier(true)),
        (&non_residue, class_multiplier(false)),
    ] {
        let (u, h) = decomposition(points, class, discriminant).unwrap();
        verify_side(points, class, discriminant, &u, &h);
    }
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
