#![allow(clippy::min_ident_chars, reason = "test code")]

use core::iter;

use rand::{Rng as _, SeedableRng as _, rngs::StdRng};

use super::*;
use crate::collections::multiset;

fn dense(poly: &Polynomial<Fp, WalletRank>) -> Vec<Fp> {
    let mut coeffs = poly.iter_coeffs().collect::<Vec<_>>();
    let last_nonzero = coeffs.iter().rposition(|coeff| coeff != &Fp::ZERO);
    coeffs.truncate(last_nonzero.map_or(1, |idx| idx + 1));
    coeffs
}

fn verify_side(
    points: &[(Fp, Fp)],
    class: Fp,
    shift: Fp,
    u: &Polynomial<Fp, WalletRank>,
    h: &Polynomial<Fp, WalletRank>,
) {
    let q = multiset::try_encode(points.iter().map(|&(abscissa, _)| abscissa)).unwrap();
    let [u_degree, q_degree, h_degree] = [u, &q, h].map(|poly| {
        poly.iter_stored_coeffs()
            .last()
            .map_or(0, |(degree, _)| degree)
    });
    let degree_bound = (2 * u_degree).max(q_degree + h_degree).max(1);
    // Agreement at more distinct points than the degree bound proves the full
    // coefficient identity, without multiplying coefficient vectors here.
    for at in (0..=u64::try_from(degree_bound).unwrap()).map(Fp::from) {
        assert_eq!(
            u.eval(at).square() - class * (at + shift),
            q.eval(at) * h.eval(at)
        );
    }
    for &(abscissa, root) in points {
        assert_eq!(u.eval(abscissa), root);
    }
}

#[test]
fn the_decomposition_holds_on_both_sides() {
    let rng = &mut StdRng::seed_from_u64(23);
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    for class in [Fp::ONE, QUADRATIC_NON_RESIDUE] {
        let inverse = class.invert().unwrap();
        let points: Vec<_> = iter::repeat_with(|| {
            let root = Fp::random(|bytes| rng.fill_bytes(bytes));
            (root.square() * inverse - discriminant, root)
        })
        .take(300)
        .collect();
        let (u, h) = decomposition(points.iter().copied(), class, discriminant).unwrap();
        verify_side(&points, class, discriminant, &u, &h);
    }
}

#[test]
fn an_all_zero_side_takes_the_vanishing_polynomial() {
    let rng = &mut StdRng::seed_from_u64(35);
    let discriminant = Fp::random(|bytes| rng.fill_bytes(bytes));
    let points = [(-discriminant, Fp::ZERO)];
    let (u, h) = decomposition(points, Fp::ONE, discriminant).unwrap();
    assert_eq!(dense(&u), [discriminant, Fp::ONE]);
    verify_side(&points, Fp::ONE, discriminant, &u, &h);
}
