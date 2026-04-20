use core::ops::Neg as _;

use ff::Field as _;
use pasta_curves::Fp;

use crate::polynomial::*;

#[test]
fn from_roots_and_multiply() {
    let a = Fp::from(3u64);
    let b = Fp::from(7u64);

    let pa = Polynomial::from_roots(&[a]);
    assert_eq!(pa.coefficients(), &[a.neg(), Fp::ONE]);

    let pb = Polynomial::from_roots(&[b]);
    assert_eq!(pa.multiply(&pb), Polynomial::from_roots(&[a, b]));

    let identity = Polynomial::default();
    assert_eq!(pa.multiply(&identity), pa);
}

#[test]
fn commitment_deterministic_and_distinct() {
    let c1 = Polynomial::from_roots(&[Fp::from(1u64)]).commit(Fp::ZERO);
    let c2 = Polynomial::from_roots(&[Fp::from(2u64)]).commit(Fp::ZERO);
    let c1_again = Polynomial::from_roots(&[Fp::from(1u64)]).commit(Fp::ZERO);
    assert_eq!(c1, c1_again);
    assert_ne!(c1, c2);
}

#[test]
fn commitment_serialization_roundtrip() {
    let commitment = Polynomial::from_roots(&[Fp::from(99u64)]).commit(Fp::ZERO);
    let bytes: [u8; 32] = commitment.into();
    let recovered = Commitment::try_from(&bytes).expect("valid point");
    assert_eq!(commitment, recovered);
}

#[test]
fn blinding_changes_commitment() {
    let poly = Polynomial::from_roots(&[Fp::from(42u64)]);
    let unblinded = poly.commit(Fp::ZERO);
    let blinded = poly.commit(Fp::ONE);
    assert_ne!(unblinded, blinded);
}
