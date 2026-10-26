//! # Indexed multiset
//!
//! An indexed multiset may contain any number of unique or repeated members at
//! each index. Conceptually, it is a multiset of `(index, member)` tuples.
//!
//! ## Irreducible encoding
//!
//! Construct a single-member indexed multiset of member $m$ at index $i$ as the
//! polynomial
//!
//! $$
//!   F_{i,m}(X) = (m + (i+1)X)^3 - c
//! $$
//!
//! where $c = 2$ is selected because it is the smallest cubic non-residue.
//!
//! Since $(m + (i+1)X)^3 \neq c$ the encoding is irreducible.
//!
//! ## Product composition
//!
//! Construct a larger indexed multiset as the product of smaller ones.
//!
//! $$
//!   S(X) = \prod_{(i,m) \in S}{F_{i,m}(X)}
//! $$
//!
//! Combined indexed multisets will maintain input multiplicity. The inputs
//! may be contiguous, disjoint, or overlapping.
//!
//! ## Quotient decomposition
//!
//! Since a union is a product of irreducible factors, we may demonstrate
//! correct division to confirm membership.
//!
//! $$
//!   \begin{aligned}
//!
//!   Q \uplus R &= S
//!       &\quad \iff &\quad
//!   &R &= S \setminus Q
//!
//!   \\ \\
//!
//!   Q(X) \cdot R(X) &= S(X)
//!       &\quad \iff &\quad
//!   &R(X) &= \frac{S(X)}{Q(X)}
//!
//!   \end{aligned}
//! $$
//!
//! Sequences $Q$ and $R$ combine to produce $S$, or, subsequence $R$ is
//! extracted from $S$ by complement $Q$. Select a challenge and evaluate.
//!
//! ## Injectivity
//!
//! Single-member encodings collide when the ratio of their linear terms is a
//! cube root of unity.
//!
//! Precisely, if
//!
//! $$
//!   \frac{m_1 + (i_1+1)X}{m_2 + (i_2+1)X} \in \{1, \zeta, \zeta^2\}
//! $$
//!
//! then $(i_1, m_1)$ cannot be distinguished from $(i_2, m_2)$ in an
//! indexed multiset.
//!
//! Specifying $i_\mathsf{max} + 1$ below $\lfloor\sqrt{p/3}\rfloor$ is
//! sufficient to prevent collisions.

#![allow(clippy::min_ident_chars, reason = "just for fun")]

extern crate alloc;

use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_core::pasta;
use udon::field::{Fp, Reduced};

use super::poly_mul;

const NON_RESIDUE: Fp =
    udon::fp_hex!("0x0000000000000000000000000000000000000000000000000000000000000002");

#[must_use]
fn encode_single(idx: u64, m: Fp<Reduced>) -> Polynomial<pasta::Fp, ProductionRank> {
    let i = <Fp>::from_u64(idx).add(&<Fp>::ONE);
    // writing out expanded coefficients for $F(X) = (iX + m)^3 - c$ is
    // cheaper than constructing a linear $f(X) = iX + m$ and then cubing it.
    Polynomial::from_coeffs(
        [
            m.pow_u64(3).sub(&NON_RESIDUE),
            i.mul(&m.square()).triple(),
            i.square().mul(&m).triple(),
            i.pow_u64(3),
        ]
        .map(pasta::Fp::new)
        .to_vec(),
    )
}

#[must_use]
fn direct_eval_single(idx: u64, m: Fp<Reduced>, x: Fp<Reduced>) -> Fp {
    let i = <Fp>::from_u64(idx).add(&<Fp>::ONE);
    i.mul(&x).add(&m).pow_u64(3).sub(&NON_RESIDUE)
}

/// Encode the provided indexed members.
pub(crate) fn encode(
    members: impl IntoIterator<Item = (u64, Fp<Reduced>)>,
) -> Polynomial<pasta::Fp, ProductionRank> {
    members.into_iter().fold(
        Polynomial::from_coeffs([<Fp>::ONE.into()].to_vec()),
        |acc, (idx, m)| poly_mul(&acc, &encode_single(idx, m)),
    )
}

/// Evaluate the indexed multiset without building the polynomial.
pub(crate) fn direct_eval(
    members: impl IntoIterator<Item = (u64, Fp<Reduced>)>,
    x: Fp<Reduced>,
) -> Fp<Reduced> {
    members
        .into_iter()
        .fold(<Fp>::ONE, |acc, (idx, m)| {
            acc.mul(&direct_eval_single(idx, m, x))
        })
        .reduce()
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use rand::{Rng as _, RngExt as _, SeedableRng as _, rngs::StdRng};
    use udon::field::random;

    use super::*;

    fn eval_at(poly: &Polynomial<pasta::Fp, ProductionRank>, at: Fp<Reduced>) -> Fp<Reduced> {
        poly.eval(at.into_loose().into()).into_inner().reduce()
    }

    #[test]
    fn member_encoding_matches_manual_evaluation() {
        let rng = &mut StdRng::seed_from_u64(3);
        for _ in 0..8 {
            let idx = u64::from(rng.random_range(0..u32::MAX));
            let member = random(|bytes| rng.fill_bytes(bytes)).reduce();
            let x = random(|bytes| rng.fill_bytes(bytes)).reduce();
            assert_eq!(
                eval_at(&encode_single(idx, member), x),
                direct_eval([(idx, member)], x)
            );
        }
    }

    #[test]
    fn member_encoding_matches_manual_construction() {
        let rng = &mut StdRng::seed_from_u64(6);
        let idx = u64::from(rng.random_range(0..u32::MAX));
        let member = random(|bytes| rng.fill_bytes(bytes)).reduce();
        let x = random(|bytes| rng.fill_bytes(bytes)).reduce();

        let manual_poly = {
            let m_ix = Polynomial::from_coeffs(
                [
                    member.into_loose().into(),
                    <Fp>::from_u64(idx).add(&<Fp>::ONE).into(),
                ]
                .to_vec(),
            );

            let m_ix_cube = poly_mul(&poly_mul(&m_ix, &m_ix), &m_ix);

            {
                let mut coeffs = m_ix_cube.iter_coeffs().collect::<Vec<_>>();
                coeffs[0] -= pasta::Fp::new(NON_RESIDUE);
                Polynomial::<pasta::Fp, ProductionRank>::from_coeffs(coeffs)
            }
        };

        assert_eq!(
            eval_at(&encode_single(idx, member), x),
            eval_at(&manual_poly, x)
        );
    }

    #[test]
    fn sequence_evaluation_matches_the_encoding() {
        let rng = &mut StdRng::seed_from_u64(12);
        for len in 0..6u64 {
            let start_idx = u64::from(rng.random_range(0..u32::MAX));
            let members: Vec<(u64, Fp<Reduced>)> = (start_idx..start_idx + len)
                .map(|idx| (idx, random(|bytes| rng.fill_bytes(bytes)).reduce()))
                .collect();
            let x = random(|bytes| rng.fill_bytes(bytes)).reduce();
            assert_eq!(
                direct_eval(members.iter().copied(), x),
                eval_at(&encode(members), x)
            );
        }
    }
}
