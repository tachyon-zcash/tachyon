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

use ff::Field as _;
use pasta_curves::Fp;
use ragu_circuits::polynomials::{ProductionRank, sparse::Polynomial};
use ragu_pasta::fp;

use super::poly_mul;

const NON_RESIDUE: Fp = fp!(0x02);

#[must_use]
fn encode_single(idx: u64, m: Fp) -> Polynomial<Fp, ProductionRank> {
    let i = Fp::from(idx) + Fp::ONE;
    // writing out expanded coefficients for $F(X) = (iX + m)^3 - c$ is
    // cheaper than constructing a linear $f(X) = iX + m$ and then cubing it.
    Polynomial::from_coeffs(
        [
            m.pow([3]) - NON_RESIDUE,
            fp!(3) * i * m.square(),
            fp!(3) * i.square() * m,
            i.pow([3]),
        ]
        .to_vec(),
    )
}

#[must_use]
fn direct_eval_single(idx: u64, m: Fp, x: Fp) -> Fp {
    let i = Fp::from(idx) + Fp::ONE;
    ((i * x) + m).pow([3]) - NON_RESIDUE
}

/// Encode the provided indexed members.
pub(crate) fn encode(
    members: impl IntoIterator<Item = (u64, Fp)>,
) -> Polynomial<Fp, ProductionRank> {
    members.into_iter().fold(
        Polynomial::from_coeffs([Fp::ONE].to_vec()),
        |acc, (idx, m)| poly_mul(&acc, &encode_single(idx, m)),
    )
}

/// Evaluate the indexed multiset without building the polynomial.
pub(crate) fn direct_eval(members: impl IntoIterator<Item = (u64, Fp)>, x: Fp) -> Fp {
    members
        .into_iter()
        .fold(Fp::ONE, |acc, (idx, m)| acc * direct_eval_single(idx, m, x))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use proptest::{collection, prelude::*};
    use rand::{RngExt as _, SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::testing::arb_fp;

    fn arb_index() -> impl Strategy<Value = u64> {
        prop_oneof![
            1 => Just(0),
            1 => Just(1),
            1 => Just(u64::MAX),
            6 => any::<u64>(),
        ]
    }

    fn arb_members() -> impl Strategy<Value = Vec<(u64, Fp)>> {
        collection::vec((arb_index(), arb_fp()), 0..=8)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn the_encoding_evaluates_as_the_direct_product(members in arb_members(), x in arb_fp()) {
            prop_assert_eq!(encode(members.iter().copied()).eval(x), direct_eval(members, x));
        }

        #[test]
        fn concatenation_multiplies_encodings(
            left in arb_members(),
            right in arb_members(),
            x in arb_fp(),
        ) {
            let product = poly_mul(&encode(left.iter().copied()), &encode(right.iter().copied()));
            let both = left.iter().chain(&right).copied();
            prop_assert_eq!(encode(both.clone()).eval(x), product.eval(x));
            prop_assert_eq!(
                direct_eval(both, x),
                direct_eval(left, x) * direct_eval(right, x)
            );
        }

        #[test]
        fn member_order_does_not_matter(
            (members, shuffled) in arb_members()
                .prop_flat_map(|members| (Just(members.clone()), Just(members).prop_shuffle())),
            x in arb_fp(),
        ) {
            prop_assert_eq!(encode(members).eval(x), encode(shuffled).eval(x));
        }

        #[test]
        fn the_empty_multiset_is_one(x in arb_fp()) {
            prop_assert_eq!(encode([]).eval(x), Fp::ONE);
            prop_assert_eq!(direct_eval([], x), Fp::ONE);
        }

        #[test]
        fn a_single_member_has_no_root(idx in arb_index(), member in arb_fp(), x in arb_fp()) {
            prop_assert_ne!(direct_eval_single(idx, member, x), Fp::ZERO);
        }

        #[test]
        fn distinct_indices_encode_distinctly(
            idx_a in any::<u32>(),
            idx_b in any::<u32>(),
            member in arb_fp(),
        ) {
            prop_assume!(idx_a != idx_b);
            let coeffs_a = Vec::from_iter(encode_single(idx_a.into(), member).iter_coeffs());
            let coeffs_b = Vec::from_iter(encode_single(idx_b.into(), member).iter_coeffs());
            prop_assert_ne!(coeffs_a, coeffs_b);
        }
    }

    #[test]
    fn member_encoding_matches_manual_evaluation() {
        let rng = &mut StdRng::seed_from_u64(3);
        for _ in 0..8 {
            let idx = u64::from(rng.random_range(0..u32::MAX));
            let member = Fp::random(&mut *rng);
            let x = Fp::random(&mut *rng);
            assert_eq!(
                encode_single(idx, member).eval(x),
                direct_eval([(idx, member)], x)
            );
        }
    }

    #[test]
    fn member_encoding_matches_manual_construction() {
        let rng = &mut StdRng::seed_from_u64(6);
        let idx = u64::from(rng.random_range(0..u32::MAX));
        let member = Fp::random(&mut *rng);
        let x = Fp::random(&mut *rng);

        let manual_poly = {
            let m_ix = Polynomial::from_coeffs([member, Fp::from(idx) + Fp::ONE].to_vec());

            let m_ix_cube = poly_mul(&poly_mul(&m_ix, &m_ix), &m_ix);

            {
                let mut coeffs = Vec::from_iter(m_ix_cube.iter_coeffs());
                coeffs[0] -= NON_RESIDUE;
                Polynomial::<Fp, ProductionRank>::from_coeffs(coeffs)
            }
        };

        assert_eq!(encode_single(idx, member).eval(x), manual_poly.eval(x));
    }

    #[test]
    fn sequence_evaluation_matches_the_encoding() {
        let rng = &mut StdRng::seed_from_u64(12);
        for len in 0..6u64 {
            let start_idx = u64::from(rng.random_range(0..u32::MAX));
            let members: Vec<(u64, Fp)> = (start_idx..start_idx + len)
                .map(|idx| (idx, Fp::random(&mut *rng)))
                .collect();
            let x = Fp::random(&mut *rng);
            assert_eq!(
                direct_eval(members.iter().copied(), x),
                encode(members).eval(x)
            );
        }
    }
}
